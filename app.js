require('dotenv').config(); // Load environment variables from .env file
const cors = require('cors');
const express = require('express');
const multer = require('multer');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

// Initialize Express app
const app = express();

app.use(cors());
app.use(express.json());

// Set up multer for file uploads, storing files in the 'script/' directory
const upload = multer({ dest: 'script/' });
let verificationResult = {};

// POST route to handle the file upload and DKIM verification
app.post('/verify-dkim', upload.single('email_file'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No file uploaded. Please upload a .eml file.' });
    }

    const originalFileName = req.file.originalname; // Original name of the .eml file
    const filePath = path.join('script', originalFileName); // Use the original file name

    // Rename the uploaded file
    fs.rename(req.file.path, filePath, (renameError) => {
        if (renameError) {
            console.error('Error renaming file:', renameError);
            return res.status(500).json({ message: 'Error renaming file: ' + renameError });
        }

        // Convert line endings from CRLF to LF
        exec(`dos2unix ${filePath}`, (conversionError, conversionStdout, conversionStderr) => {
            if (conversionError) {
                console.error('Error converting file line endings:', conversionStderr);
                return res.status(500).json({ message: 'Error converting file line endings: ' + conversionStderr });
            }

            // Define the Rust project directories
            const programDir = path.join(__dirname, 'program');
            const rustProjectDir = path.join(__dirname, 'script');

            // Step 1: Build the Rust project in the program directory
            exec('cargo prove build', { cwd: programDir }, (buildError, buildStdout, buildStderr) => {
                if (buildError) {
                    console.error('Error building Rust project:', buildStderr);
                    return res.status(500).json({ message: 'Error building Rust project: ' + buildStderr });
                }

                console.log('Rust project built successfully');

                // Step 2: Set up and run the Rust DKIM verifier binary with the uploaded .eml file as input
                exec(`SP1_PROVER=network SP1_PRIVATE_KEY=${process.env.SP1_PRIVATE_KEY} RUST_LOG=info cargo run --release -- --prove`, { cwd: rustProjectDir }, (runError, runStdout, runStderr) => {
                    if (runError) {
                        console.error('Error running Rust DKIM verifier:', runStderr);
                        return res.status(500).json({ message: 'Error during DKIM verification: ' + runStderr });
                    }

                    console.log('DKIM verification result:', runStdout);

                    // Check if the proof was verified successfully
                    if (runStdout.includes("Extracted Transaction ID:") && runStdout.includes("Extracted Amount:")) {
                        res.json({ message: 'DKIM Verification Result: Email is verified.' });
                    } else {
                        res.json({ message: 'DKIM Verification Result: Email is not verified.' });
                    }

                    const transactionId = runStdout.match(/Transaction ID:([^\n]*)/)[1].trim();
                    const paidToName = runStdout.match(/Paid to name:([^\n]*)/)[1].trim();
                    const extractedAmount = runStdout.match(/Extracted Amount:([^\n]*)/)[1].trim();

                    const result = {
                        transactionId,
                        paidToName,
                        amount,
                        verified: Boolean(transactionId && paidToName && amount)
                    };

                    verificationResult = result;

                    res.json(result);

                    // Step 3: Clean up by deleting the uploaded file
                    fs.unlink(filePath, (unlinkError) => {
                        if (unlinkError) {
                            console.error('Error deleting file:', unlinkError);
                        } else {
                            console.log('Uploaded file deleted successfully');
                        }
                    });
                });
            });
        });
    });
});
app.get('/get-verification-result', (req, res) => {
    if (verificationResult) {
        return res.json(verificationResult);  // Send back the stored result
    }
    return res.status(404).json({ message: "No result found" });
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
