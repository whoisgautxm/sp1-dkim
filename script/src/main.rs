use cfdkim::{dns, header::HEADER, public_key::retrieve_public_key, validate_header};
use mailparse::MailHeaderMap;
use regex::Regex;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::TokioAsyncResolver;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn extract_info(content: &str, pattern: &str, field_name: &str) -> Option<String> {
    let re = Regex::new(pattern).unwrap();
    match re.captures(content) {
        Some(caps) => {
            let value = caps.get(1).unwrap().as_str().trim().to_string();
            println!("Extracted {}: {}", field_name, value);
            Some(value)
        }
        None => {
            println!("{} not found", field_name);
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup the logger.
    sp1_sdk::utils::setup_logger();
    let from_domain = "phonepe.com";

    let mut file = File::open("./email1.eml")?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let raw_email = contents.replace('\n', "\r\n");

    let email = mailparse::parse_mail(raw_email.as_bytes())?;
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    let resolver = dns::from_tokio_resolver(resolver);

    for h in email.headers.get_all_headers(HEADER) {
        let value = String::from_utf8_lossy(h.get_value_raw());
        let dkim_header = validate_header(&value).unwrap();

        let signing_domain = dkim_header.get_required_tag("d");
        if signing_domain.to_lowercase() != from_domain.to_lowercase() {
            continue;
        }

        let public_key = retrieve_public_key(
            Arc::clone(&resolver),
            dkim_header.get_required_tag("d"),
            dkim_header.get_required_tag("s"),
        )
        .await
        .unwrap();

        let mut stdin = SP1Stdin::new();
        stdin.write::<String>(&from_domain.to_string());
        stdin.write_vec(raw_email.as_bytes().to_vec());
        stdin.write::<String>(&public_key.get_type());
        stdin.write_vec(public_key.to_vec());

        let client = ProverClient::new();
        let (pk, vk) = client.setup(ELF);
        let mut proof = client.prove(&pk, stdin).run()?;

        let result = proof.public_values.read::<bool>();
        println!("Email verification result: {}", result);

        if result {
            let email_content = String::from_utf8_lossy(&raw_email.as_bytes().to_vec()).to_string(); 

            // Define regex patterns
            let patterns = [
                (r"Txn\.\s*ID\s*=\s*\n\s*:\s*=\s*\n\s*(\S+)","Transaction ID"),
                (r"Paid to\s*=\s*\n\s*(\S+(?:\s+\S+\s\S*))", "Paid to name"),
                (r"&#8377;\s*(\d+)", "Amount"),
            ];

            // Extract information using the Mail content and regex patterns
            for (pattern, field_name) in patterns.iter() {
                extract_info(&email_content, pattern, field_name);
            }
        } else {
            println!("Email is not verified");
        }

        client.verify(&proof, &vk).expect("verification failed");

        proof.save("proof.bin").expect("saving proof failed");
        return Ok(());
    }

    println!("Invalid from_domain.");
    Ok(())
}
