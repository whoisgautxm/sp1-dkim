use aligned_sdk::core::types::{Network, PriceEstimate, ProvingSystemId, VerificationData};
use aligned_sdk::sdk:: estimate_fee;
use aligned_sdk::sdk::{get_next_nonce, submit_and_wait_verification};
use cfdkim::{dns, header::HEADER, public_key::retrieve_public_key, validate_header};
use ethers::middleware::SignerMiddleware;
use ethers::types::U256;
use ethers::utils::hex;
use ethers::{
    providers::{Http, Provider},
    signers::{LocalWallet, Signer},
};
use mailparse::MailHeaderMap;
use regex::Regex;
use sp1_sdk::{ProverClient, SP1Stdin};
use std::fs;
use std::fs::File;
use std::io::Read;
use std::sync::Arc;
use tokio;
use trust_dns_resolver::TokioAsyncResolver;
const BATCHER_URL: &str = "wss://batcher.alignedlayer.com";
const NETWORK: Network = Network::Holesky;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

fn extract_info(content: &str, pattern: &str, field_name: &str) -> Option<String> {
    let re = Regex::new(pattern).unwrap();
    match re.captures(content) {
        Some(caps) => {
            let value = caps.get(1).unwrap().as_str().trim().to_string();
            println!("{}:{}", field_name, value);
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

    let mut file = File::open("/home/whoisgautxm/Desktop/sp1-dkim/script/email.eml")?;
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
                (
                    r"Txn\.\s*ID\s*=\s*\n\s*:\s*=\s*\n\s*(\S+)",
                    "Transaction ID",
                ),
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

        // client.verify(&proof, &vk).expect("verification failed");

        let rpc_url: String = "https://ethereum-holesky-rpc.publicnode.com".to_string();
        println!("RPC URL: {}", rpc_url);

        let provider =
            Provider::<Http>::try_from(rpc_url.clone()).expect("Failed to create provider");
        let chain_id = U256::from(17000);
        let private_key = "0x85e9fc5a95ae6f25cef7b266748722b8935e242648bfc7f7a9f3fe5dd9f301c0";
        let wallet: LocalWallet = private_key
            .parse::<LocalWallet>()
            .expect("Failed to parse the wallet")
            .with_chain_id(chain_id.as_u64());

        let signer = SignerMiddleware::new(provider.clone(), wallet.clone());
        // Just call once to have sufficient balance
        println!("Wallet: {:?}", wallet);
        let elf_path = format!("../program/elf/riscv32im-succinct-zkvm-elf");
        let elf = fs::read(&elf_path)?;
        let proof = bincode::serialize(&proof).expect("Failed to serialize proof");
        let verification_data = VerificationData {
            proving_system: ProvingSystemId::SP1,
            proof,
            proof_generator_addr: wallet.address(),
            vm_program_code: Some(elf.to_vec()),
            verification_key: None,
            pub_input: None,
        };

        let rpc_str: &str = &rpc_url;

        let mut max_fee = estimate_fee(&rpc_str, PriceEstimate::Instant)
            .await
            .expect("Failed to estimate fee");
        max_fee *= 2;
        let nonce: U256 = get_next_nonce(&rpc_url, wallet.address(), NETWORK)
            .await
            .expect("Failed to get nonce");

        println!("Max fee: {}, Nonce: {}", max_fee, nonce);

        let aligned_verification_data = submit_and_wait_verification(
            BATCHER_URL,
            &rpc_url,
            NETWORK,
            &verification_data,
            max_fee,
            wallet.clone(),
            nonce,
        )
        .await
        .unwrap();

        println!(
            "Proof submitted and verified successfully on batch {}",
            hex::encode(aligned_verification_data.batch_merkle_root)
        );

       
        // client.verify(&proof, &vk).expect("verification failed");

        // proof.save("proof.bin").expect("saving proof failed");
        // proof.save("proof.json").expect("saving proof failed");

        return Ok(());
    }
    println!("Invalid from_domain.");
    Ok(())
}
