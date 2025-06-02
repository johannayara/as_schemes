mod fde_client;
mod fde_server;
use as_for_fde::{Scheme, Schnorr, ECDSA};
use fde_client::Client;
use fde_server::Server;
use std::env;

/// Schematic implementation of the steps of a two party fair data exchange protocol.
fn main() {
    // === Step 0: Set to chosen scheme ===
    let args: Vec<String> = env::args().collect();
    let input = args.get(1).map(String::as_str).unwrap_or("schnorr");

    let scheme: Scheme = match input {
        "schnorr" => Scheme::Schnorr(Schnorr {}),
        "ecdsa" => Scheme::ECDSA(ECDSA {}),
        _ => {
            eprintln!("Please input a valid scheme: [\"schnorr\", \"ecdsa\"]");
            std::process::exit(1);
        }
    };
    println!("The protocol will run using : {}", input);

    // === Step 1: Setup ===
    let server = Server::new(scheme.clone());
    let client = Client::new(scheme);

    // === Step 2: Server encrypts data ===
    let data = "Very secret data :)";
    let (ct, nonce) = server.encrypt_data(data);

    println!("Server encrypted data and sent ct + nonce + pk to client.");

    // === Step 3: Client creates pre-signature ===
    let sigma_prime_c = client.generate_presig(&ct, &server.pk);
    println!("Client generated (s'_c, R'_c) and sent to server.");

    // === Step 4: Server verifies s'_c and generates s_s, s_c ===
    assert!(server.verify_presig(&sigma_prime_c, &client.pk, &ct));
    let (sigma_s, sigma_c) = server.generate_sig_and_adapt(&ct, &sigma_prime_c);
    println!("Server verified pre-sig and broadcasted s_s, s_c.");

    // === Step 5: Client extracts secret and decrypts ===
    assert!(client.verify_sign(&server.pk_s, &ct, &sigma_s, &sigma_c));
    println!("Client verified signatures broadcasted by server");
    let sk_recovered = client.extract_secret(&sigma_c, &sigma_prime_c);
    let decrypted = client.decrypt_data(&ct, &sk_recovered, &nonce);

    println!("Client extracted sk and decrypted the data:");
    println!("Decrypted message: {}", decrypted);
}
