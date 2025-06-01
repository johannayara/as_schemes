mod fde_client;
mod fde_server;
use fde_server::Server;
use fde_client::Client;

fn main() {
    // === Step 1: Setup ===
    let server = Server::new();
    let client = Client::new();

    // === Step 2: Server encrypts data ===
    let data = "Very secret data :)";
    let (ct, nonce) = server.encrypt_data(data);

    println!("Server encrypted data and sent ct + nonce + pk to client.");

    // === Step 3: Client creates pre-signature ===
    let delta_prime_c = client.generate_presig(&ct, &server.pk);
    println!("Client generated (s'_c, R'_c) and sent to server.");

    // === Step 4: Server verifies s'_c and generates s_s, s_c ===
    assert!(server.verify_presig(&delta_prime_c, &client.pk_c, &ct));
    let (delta_s, delta_c) = server.generate_sig_and_adapt(&ct, &delta_prime_c);
    println!("Server verified pre-sig and broadcasted s_s, s_c.");

    // === Step 5: Client extracts secret and decrypts ===
    assert!(client.verify_sign(&server.pk_s, &ct, &delta_s, &delta_c));
    println!("Client verified signatures broadcasted by server");
    let sk_recovered = client.extract_secret(&delta_c, &delta_prime_c);
    let decrypted = client.decrypt_data(&ct, &sk_recovered, &nonce);

    println!("Client extracted sk and decrypted the data:");
    println!("Decrypted message: {}", decrypted);
}
