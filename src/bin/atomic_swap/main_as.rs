#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

mod alice;
mod bob;
use alice::Alice;
use as_for_fde::{Schnorr, ECDSA, Scheme};
use bob::Bob;
use std::env;



fn main() {
    // === Step 0: set to chosen scheme ===
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
    let alice = Alice::new(scheme.clone());
    let bob = Bob::new(scheme);

    // === Step 2: Alice creates tx_2, and generates a pre-signature on it ===
    let tx2 = "Transaction id 2 :)";
    let (delta_prime_a2, T) = alice.generate_presig(&tx2);

    println!("Alice generated tx2 and sent her pre-signature, on tx2, as well as T to Bob.");

    // === Step 3: Bob verifies Alice's presignature  ===
    assert!(bob.verify_presig(&delta_prime_a2, &alice.pk, &tx2, &T));
    //Bob creates tx1 and a pre-signature on it 
    let tx1 = "Transaction id 1 :)";
    let delta_prime_b1 = bob.generate_presig(&tx1, &T);
    println!("Bob generated tx1 and sent his pre-signature on it to Alice.");

    // === Step 4: Alice verifies s'_b1 and generates s_a1, s_b1 ===
    assert!(alice.verify_presig(&delta_prime_b1, &bob.pk, &tx1));
    let (delta_a1, delta_b1) = alice.generate_sig_and_adapt(&tx1, &delta_prime_b1);
    println!("Alice verified pre-sig and broadcasted s_a1, s_b1.");

    // === Step 5: Bob verifies broadcasted signatures, extracts secret and generates s_a2, s_b2 ===
    assert!(bob.verify_sign(&alice.pk, &tx1, &delta_a1, &delta_b1));
    println!("Bob verified signatures broadcasted by Alice");
    let t = bob.extract_secret(&delta_b1, &delta_prime_b1);
    let (_delta_a2, _delta_b2) = bob.generate_sig_and_adapt(&tx2, &delta_prime_a2, &t);
    println!("Client extracted t and broadcasted s_a2, s_b2");
}
