# Adaptor signatures appplied to fair data exchange and atomic swaps
## Overview

This project provides implementations of adaptor signature schemes and demonstrates their application through two example protocols: **Atomic Swap** and **Fair Data Exchange**. Both **Schnorr** and **ECDSA** adaptor signature schemes are implemented.

These protocols are simplified and schematic—they aim to demonstrate the core steps and concepts as they might appear in real blockchain-based applications. This is not a production-ready library, but rather an educational or proof-of-concept implementation. Therefore they use a `main` as if it was the communication channel between parties, as well as the blockchain.

Rust is used as the programming language for all components.

### Note on Fair Data Exchange protocol
This protocol is implemented without cryptographic proofs of correct encryption (e.g., zero-knowledge proofs or verifiable encryption), as that falls outside the intended scope of this project.

## Project structure
```
.
├── Cargo.lock
├── Cargo.toml
├── README.md
├── src
│   ├── bin
│   │   ├── atomic_swap
│   │   │   ├── alice.rs
│   │   │   ├── bob.rs
│   │   │   └── main_as.rs
│   │   └── fde
│   │       ├── fde_client.rs
│   │       ├── fde_server.rs
│   │       └── main_fde.rs
│   ├── crypto_impl.rs
│   ├── ecdsa.rs
│   ├── lib.rs
│   ├── main.rs
│   ├── schnorr.rs
│   └── utils.rs
└── tests
    ├── ecdsa_tests.rs
    └── schnorr_tests.rs

```

## Setup

### Prerequisites
Ensure that [Rust](https://www.rust-lang.org/tools/install) is installed.

### Clone Repository

#### Via HTTPS:
```bash
git clone https://github.com/johannayara/as_schemes.git
```

#### Via SSH:
```bash
git clone git@github.com:johannayara/as_schemes.git
```
---
## Provided protocols 

### 1. Fair data exchange 
The implementations for the fair data exchange protocol can be found [here](src/bin/fde/main_fde.rs). 
This example illustrates a fair data exchange mechanism using adaptor signatures.

#### Key Features
- Instatiates a client and a server 
- Allows client to get the data and server to be able to sell their data
- Can be run using either Schnorr or ECDSA
#### Example Usage
(Default) Schnorr:
```bash
cargo run --bin fde
```
ECDSA:
```bash
cargo run --bin fde ecdsa 
```
---

### 2. Cross-chain Atomic Swap
The implementation for the atomic swap protocol can be found [here](src/bin/atomic_swap/main_as.rs). Simulates an atomic swap between two parties using adaptor signatures.

#### Key Features
- Instantiates Alice and Bob 
- Shows main steps of the cross-chain atomic swap 
- Can be run using either Schnorr or ECDSA

#### Example Usage
(Default) Schnorr:
```bash
cargo run --bin atomic_swap 
```
ECDSA:
```bash
cargo run --bin atomic_swap ecdsa 
```

---

### Output
Both protocols simulate a sequence of steps representing how they might operate in a real blockchain environment. The output logs each step accordingly.

### Notes on notation 
In the code a struct Sigma was created to denote a full signature and a struct Sigma_prime, represents a pre-signature. A Sigma_prime element has optional proof, pi, and point on the curve, Z. These are used in ECDSA adaptor signatures. 

---

### **Quick Workflow**
#### Fair Data Exchange (Schnorr):
```bash
cargo run --bin fde 
```
#### Atomic swap (Schnorr):
```bash
cargo run --bin atomic_swap 
```
---

### Further works 
Here is a non-exhaustive list of ways this project could be expanded: 
- Integrate the project with existing blockchain technology 
- Add a Verifiable Encryption Under Commitment Key to FDE protocol
- Implement a multi-signature scheme, for an arbitrary number of participants
