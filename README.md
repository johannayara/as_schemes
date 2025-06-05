# Adaptor signatures appplied to fair data exchange and atomic swaps
## Overview

This project provides implementations of adaptor signature schemes and demonstrates their application through two example protocols: **Atomic Swap** and **Fair Data Exchange**. Both **Schnorr** and **ECDSA** adaptor signature schemes are implemented.

These protocols are simplified and schematic—they aim to demonstrate the core steps and concepts as they might appear in real blockchain-based applications. This is not a production-ready library, but rather an educational or proof-of-concept implementation. For the sake of demonstration, communication between parties and interaction with the blockchain are modeled using a `main` function.

An implementation of two bitcoin scripts that could be used in the protocols as well as a smart contract is also provided. 

`Rust` is used for the core logic, `Soldity` was used for the smart contract implementation and `Bitcoin Script` was used for the scripts. 

### Note on Fair Data Exchange protocol
This protocol is implemented without cryptographic proofs of correct encryption (e.g., zero-knowledge proofs or verifiable encryption), as that falls outside the intended scope of this project.

## Project structure
```
.
├── bitcoin_scripts
│   ├── scriptPubKey
│   └── scriptSig
├── Cargo.lock
├── Cargo.toml
├── eth_smart_contracts
│   ├── contracts
│   │   └── TimedMultisigWallet.sol
│   ├── hardhat.config.js
│   ├── README.md
│   └── test
│       └── TimedMultisigWallet.js
├── package.json
├── package-lock.json
├── README.md
├── src
│   ├── bin
│   │   ├── atomic_swap
│   │   │   ├── alice.rs
│   │   │   ├── bob.rs
│   │   │   └── main_as.rs
│   │   └── fde
│   │       ├── fde_client.rs
│   │       ├── fde_server.rs
│   │       └── main_fde.rs
│   ├── ecdsa.rs
│   ├── lib.rs
│   ├── scheme.rs
│   ├── schnorr.rs
│   └── utils.rs
└── tests
    ├── ecdsa_tests.rs
    └── schnorr_tests.rs

```

## Setup

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

### Prerequisites
Ensure that [Rust](https://www.rust-lang.org/tools/install) is installed.
You'll also need [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm).

Please navigate to the smart contract directory,`eth_smart_contracts` before running these commands, so the hardhat root is correctly located.
Install `hardhat` dependencies with the following commands:
```bash
npm install --save-dev hardhat @nomicfoundation/hardhat-toolbox
npm install --save-dev hardhat-gas-reporter
npx hardhat
```
If the option appears choose `Create a JavaScript project` in the shown options. 
If you see the help page for hardhat the installation was successful. 

#### Troubleshooting
If when installing hardhat you get an dependency error titled ERESOLVE. This is because some of the dependencies are only compatible with certain versions. Please run the follwing commands and try installing the dependencies again:
```bash
npm uninstall --save-dev hardhat @nomicfoundation/hardhat-toolbox
npm uninstall --save-dev hardhat-gas-reporter
```

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
cargo run --bin main_fde
```
ECDSA:
```bash
cargo run --bin main_fde ecdsa 
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
cargo run --bin main_as 
```
ECDSA:
```bash
cargo run --bin main_as ecdsa 
```

---

### Output
Both protocols simulate a sequence of steps representing how they might operate in a real blockchain environment. The output logs each step accordingly.

### Notes on notation 
In the code a struct Sigma was created to denote a full signature and a struct Sigma_prime, represents a pre-signature. A Sigma_prime element has optional proof, pi, and point on the curve, Z. These are used in ECDSA adaptor signatures. 

---
## Provided scripts and contracts

In this repository a scriptPubKey and its corresponding scriptSig are provided. They describe how an user could create a pay to mutli-signature transaction and implement a timeout on it. Note that these scripts would usually be wrapped in either a P2SH or a P2WSH script. 

Additionally, a smart contract implementation of a TimeMultisigWallet is provided [here](eth_smart_contracts/). This contract can be tested using Hardhat. Make sure you've completed the setup steps above before running tests.

#### Key Features
- Generates a smart contract with a timeout for a mutli-signature wallet
- Computes expected gas cost for this contract
- Runs tests on the contract

#### Example Usage
The tests as well as the gas cost reporter can be ran using this command:
```bash
npx hardhat test
```
### Output
Shows the tests status as well as a table with estimated gas costs. 


### TL;DR Quick Workflow
#### Fair Data Exchange (Schnorr):
```bash
cargo run --bin main_fde 
```
#### Atomic swap (Schnorr):
```bash
cargo run --bin main_as 
```

#### Running tests for Schnorr and ECDSA AS schemes:
```bash
cargo test
```
#### Testing smart contract:
```bash
npx hardhat test
```

---

### Further works 
Here is a non-exhaustive list of ways this project could be expanded: 
- Integrate the project with existing blockchain technology 
- Add a Verifiable Encryption Under Commitment Key to FDE protocol
- Implement a multi-signature scheme, for an arbitrary number of participants
