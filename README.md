# Adaptor signatures appplied to fair data exchange and atomic swaps
## Overview

This project provides implementations of adaptor signature schemes and demonstrates their application through two example protocols: **Atomic Swap** and **Fair Data Exchange**. Both **Schnorr** and **ECDSA** adaptor signature schemes are implemented.

These protocols are simplified and schematic—they aim to demonstrate the core steps and concepts as they might appear in real blockchain-based applications. This is not a production-ready library, but rather an educational or proof-of-concept implementation.

Rust is used as the programming language for all components.

### **Note on Fair Data Exchange protocol**
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

### Set Up the Environment

---

## Provided features 

### 1. **Fair data exchange **
The implementations for the fair data exchange protocol can be found [here](src/bin/fde). 
This example illustrates a fair data exchange mechanism using adaptor signatures.

#### Key Features

#### Arguments
| Argument              | Type     | Default      | Description                                                                 |
|-----------------------|----------|--------------|-----------------------------------------------------------------------------|
| `--scheme` | `str`   | `multiclass` | this flag can be set to ecdsa or schnorr to choose which primitives are used              |

#### Example Usage
** (Default) Schnorr**:
```bash
cargo run --bin fde
```
** ECDSA **:
```bash
cargo run --bin fde --scheme ecdsa 
```
---

### 2. **Atomic Swap**
The implementation for the atomic swap protocol can be found [here](src/bin/atomic_swap). Simulates an atomic swap between two parties using adaptor signatures.

#### Key Features

#### Arguments
| Argument              | Type     | Default      | Description                                                                 |
|-----------------------|----------|--------------|-----------------------------------------------------------------------------|
| `--scheme` | `str`   | `multiclass` | this flag can be set to ecdsa or schnorr to choose which primitives are used              |

#### Example Usage
** (Default) Schnorr**:
```bash
cargo run --bin atomic_swap 
```
** ECDSA **:
```bash
cargo run --bin atomic_swap --scheme ecdsa 
```

---

### Output
Both protocols simulate a sequence of steps representing how they might operate in a real blockchain environment. The output logs each step accordingly.

### Notes
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