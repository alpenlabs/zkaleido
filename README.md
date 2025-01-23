# ZKVM Adapters Repository

This repository provides adapters for various ZKVMs (Zero-Knowledge Virtual Machines) to ensure a unified interface and enable the reuse of guest logic across multiple ZKVM implementations. By writing the code once, we aim to support multiple ZKVMs seamlessly.

## Supported ZKVMs

Currently, the repository supports the following ZKVMs:

- [x] Risc0
- [x] SP1  
- [ ] OpenVM
- [ ] Valida


## Repository Structure

- **`crates/`**  
  Contains core traits and ZKVM-specific adapters to standardize proof generation and verification.  
  Each adapter implements core interfaces to interact with the underlying ZKVM.

- **`examples/`**  
  Contains guest logic for different programs. These programs demonstrate how to use the adapters for various ZKVMs.

- **`artifacts/`**  
  Contains the build pipeline for generating necessary artifacts, including ELF binaries and other dependencies.

---

## Usage

### Generating report of cycle count of different programs

```bash
make report
```

---

## Adding Support for New ZKVMs
To add support for a new ZKVM:
1. Create a new adapter in the `crates/` directory.
2. Implement the core traits required to interface with the ZKVM.
3. Extend the artifact generation logic in `artifacts/` as needed.

---

## Contributions
We welcome contributions to support additional ZKVMs or enhance the functionality of the repository. Feel free to create a pull request or open an issue to discuss your ideas.