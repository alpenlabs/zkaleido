# Zkaleido

This repository provides the core traits as well as adapters for various ZKVMs (Zero-Knowledge Virtual Machines) to ensure a unified interface and enable the reuse of guest logic across multiple ZKVM implementations. By writing the code once, we aim to support multiple ZKVMs seamlessly.

## Supported ZKVMs

Currently, the repository supports the following ZKVMs:

- [x] Risc0
- [x] SP1  
- [ ] OpenVM
- [ ] Valida


## Repository Structure

- **`zkaleido/`**  
  Contains core traits to standardize proof generation and verification.  

- **`adapters/`**  
  Contains ZKVM-specific adapters. Each adapter implements core interfaces to interact with the underlying ZKVM.

- **`examples/`**  
  Contains guest logic for different programs. These programs demonstrate how to use the adapters for various ZKVMs.

- **`artifacts/`**  
  Contains the build pipeline for generating necessary artifacts, including ELF binaries and other dependencies.

---

# Usage Guide

## Generating Report of Cycle Counts for Programs

To generate a report of cycle counts for one or more programs, use the following command:

```bash
make report PROGRAMS=<PROGRAM_NAME>
```

### Notes:
- **Multiple Programs Supported:** You can specify multiple programs by separating them with commas.
- **Example Commands:**
  ```bash
  make report PROGRAMS=fibonacci
  make report PROGRAMS=fibonacci,sha2-chain
  ```
- **Optional Parameter:** If `PROGRAMS` is left empty, the report will be generated for all supported programs.

### Supported Programs
Here is the list of currently supported programs:
- `fibonacci`
- `sha2-chain`
- `schnorr-sig-verify`

## Generating Report for a Specific ZKVM

To generate profiling data for a specific ZKVM, use the following commands:

```bash
make report-<ZkVm>
```

### Example Commands:
- For Risc0:
  ```bash
  make report-risc0
  ```
- For SP1:
  ```bash
  make report-sp1
  ```
- Similar to the general `make report`, you can also pass the `PROGRAMS` parameter:
  ```bash
  make report-risc0 PROGRAMS=fibonacci
  make report-sp1 PROGRAMS=fibonacci,sha2-chain
  ```


## Generating Profile Data

To dump profiling data, set the environment variable `ZKVM_PROFILING_DUMP=1` while running any of the above command.

```bash
ZKVM_PROFILING_DUMP=1 make report
```


### Viewing SP1 Profile

The profiling data for SP1 can be viewed using [Samply](https://github.com/mstange/samply). To view the profile:

```bash
samply load <FILENAME>.trace_profile
```

### Viewing Risc0 Profile

The profiling data for Risc0 can be viewed using [pprof](https://github.com/google/pprof). To view the profile:

```bash
go tool pprof -http=127.0.0.1:8000 <FILENAME>.trace_profile
```

## Generating Proof for Program

If proof is required, use the following command:

```bash
make proof ZKVM=<ZKVM_NAME> PROGRAMS=<PROGRAM_NAME>
```
> The proofs are dumped by default

### Additional Options:
- **Dump Profiling Data:** To dump proofs, set the environment variable `ZKVM_PROOF_DUMP=1` while running the command:

## Cleaning Up Generated Data
To clean up generated proofs and profiling data, run:

```bash
make prover-clean
```
This will remove all `.trace_profile` and `.proof` files from the current directory.

---

### Example Workflow
1. **Generate Report for All Programs:**
   ```bash
   make report
   ```

2. **Generate Report for Specific Programs:**
   ```bash
   make report PROGRAMS=fibonacci,sha2-chain
   ```

3. **Generate SP1 Report for Specific Programs:**
   ```bash
   make report-sp1 PROGRAMS=schnorr-sig-verify
   ```

4. **Dump Profiling Data for Risc0:**
   ```bash
   ZKVM_PROFILING_DUMP=1 make report-risc0 PROGRAMS=fibonacci
   ```

5. **Generate and dump Risc0 Proof**
   ```bash
  make proof ZKVM=risc0 PROGRAMS=fibonacci
   ```


5. **Clean Up Generated Data:**
   ```bash
   make prover-clean
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