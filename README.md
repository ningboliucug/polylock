# PolyLock

**PolyLock** is a research prototype for constraint-aware post-quantum data sharing with policy privacy in Space-Air-Ground Integrated Networks (SAGIN). The prototype implements a lattice-based access-lock mechanism that separates bulk payload encryption from policy-controlled key recovery. It is designed to support policy-private access control, lightweight terminal-side recovery, and lock-only policy updates without re-encrypting the bulk payload.

This repository accompanies the manuscript:

> PolyLock: Constraint-Aware Post-Quantum Data Sharing with Policy Privacy for Space-Air-Ground Integrated Networks

## Repository Layout

```text
polylock/
├── README.md
├── .gitignore
├── examples/
│   └── standalone/                 # Single-machine prototype and policy example
│       ├── go.mod
│       ├── go.sum
│       ├── main.go
│       └── policy.json
├── deployments/
│   └── docker/                     # Containerized SAGIN-style testbed
│       ├── docker-compose.yml
│       ├── precompute/             # Workload generation and valid-profile precomputation
│       ├── satellite/              # Satellite-side encryption, offloading, and update logic
│       ├── terminal/               # Terminal-side retrieval and recovery logic
│       ├── ipfs-data/              # Runtime IPFS data directory, ignored by Git
│       ├── shared-data/            # Runtime coordination directory, ignored by Git
│       ├── run_b4_policy_profile_avg.py
│       ├── run_b5_1_offload_heatmap_avg.py
│       ├── run_b5_2_update_delta_avg.py
│       ├── run_b6_terminal_sensitivity_avg.py
│       └── monitor_peaks.py
├── experiments/
│   └── results/
│       ├── b4_end_to_end/          # End-to-end scalability results
│       ├── b5_offloading/          # Satellite-side offloading heatmap results
│       ├── b5_update/              # Lock-only policy update results
│       └── b6_terminal/            # Terminal-side resource envelope results
├── docs/                           # Supplementary notes, if any
├── archive/                        # Local archives, ignored when appropriate
└── bin/                            # Local binaries, ignored by Git
```

## Prototype Components

PolyLock is organized around three execution roles.

1. **Precompute node**  
   Generates the admissible profile space, valid roots, and authorized test attributes used by the containerized experiments.

2. **Satellite node**  
   Acts as the data owner. It encrypts the payload, constructs the policy lock, offloads encrypted objects to IPFS, and performs lock-only policy updates.

3. **Terminal node**  
   Acts as the data consumer. It retrieves the encrypted payload and policy lock from IPFS, reconstructs the session key if authorized, and decrypts the payload.

The prototype follows a hybrid KEM/DEM workflow. The payload is encrypted with a symmetric primitive, while PolyLock controls access to the session key through a policy-private lattice-based access lock.

## Requirements

The artifact has been tested in a Linux containerized environment. The following tools are required.

- Go 1.20 or later
- Docker Engine
- Docker Compose plugin or `docker-compose`
- Python 3.8 or later
- Python packages from the standard library for experiment automation
- Linux traffic control support for `tc-netem`

The Docker testbed requires `NET_ADMIN` capability, which is already configured in `deployments/docker/docker-compose.yml`.

## Quick Start

### Standalone Prototype

```bash
cd examples/standalone
go mod tidy
go run .
```

This runs the single-machine prototype and is useful for checking the core cryptographic workflow without the containerized SAGIN testbed.

### Containerized SAGIN Testbed

```bash
cd deployments/docker
docker compose down -v --remove-orphans
rm -rf ipfs-data/* shared-data/*
docker compose up --build
```

The testbed starts an IPFS node, a satellite container, and a terminal container. Runtime files are exchanged through `shared-data/`, while IPFS state is stored in `ipfs-data/`.

## Reproducing Paper Experiments

All experiment scripts are placed under `deployments/docker/` so that they can directly locate `docker-compose.yml`, service directories, and runtime folders.

Before running a new experiment, the scripts reset the Docker environment and clean runtime IPFS/shared data. Each configuration is repeated multiple times and aggregated into raw and averaged CSV files.

### B-4: End-to-End Scalability

```bash
cd deployments/docker
python3 run_b4_policy_profile_avg.py
```

This experiment sweeps the valid profile space and policy selectivity. It reports satellite-side encryption and upload time, terminal-side download and decryption time, and satellite resource usage.

Primary output:

```text
results_b4_policy_profile_raw.csv
results_b4_policy_profile_avg.csv
```

Archived results are stored under:

```text
experiments/results/b4_end_to_end/
```

### B-5-1: Satellite-Side Offloading

```bash
cd deployments/docker
python3 run_b5_1_offload_heatmap_avg.py
```

This experiment evaluates satellite-side dissemination latency under different payload sizes and bandwidth settings. The reported metrics include total latency, encryption or lock-generation latency, and IPFS offloading latency.

Primary output:

```text
results_b5_1_offload_heatmap_raw.csv
results_b5_1_offload_heatmap_avg.csv
```

For the 7 by 7 heatmap used in the manuscript, use the corresponding 7 by 7 version of the script if present:

```bash
python3 run_b5_1_offload_heatmap_7x7_avg.py
```

Archived results are stored under:

```text
experiments/results/b5_offloading/
```

### B-5-2: Lock-Only Policy Update

```bash
cd deployments/docker
python3 run_b5_2_update_delta_avg.py
```

This experiment varies the affected bucket ratio during policy update. It reports recompilation, re-encapsulation, and lock offloading latency.

Primary output:

```text
results_b5_2_update_delta_raw.csv
results_b5_2_update_delta_avg.csv
```

Archived results are stored under:

```text
experiments/results/b5_update/
```

### B-6: Terminal-Side Resource Envelope

```bash
cd deployments/docker
python3 run_b6_terminal_sensitivity_avg.py
```

This experiment fixes the terminal memory budget and varies the CPU quota to characterize terminal-side feasibility under constrained resources.

Primary output:

```text
results_b6_terminal_sensitivity_raw.csv
results_b6_terminal_sensitivity_avg.csv
```

Archived results are stored under:

```text
experiments/results/b6_terminal/
```

## Notes on Measurement

The containerized experiments use Linux `tc-netem` to emulate bandwidth and delay. Process-level resource measurements are collected inside the Go programs using runtime and OS-level counters. CPU usage is reported as average CPU utilization normalized by the allocated CPU quota, while memory usage is reported as MaxRSS.

The experimental environment is intended to support reproducibility of the paper results. It is not a production-ready deployment.

## Cleaning Runtime State

To remove runtime files before a manual run:

```bash
cd deployments/docker
docker compose down -v --remove-orphans
rm -rf ipfs-data/* shared-data/*
touch ipfs-data/.gitkeep shared-data/.gitkeep
```

## Citation

If you use this artifact, please cite the associated manuscript.

```bibtex
@article{polylock,
  title   = {PolyLock: Constraint-Aware Post-Quantum Data Sharing with Policy Privacy for SAGIN},
  author  = {Liu, Ningbo and collaborators},
  journal = {Submitted manuscript},
  year    = {2026}
}
```

## License

A license file is not included by default. Please add a license before public release if redistribution or reuse is intended.
