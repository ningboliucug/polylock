# PolyLock: Constraint-Aware Attribute-Based Encryption for SAGIN

[![Go Reference](https://pkg.go.dev/badge/github.com/ningboliucug/polylock.svg)](https://pkg.go.dev/github.com/ningboliucug/polylock)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Official Implementation** of the paper: *"PolyLock: A Constraint-Aware Attribute-Based Encryption Scheme via Lattice-Based Polynomial Obfuscation for SAGIN"*.

PolyLock is a post-quantum, constraint-aware, and fully policy-hidden access control framework designed strictly for the Space-Air-Ground Integrated Network (SAGIN). By translating traditional access structures into Ring Learning With Errors (Ring-LWE) polynomial evaluations, PolyLock completely circumvents the combinatorial explosion of complex policies, providing $\mathcal{O}(1)$ decryption cost natively tailored for Size, Weight, and Power (SWaP) constrained tactical edge devices.

## 🌟 Key Features

* **Post-Quantum Security**: Built upon the hardness of the Decisional Ring-LWE and Ring-ISIS problems, avoiding quantum-vulnerable bilinear pairings.
* **Full Policy Hiding**: Access policies are mathematically obfuscated into pseudorandom polynomial coefficients, eliminating tactical intelligence leakage.
* **Constraint-Aware Paradigm**: Exploits the inherent sparsity of valid attribute profiles. Decryption overhead is entirely decoupled from policy complexity.
* **Modulus Switching Compression**: Integrates NIST ML-KEM (Kyber) inspired bit-truncation techniques to drastically reduce ciphertext communication overhead over satellite links.
* **Decoupled Architecture**: Natively supports dynamic policy updates without the need for bulk data re-encryption, seamlessly integrated with IPFS.

## 🏗️ Repository Architecture

This repository adopts a standard Go project layout to decouple core cryptographic primitives from deployment applications:

* `/pkg`: Core cryptographic library (Setup, KeyGen, Encaps, Decaps) based on [Lattigo v5](https://github.com/tuneinsight/lattigo).
* `/cmd/benchmark`: Monolithic local benchmark for algorithm performance profiling.
* `/cmd/satellite`: Data Owner node implementation (incorporating PreResolve and Encaps).
* `/cmd/terminal`: Edge User node implementation (incorporating Decaps).
* `/deployments`: Dockerized End-to-End (E2E) SAGIN emulation environment with Linux Traffic Control (`tc`) network delay injection.

## ⚙️ Prerequisites

* **Go**: `>= 1.24.9`. 
* **Docker & Docker Compose**: For E2E SAGIN emulation.
* **Lattigo**: Version `v5.0.7` is heavily utilized for homomorphic ring operations.

## 🚀 Quick Start (Local Benchmark)

To run the standalone cryptographic benchmark without network overhead:

```bash
git clone [https://github.com/ningboliucug/polylock.git](https://github.com/ningboliucug/polylock.git)
cd polylock
go mod tidy
go run cmd/benchmark/main.go
````

*This will execute the mathematical evaluations of Setup, SpaceGen, KeyGen, PolicyGen, Encaps, and Decaps.*

## 🛰️ E2E SAGIN Emulation (Dockerized)

To faithfully replicate the deployment conditions in the paper, we provide a Docker-compose environment that limits CPU/Memory boundaries and uses `netem` to inject realistic Ka-band/Sub-6GHz link latencies.

### 1\. Pre-computation Phase

Run the pre-computation on the host to generate the admissible space $\mathbb{S}$ and access policies.

```bash
go run cmd/precompute/main.go
```

*Data will be saved to the `./data/shared` directory.*

### 2\. Start the SAGIN Network

Launch the IPFS backend, the Satellite (Encryptor), and the Terminal (Decryptor).

```bash
cd deployments
docker-compose up --build
```

*Note: The `docker-compose.yml` explicitly bounds the satellite container to strict NUMA cores (`cpuset`) to evaluate realistic constrained performance.*

### 3\. Real-time Resource Monitoring

In a separate terminal window, monitor the exact CPU and Memory peaks of the containers in real-time during the cryptographic operations:

```bash
python3 deployments/monitor_peaks.py
```

## 🔬 Cryptographic Implementation Details

  * **Ring Selection**: We instantiate the cyclotomic ring $\mathcal{R}_q$ with dimension $N = 1024$ and prime moduli up to $42$-bit to achieve a rigorous 128-bit post-quantum security level.
  * **Ciphertext Compression**: We map ciphertext components from $\mathbb{Z}_q$ to a smaller modulus $p \ll q$ via `CompressShift = 11`. This safely reduces the underlying assumption to Ring Learning With Rounding (Ring-LWR) while allowing elements to be packed into `uint16` structures.
  * **Noise Management**: Payload keys are encoded exclusively into the second-highest bit of polynomial coefficients, leaving a massive structural buffer to deterministically absorb modulus switching errors without requiring error-correction codes (e.g., BCH/Reed-Solomon).

## 📝 Citation

If you find this code or our concepts useful in your research, please consider citing our paper:

```bibtex
@article{liu2026polylock,
  title={PolyLock: A Constraint-Aware Attribute-Based Encryption Scheme via Lattice-Based Polynomial Obfuscation for SAGIN},
  author={Liu, Ningbo and Xiang, Yuexin and Guan, Faqian and Ren, Wei and Cao, Yue and Zhu, Tianqing and Min, Geyong},
  journal={IEEE Transactions on Information Forensics and Security, Under Review},
  year={2026},
  publisher={IEEE}
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

```
```
