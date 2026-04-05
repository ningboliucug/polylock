# PolyLock: Constraint-Aware Attribute-Based Encryption for SAGIN

[![Go Reference](https://pkg.go.dev/badge/github.com/ningboliucug/polylock.svg)](https://pkg.go.dev/github.com/ningboliucug/polylock)
[![Go Version](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Official Implementation** of the paper: *"PolyLock: A Constraint-Aware Attribute-Based Encryption Scheme via Lattice-Based Polynomial Obfuscation for SAGIN"*. [cite: 18, 177]

PolyLock is a post-quantum, constraint-aware, and fully policy-hidden access control framework designed strictly for the Space-Air-Ground Integrated Network (SAGIN)[cite: 18]. By translating traditional access structures into Ring Learning With Errors (Ring-LWE) polynomial evaluations, PolyLock completely circumvents the combinatorial explosion of complex policies, providing $\mathcal{O}(1)$ decryption cost natively tailored for Size, Weight, and Power (SWaP) constrained tactical edge devices[cite: 18, 19].

## 🌟 Key Features

* **Post-Quantum Security**: Built upon the hardness of the Decisional Ring-LWE and Ring-ISIS problems, avoiding quantum-vulnerable bilinear pairings[cite: 18].
* **Full Policy Hiding**: Access policies are mathematically obfuscated into pseudorandom polynomial coefficients, eliminating tactical intelligence leakage[cite: 18].
* **Constraint-Aware Paradigm**: Exploits the inherent sparsity of valid attribute profiles[cite: 18, 19]. Decryption overhead is entirely decoupled from policy complexity[cite: 18].
* **Modulus Switching Compression**: Integrates NIST ML-KEM (Kyber) inspired bit-truncation techniques to drastically reduce ciphertext communication overhead over satellite links[cite: 18, 177].
* **Decoupled Architecture**: Natively supports dynamic policy updates without the need for bulk data re-encryption, seamlessly integrated with IPFS[cite: 18, 121].

## 🏗️ Repository Architecture

This repository adopts a standard Go project layout to decouple core cryptographic primitives from deployment applications[cite: 177]:

* `/pkg`: Core cryptographic library (Setup, KeyGen, Encaps, Decaps) based on [Lattigo v5](https://github.com/tuneinsight/lattigo)[cite: 18, 177].
* `/cmd/benchmark`: Monolithic local benchmark for algorithm performance profiling[cite: 18, 177].
* `/cmd/satellite`: Data Owner node implementation (incorporating PreResolve and Encaps)[cite: 18, 123, 177, 181].
* `/cmd/terminal`: Edge User node implementation (incorporating Decaps)[cite: 18, 125, 177, 245].
* `/deployments`: Dockerized End-to-End (E2E) SAGIN emulation environment with Linux Traffic Control (`tc`) network delay injection[cite: 18, 121, 177].

## ⚙️ Prerequisites

* **Go**: `>= 1.24.9` [cite: 9, 177]
* **Docker & Docker Compose**: For E2E SAGIN emulation[cite: 121, 177].
* **Lattigo**: Version `v5.0.7` is heavily utilized for homomorphic ring operations[cite: 9, 18].

## 🚀 Quick Start (Local Benchmark)

To run the standalone cryptographic benchmark without network overhead:

```bash
git clone [https://github.com/ningboliucug/polylock.git](https://github.com/ningboliucug/polylock.git)
cd polylock
go mod tidy
go run cmd/benchmark/main.go
````

*This will execute the mathematical evaluations of Setup, SpaceGen, KeyGen, PolicyGen, Encaps, and Decaps[cite: 18, 177].*

## 🛰️ E2E SAGIN Emulation (Dockerized)

To faithfully replicate the deployment conditions in the paper, we provide a Docker-compose environment that limits CPU/Memory boundaries and uses `netem` to inject realistic Ka-band/Sub-6GHz link latencies[cite: 18, 121, 123, 125].

### 1\. Pre-computation Phase

Run the pre-computation on the host to generate the admissible space $\mathbb{S}$ and access policies[cite: 18, 114].

```bash
go run cmd/precompute/main.go
```

*Data will be saved to the `./data/shared` directory[cite: 115, 177, 187].*

### 2\. Start the SAGIN Network

Launch the IPFS backend, the Satellite (Encryptor), and the Terminal (Decryptor)[cite: 18, 121].

```bash
cd deployments
docker-compose up --build
```

*Note: The `docker-compose.yml` explicitly bounds the satellite container to strict NUMA cores (`cpuset`) to evaluate realistic constrained performance[cite: 123].*

### 3\. Real-time Resource Monitoring

In a separate terminal window, monitor the exact CPU and Memory peaks of the containers in real-time during the cryptographic operations[cite: 64, 177]:

```bash
python3 deployments/monitor_peaks.py
```

## 🔬 Cryptographic Implementation Details

  * **Ring Selection**: We instantiate the cyclotomic ring $\mathcal{R}_q$ with dimension $N = 1024$ and prime moduli up to $42$-bit to achieve a rigorous 128-bit post-quantum security level[cite: 18, 139].
  * **Ciphertext Compression**: We map ciphertext components from $\mathbb{Z}_q$ to a smaller modulus $p \ll q$ via `CompressShift = 11`[cite: 18, 19, 36, 177]. This safely reduces the underlying assumption to Ring Learning With Rounding (Ring-LWR) while allowing elements to be packed into `uint16` structures[cite: 18, 37].
  * **Noise Management**: Payload keys are encoded exclusively into the second-highest bit of polynomial coefficients, leaving a massive structural buffer to deterministically absorb modulus switching errors without requiring error-correction codes (e.g., BCH/Reed-Solomon)[cite: 18, 41].

## 📝 Citation

If you find this code or our concepts useful in your research, please consider citing our paper:

```bibtex
@article{liu2026polylock,
  title={PolyLock: A Constraint-Aware Attribute-Based Encryption Scheme via Lattice-Based Polynomial Obfuscation for SAGIN},
  author={Liu, Ningbo and Xiang, Yuexin and Guan, Faqian and Ren, Wei and Cao, Yue and Zhu, Tianqing and Min, Geyong},
  journal={IEEE Transactions on Information Forensics and Security},
  year={2026},
  publisher={IEEE}
}
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

```
```
