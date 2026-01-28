# FHE Protocol Security Audit Checklist

A comprehensive security audit checklist for Fully Homomorphic Encryption protocols, derived from the [awesome-fhe-attacks](https://github.com/Hexens/awesome-fhe-attacks) research compilation.

---

## Table of Contents

1. [Security Model & Threat Assessment](#1-security-model--threat-assessment)
2. [IND-CCA/IND-CPA/IND-CPAD Security](#2-ind-ccaind-cpaind-cpad-security)
3. [Lattice-Based Cryptographic Security](#3-lattice-based-cryptographic-security)
4. [Side-Channel Resistance](#4-side-channel-resistance)
5. [Key Management Security](#5-key-management-security)
6. [Reaction Attack Resistance](#6-reaction-attack-resistance)
7. [Cryptanalysis Resistance](#7-cryptanalysis-resistance)
8. [Implementation Security](#8-implementation-security)
9. [FHE-ML Specific Security](#9-fhe-ml-specific-security)
10. [Tools & Verification](#10-tools--verification)

---

## 1. Security Model & Threat Assessment

### 1.1 Adversary Model Definition
- [ ] **Define adversary capabilities**: Passive (honest-but-curious) vs. Active (malicious)
- [ ] **Identify trust boundaries**: Client, server, third-party evaluators
- [ ] **Assess data sensitivity levels**: Classification of encrypted data
- [ ] **Document threat assumptions**: Network, physical access, side-channels

### 1.2 Security Guarantees
- [ ] **Verify claimed security level**: IND-CPA, IND-CCA1, IND-CCA2, IND-CPAD
- [ ] **Validate security proofs**: Reduction to hard problems (LWE, RLWE, AGCD)
- [ ] **Check parameter security margins**: Bits of security vs. NIST recommendations

> [!WARNING]
> FHE schemes are typically only IND-CPA secure. Do NOT assume IND-CCA security without explicit verification.

---

## 2. IND-CCA/IND-CPA/IND-CPAD Security

### 2.1 CPA Security Verification
- [ ] **Ciphertext indistinguishability**: Verify ciphertexts don't leak plaintext information
- [ ] **Randomness quality**: Check CSPRNG usage for encryption randomness
- [ ] **Noise distribution**: Validate noise follows specified distribution (Gaussian, uniform)

### 2.2 CCA1/CCA2 Considerations
- [ ] **Decryption oracle exposure**: Identify any paths that expose decryption results
- [ ] **Malleability risks**: Assess if ciphertext modification produces valid decryptions
- [ ] **Integrity verification**: Check for authenticated encryption or MAC-then-encrypt

> [!CAUTION]
> **IND-CCA1 Attack Vector**: FHE schemes allowing decryption oracle access before challenge can be completely broken. See [IND-CCA1 Security of FHE Schemes](https://eprint.iacr.org/2021/1624.pdf)

### 2.3 CPAD (Chosen Plaintext Attack with Decryption) Security
- [ ] **Noise leakage via decryption**: Check if decryption reveals noise magnitude
- [ ] **Exact FHE scheme exposure**: Verify CKKS/approximate schemes implement noise flooding
- [ ] **Threshold FHE vulnerabilities**: Assess multi-party decryption for CPAD risks

**Critical Checks for Approximate FHE (CKKS):**
- [ ] Does decryption reveal the encoded message with more precision than expected?
- [ ] Is differential privacy applied to decrypted outputs?
- [ ] Are noise flooding countermeasures sufficient against non-worst-case attacks?

> [!IMPORTANT]
> **CPAD attacks can recover secret keys** in CKKS and threshold FHE schemes. See:
> - [Attacks Against INDCPA-D Security](https://eprint.iacr.org/2024/127.pdf)
> - [Practical CPAD Security Analysis](https://eprint.iacr.org/2024/116.pdf)

### 2.4 Verifiability & Integrity
- [ ] **Computation verification**: Implement verifiable FHE if integrity is required
- [ ] **Zero-knowledge proofs**: Consider ZK-SNARKs for computation correctness
- [ ] **Authenticated encryption integration**: MAC on ciphertexts where applicable

---

## 3. Lattice-Based Cryptographic Security

### 3.1 LWE/RLWE Parameter Security

- [ ] **Security parameter estimation**: Use [Lattice Estimator](https://github.com/malb/lattice-estimator) to verify claimed security
- [ ] **Dimension (n) adequacy**: Ensure lattice dimension provides target security level
- [ ] **Modulus (q) sizing**: Balance between functionality and security
- [ ] **Error distribution (χ)**: Verify Gaussian width or uniform bound

**Security Level Estimation Checklist:**
```
Security Target    | Min Dimension (n) | Typical q (log2)
-------------------|-------------------|------------------
128-bit security   | 2048+             | 54-109 bits
192-bit security   | 4096+             | 109-218 bits
256-bit security   | 8192+             | 218-438 bits
```

### 3.2 Key and Secret Distribution Vulnerabilities

- [ ] **Sparse secret attacks**: If using sparse secrets, verify resistance to hybrid attacks
- [ ] **Ternary secret risks**: Verify parameters account for small secret vulnerabilities
- [ ] **Dual lattice attack resistance**: Check for weak parameters exploitable by dual attacks

> [!WARNING]
> **Small/Sparse Secret Warning**: Using secrets from {-1, 0, 1} or sparse distributions significantly reduces security. See:
> - [Dual and Meet-in-the-Middle Attack](https://eprint.iacr.org/2019/1114.pdf)
> - [Dual Lattice Attacks on HElib and SEAL](https://eprint.iacr.org/2017/047.pdf)

### 3.3 NTRU-Based Scheme Vulnerabilities

- [ ] **Overstretched parameter detection**: Check if NTRU modulus is too large relative to dimension
- [ ] **Subfield lattice attack resistance**: Verify cyclotomic field choice doesn't enable subfield attacks
- [ ] **Key generation correctness**: Ensure generated keys satisfy required norm bounds

> [!CAUTION]
> **Subfield Attack**: Power-of-two cyclotomics with overstretched parameters are vulnerable. See [Subfield Lattice Attack on FHE](https://eprint.iacr.org/2021/1626.pdf)

### 3.4 AGCD-Based Scheme Security (DGHV-style)

- [ ] **Approximate GCD hardness**: Verify parameters resist orthogonal lattice attacks
- [ ] **Integer FHE bit-size**: Check ciphertext/key sizes against known attacks
- [ ] **Noise growth bounds**: Ensure noise doesn't grow beyond decryption capability

---

## 4. Side-Channel Resistance

### 4.1 Timing Side-Channels

- [ ] **Constant-time operations**: Verify key operations don't branch on secret data
- [ ] **NTT/FFT timing**: Check number-theoretic transform implementations
- [ ] **Modular reduction timing**: Verify Barrett/Montgomery reduction is constant-time
- [ ] **Memory access patterns**: Ensure cache-timing resistance

### 4.2 Power/EM Side-Channels

- [ ] **Key-dependent operations**: Identify operations that could leak key bits
- [ ] **Gaussian sampling leakage**: Verify discrete Gaussian samplers are protected
- [ ] **Hardware acceleration security**: Check if hardware (GPU/FPGA) introduces leakage

### 4.3 Fault Injection Attacks

- [ ] **Decryption fault exploitation**: Assess if faults during decryption leak key
- [ ] **Computation fault tolerance**: Check if induced faults reveal secret state
- [ ] **Software fault injection**: Verify resistance to controlled crash/restart attacks

> [!IMPORTANT]
> **Fault attacks can achieve full key recovery** in TFHE/FHEW schemes. See:
> - [Leaking Secrets with Side-Channel Attacks](https://eprint.iacr.org/2023/1128.pdf)
> - [Software Fault Injections on FHE](https://eprint.iacr.org/2016/1164.pdf)

### 4.4 Microarchitectural Attacks

- [ ] **Spectre/Meltdown resistance**: Check for speculative execution vulnerabilities
- [ ] **Cache-line alignment**: Verify sensitive data doesn't span cache lines insecurely
- [ ] **Hyperthreading concerns**: Assess SMT-related leakage risks

---

## 5. Key Management Security

### 5.1 Key Generation

- [ ] **Entropy source quality**: Verify cryptographic random number generator quality
- [ ] **Key derivation security**: If deriving keys, verify KDF strength
- [ ] **Parameter generation**: Check parameter generation for backdoors

### 5.2 Key Recovery Attack Resistance

- [ ] **Decryption error exploitation**: Verify decryption errors don't leak key information
- [ ] **Noise flooding adequacy**: Check noise magnitude in approximate schemes
- [ ] **Threshold key share security**: In MPC settings, verify share independence

**Key Recovery Attack Vectors to Check:**
| Attack Type | Applicable Schemes | Mitigation |
|-------------|-------------------|------------|
| CPAD-based recovery | CKKS, Threshold FHE | Noise flooding, DP |
| Fault-based recovery | TFHE, FHEW | Redundancy checks |
| Adaptive decryption | GSW, NTRU variants | Query limiting |

> [!CAUTION]
> **Decryption error attacks** can fully recover keys in TFHE/FHEW. See:
> - [Full Key Recovery via Decryption Errors](https://eprint.iacr.org/2022/1563.pdf)
> - [Key Recovery on Approximate HE](https://www.usenix.org/system/files/sec24summer-prepub-822-guo.pdf)

### 5.3 Key Storage and Rotation

- [ ] **Secure key storage**: Encrypted at rest, access controls
- [ ] **Key rotation procedures**: Ability to rotate without re-encrypting all data
- [ ] **Key destruction**: Secure deletion procedures for retired keys

### 5.4 Multi-Party Key Management

- [ ] **Distributed key generation**: Verify DKG protocol security
- [ ] **Threshold decryption security**: Check for collusion resistance
- [ ] **Key share refresh**: Proactive security mechanisms

---

## 6. Reaction Attack Resistance

### 6.1 Outsourced Computation Security

- [ ] **Computation result verification**: Can server detect if computation failed?
- [ ] **Adaptive query attacks**: Can server learn from repeated computations?
- [ ] **Circuit privacy**: Does computation reveal circuit structure?

> [!WARNING]
> **Reaction attacks** allow malicious servers to recover secrets by observing client behavior after decryption. See [Reaction Attack on Outsourced FHE](https://zhenfeizhang.github.io/pdf/pracfheatt.pdf)

### 6.2 Countermeasures

- [ ] **Client behavior isolation**: Ensure decryption results don't influence observable behavior
- [ ] **Dummy computations**: Implement decoy operations to hide real patterns
- [ ] **Rate limiting**: Restrict query frequency to prevent statistical attacks

---

## 7. Cryptanalysis Resistance

### 7.1 Structural Vulnerabilities

- [ ] **Linear decryptability**: Check for plaintext recovery via linear algebra
- [ ] **GCD-based attacks**: Verify resistance to approximate GCD algorithms
- [ ] **Finite field isomorphism**: Check cyclotomic field choices

### 7.2 Implementation-Specific Attacks

- [ ] **Library-specific CVEs**: Check for known vulnerabilities in FHE libraries
- [ ] **Parameter misuse**: Verify parameters match library assumptions
- [ ] **API misuse patterns**: Check for common developer mistakes

**Known Library Considerations:**
| Library | Critical Checks |
|---------|-----------------|
| Microsoft SEAL | Overstretched params, CKKS noise flooding |
| OpenFHE | Parameter validation, RNS bugs |
| TFHE-rs | Bootstrap correctness, noise bounds |
| HElib | Small secret params, BGV noise |

> [!NOTE]
> See [Danger of Using Microsoft SEAL](https://arxiv.org/pdf/1906.07127) for SEAL-specific security concerns.

### 7.3 Algebraic Attacks

- [ ] **Ring structure exploitation**: Verify cyclotomic ring choice doesn't enable attacks
- [ ] **Subfield attacks**: Check for vulnerable subfield structures
- [ ] **Automorphism leakage**: Verify Galois automorphisms don't leak information

---

## 8. Implementation Security

### 8.1 Code Security

- [ ] **Memory safety**: No buffer overflows, use-after-free, etc.
- [ ] **Integer overflow protection**: Safe arithmetic for large integers
- [ ] **Serialization security**: Secure (de)serialization of ciphertexts/keys

### 8.2 Error Handling

- [ ] **Decryption failure handling**: Errors don't leak information
- [ ] **Parameter validation**: Invalid inputs rejected safely
- [ ] **Exception safety**: No sensitive data in exception messages

### 8.3 Cryptographic Hygiene

- [ ] **No plaintext logging**: Decrypted values never logged
- [ ] **Secure memory**: Sensitive values zeroed after use
- [ ] **Constant-time comparisons**: For any secret-dependent comparisons

### 8.4 Noise Management

- [ ] **Noise budget tracking**: Implementation correctly tracks noise growth
- [ ] **Decryption correctness**: Verify noise stays within decryptable bounds
- [ ] **Modulus switching correctness**: Rescaling doesn't introduce errors

---

## 9. FHE-ML Specific Security

### 9.1 Model Security

- [ ] **Model extraction resistance**: Encrypted inference doesn't leak model
- [ ] **Adversarial example resistance**: FHE doesn't amplify adversarial inputs
- [ ] **Gradient leakage**: In training, gradients don't reveal data

> [!IMPORTANT]
> **Model stealing is possible** even with FHE protection. See [Model Stealing on FHE-based ML](https://eprint.iacr.org/2023/1665.pdf)

### 9.2 Federated Learning Security

- [ ] **CPAD vulnerabilities**: Threshold FHE in FL exposes aggregator
- [ ] **Gradient inversion**: Encrypted gradients can still leak data
- [ ] **Byzantine resilience**: Malicious clients can't poison model

### 9.3 Data Privacy

- [ ] **Inference result privacy**: Predictions don't leak training data
- [ ] **Feature leakage**: Encrypted features don't reveal sensitive attributes
- [ ] **Query privacy**: Server can't learn what's being queried

---

## 10. Tools & Verification

### 10.1 Security Estimation Tools

| Tool | Purpose | Link |
|------|---------|------|
| Lattice Estimator | LWE/RLWE security estimation | [GitHub](https://github.com/malb/lattice-estimator) |
| LWE Benchmarking | Attack benchmarking | [GitHub](https://github.com/facebookresearch/LWE-benchmarking) |
| IND-CPA-D Attacks | CPAD vulnerability testing | [GitHub](https://github.com/hmchoe0528/INDCPAD_HE_ThresFHE) |

### 10.2 Security Audit Actions

1. **Run Lattice Estimator** on all parameter sets
2. **Verify security margins** against published attack costs
3. **Test CPAD vulnerabilities** if using approximate FHE
4. **Review library versions** for known CVEs
5. **Benchmark timing** for side-channel assessment

### 10.3 Documentation Review

- [ ] Security claims documented and verifiable
- [ ] Parameter choices justified with security estimates
- [ ] Known limitations explicitly stated
- [ ] Threat model clearly defined

---

## Quick Reference: Critical Vulnerability Patterns

| Vulnerability | Severity | Detection | Mitigation |
|--------------|----------|-----------|------------|
| CPAD on CKKS | **CRITICAL** | Decryption outputs high-precision values | Noise flooding + DP |
| Small secret LWE | **HIGH** | Sparse/ternary secret distribution | Increase dimension |
| Overstretched NTRU | **CRITICAL** | Large q relative to n | Reduce modulus ratio |
| Reaction attacks | **HIGH** | Observable client behavior post-decryption | Behavior isolation |
| Timing side-channels | **MEDIUM** | Secret-dependent branching | Constant-time impl |
| Decryption error leakage | **CRITICAL** | Errors visible to adversary | Error suppression |

---

## Reference Papers

### Essential Reading
1. [Security Guidelines for Implementing HE](https://eprint.iacr.org/2024/463.pdf) - Implementation best practices
2. [On the Security of HE on Approximate Numbers](https://eprint.iacr.org/2020/1533.pdf) - CKKS security analysis
3. [Attacks Against INDCPA-D Security](https://eprint.iacr.org/2024/127.pdf) - CPAD attack methodology
4. [Key Recovery Attacks on Approximate HE](https://www.usenix.org/system/files/sec24summer-prepub-822-guo.pdf) - Noise flooding bypasses

### Additional Resources
- [FHE Beyond IND-CCA1 Security](https://eprint.iacr.org/2024/202.pdf)
- [Practical CPAD Security](https://eprint.iacr.org/2024/116.pdf)
- [Full Key Recovery on TFHE/FHEW](https://eprint.iacr.org/2022/1563.pdf)

---

## Audit Report Template

```markdown
# FHE Security Audit Report

## Executive Summary
- Protocol/Library: [Name and version]
- Audit Date: [Date]
- Auditor: [Name/Organization]
- Overall Risk Level: [Critical/High/Medium/Low]

## Scope
- Components audited
- Security claims verified
- Out of scope items

## Findings

### [FINDING-001] [Title]
- **Severity**: [Critical/High/Medium/Low/Informational]
- **Category**: [IND-CPA/Lattice/Side-Channel/Key Recovery/etc.]
- **Description**: [Detailed description]
- **Impact**: [Security impact]
- **Recommendation**: [Mitigation steps]
- **References**: [Relevant papers/resources]

## Parameter Security Analysis
- Lattice Estimator results
- Security margin assessment
- Comparison to recommended parameters

## Recommendations
1. [Priority recommendations]
2. [Secondary recommendations]

## Conclusion
[Summary of audit findings and overall security posture]
```

---

> **Disclaimer**: This checklist is a guide for security assessment and should be adapted based on the specific FHE scheme, implementation, and threat model being audited. Always consult the latest research and security guidelines.
