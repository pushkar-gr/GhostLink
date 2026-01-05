<img width="2754" height="1694" alt="image" src="https://github.com/user-attachments/assets/e6e0de94-feab-4001-b61e-47df57e828f6" /><div align="center">
  <img src="./static/banner.png" alt="GhostLink Banner" width="100%">
  
  <a href="https://github.com/pushkar-gr/ghostlink/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/pushkar-gr/ghostlink/ci.yml?label=Build&style=for-the-badge&logo=github" alt="Build Status">
  </a>
  <a href="https://github.com/pushkar-gr/ghostlink/releases">
    <img src="https://img.shields.io/github/v/release/pushkar-gr/ghostlink?label=Version&style=for-the-badge&color=007ec6" alt="Latest Version">
  </a>
  <a href="https://github.com/pushkar-gr/ghostlink/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge" alt="License">
  </a>
  <a href="https://www.rust-lang.org/">
    <img src="https://img.shields.io/badge/Made%20With-Rust-orange?style=for-the-badge&logo=rust" alt="Language">
  </a>
</div>

# 👻 GhostLink

**High-Performance Serverless P2P Messaging**

GhostLink is a decentralized chat app. It connects users directly without using central servers. Direct communication reduces latency and improves performance.

---

## 🗺️ Roadmap & Status

| Version | Status       | Description                                                                                                   |
|---------|--------------|---------------------------------------------------------------------------------------------------------------|
| v1.0    | **Legacy**   | First release. Plaintext messaging with reliable UDP transport.                                              |
| v1.1    | **Stable**   | **Added Security**. End-to-End Encryption (E2EE) using X25519 and ChaCha20-Poly1305 encryption.               |

---

## ⚙️ Architecture

GhostLink separates the Web Interface from the P2P core. These parts communicate through thread-safe state. Version 1.1 also adds a secure handshake layer before starting a stream.

[![](https://mermaid.ink/img/pako:eNp9VWtP4kAU_SuT-WA0oTwLYkUSBLIaBVkrMbvLfhjaS5nQzjTTqcoa__vedkoBYyQNncc995y5c2b6Tj3pA3WoZVkL4Umx4oGzEIToNUTgEAHS8pnaLEQesArlq7dmSpP7R4xK0mWgWLzOGj-yRv3Pgs4UJCA001wKcs-2oMjp_PZsQf9mec3vGZYY2Vv2sUEm0k9D6NWW_d5S9QdvaURcUC-IOyGuOy6AIPyvGBuYZyiFVjIks5AJIKdPayDXinFxzFlEhaAM9QQjDgZ3_C4qBzJh3ppjshMWxZdkuGZCQJh8L6WJeV3wUsX1FqVPIElYwEVginCk5YYJP1mzDRgpZfdTLUZ8teJg3UAYRkyQO9iS8RvWXwRwlK6kKla2Z5YB93bZzHC2NoGvY0FDtY21NHDTJmOBKUopWAJ8mnVrJsNto1VvkxoZjF2r2e58X5UWJn1STCSxzGxj_PAIIWdLHmKljjfJfZpPjYqslfuAe6WI6eCJjHjiSTTH9gh3N5wZGDbIM_LG-x09ICv280H5oLA-3yu3MeMU9KtUm1I3eyW3tYdPmqW3AW3o56NZ0SePkMhU7cW7eG7AJwPlnYT6cu7HJu4k0JdHOszxIL2rK4LWLpxHTocyijKbIDe5uuofONdg9n1iWYhsVA9LhWP9vLgmOC-uVcWwn6mZr2bzuaCv0zWre9OS01kqsvMRnBWZyykD3kfm2Kxq7q9pbTC8IzOWcSQ7RQeMn0Aj3KEXrJeLrs1uEjT_DmUM-rXOVpUMPI3IHbDAlGfCwPZHpJfD8OrgQsOb_orCnAcTOBZe1kVh11sNO0XoOhOb2c8EGteF8M2KP2s3V8889vGFO453366-aAhaoYHiPnW0SqFCI1ARy7r0PUu2oPmFvaAONvMLmy7EB2JiJn5LGe1gSqbBmjorFibYS3OqEWdo_KgcVehDUEOZCk2dZrebJ6HOO32jjtXpNqsX57bdPW_V7U73vF2hW-rY3WoDO912_aLdbNhd2_6o0H85b6PavrBxEv_waZx37AoFn2upJubLYz469OM_hS4Szg?type=png)](https://mermaid.live/edit#pako:eNp9VWtP4kAU_SuT-WA0oTwLYkUSBLIaBVkrMbvLfhjaS5nQzjTTqcoa__vedkoBYyQNncc995y5c2b6Tj3pA3WoZVkL4Umx4oGzEIToNUTgEAHS8pnaLEQesArlq7dmSpP7R4xK0mWgWLzOGj-yRv3Pgs4UJCA001wKcs-2oMjp_PZsQf9mec3vGZYY2Vv2sUEm0k9D6NWW_d5S9QdvaURcUC-IOyGuOy6AIPyvGBuYZyiFVjIks5AJIKdPayDXinFxzFlEhaAM9QQjDgZ3_C4qBzJh3ppjshMWxZdkuGZCQJh8L6WJeV3wUsX1FqVPIElYwEVginCk5YYJP1mzDRgpZfdTLUZ8teJg3UAYRkyQO9iS8RvWXwRwlK6kKla2Z5YB93bZzHC2NoGvY0FDtY21NHDTJmOBKUopWAJ8mnVrJsNto1VvkxoZjF2r2e58X5UWJn1STCSxzGxj_PAIIWdLHmKljjfJfZpPjYqslfuAe6WI6eCJjHjiSTTH9gh3N5wZGDbIM_LG-x09ICv280H5oLA-3yu3MeMU9KtUm1I3eyW3tYdPmqW3AW3o56NZ0SePkMhU7cW7eG7AJwPlnYT6cu7HJu4k0JdHOszxIL2rK4LWLpxHTocyijKbIDe5uuofONdg9n1iWYhsVA9LhWP9vLgmOC-uVcWwn6mZr2bzuaCv0zWre9OS01kqsvMRnBWZyykD3kfm2Kxq7q9pbTC8IzOWcSQ7RQeMn0Aj3KEXrJeLrs1uEjT_DmUM-rXOVpUMPI3IHbDAlGfCwPZHpJfD8OrgQsOb_orCnAcTOBZe1kVh11sNO0XoOhOb2c8EGteF8M2KP2s3V8889vGFO453366-aAhaoYHiPnW0SqFCI1ARy7r0PUu2oPmFvaAONvMLmy7EB2JiJn5LGe1gSqbBmjorFibYS3OqEWdo_KgcVehDUEOZCk2dZrebJ6HOO32jjtXpNqsX57bdPW_V7U73vF2hW-rY3WoDO912_aLdbNhd2_6o0H85b6PavrBxEv_waZx37AoFn2upJubLYz469OM_hS4Szg)

### Communication Flow
[![](https://mermaid.ink/img/pako:eNqdVttu4zYQ_ZUBHwobawuSYym2HlJIdnYTpA2MVYLtdr0oGImxhEiiSlJB0iCPfesntD-3X9KhLpYd29mLYRikNWfmzOFwRk8k5BEjLpHsz5LlIZsndCVotswBP7RUPC-zGybqff1bUKGSMClorsADKuFaMoGr3ruYS_VLkt_1dw0vvas_KmNcaNv3vFRM7DEMtNE7zlcpg-Dq-nK_K7915b_iyl-T87fJ1aaXXDHg95r7wHdhEVPJwHLhPGK5StQjzBMZ6ueP0NNM-psieMOTkzeBCx9iDjSD85-h5yd5lOQreK-llKoxD4ZoOfRc-MhLoILByDwyTMOyjgzLtU3ThN6ivEmTEM4XWxH874vgdxGs6cSwLcMyTWPkOjsh9mavZZIgY40_X0gDLtijhBXLmaCKRZDykKYpKvHbyLatad94VcWRCwELS_R1xvEcF2Uexpp473Q2P4MzmkcY6Y7tKIoyvWtCwmkRswyXqaZS0ERgFiK59wbo7sbrdyL5Xwf5FchfJ59yXsBpdbR4BJnUAjUUf9JIOH0IY5qvWoZNZcGCVZXuKcWyQsnuYZtAVeY6-TyCJQk-Xi4JPFWEBzCLKX5HJjxv4ypMg9UnMV_AgoZ3TGHZidDVDM0BzKVyQR9m_wVa6y-SVayA30ITv75kvGC5hIILVfn4Gg5jf_nvn-ZWRYIXKIuP537Hoo2YeHa1DP4BGfwulV0Z_Ndl8DsJd2RwOhnsAzKk7HYzmzqTDRWc_SpswrxOBO-wCJhXvakWey-CYRhwJSjuJVZjUIYhY5HUf7cAXVCbtQYznhUpUwnPu0g_UlQHC2rbpLk7X_79GxtKyJJ7vObovGoW3kay25WCCB8wq-Q2YRLzD8VjoSlDhoMEMqrCmG1UhD-sr3VHfujNLtbl0NKmraA_WkEHq2dXFu9Azv7LnNu6QID3HSl7w1rY_Sl7LevDpTPT_jmO4SLGnh0wKXWwORK4p111bHVN3Vc32qPfh-EJBLqbR7oTi1aH5szX5n7TTQ-Yb8U4u5i_rewaQtWEeAOBF8Bb7JxMFCLJt-N8K-SVUXK0HiV4m3JZ3ePrAsWJ2B6OzRMIeNU5FIeL2QJfEVia0JuUbU-NbzPe1rk-_N6SnLE05fCBizRakkq_T7MEp49Q7EF97kAY5xO6_bzncUNjzmqfmwaVwxdBWlDNpHaKhUUGZCWSiLhKlGxAcPplVG_JkwYsidITcUlcXEZU3Gk_z4jBN6TfOc9amODlKibuLU0l7soiwmnavAuu_xVYskzMeJkr4lpH48oJcZ_IA27HtjE-to-nU9sx7bEzmQzII3GHzvHIcEzHtCam44xNZ_Q8IH9VcS1jYh_bR87UnoydsTPVCBYliotf61fSkOe3yYo8_w8n-h_M?type=png)](https://mermaid.live/edit#pako:eNqdVttu4zYQ_ZUBHwobawuSYym2HlJIdnYTpA2MVYLtdr0oGImxhEiiSlJB0iCPfesntD-3X9KhLpYd29mLYRikNWfmzOFwRk8k5BEjLpHsz5LlIZsndCVotswBP7RUPC-zGybqff1bUKGSMClorsADKuFaMoGr3ruYS_VLkt_1dw0vvas_KmNcaNv3vFRM7DEMtNE7zlcpg-Dq-nK_K7915b_iyl-T87fJ1aaXXDHg95r7wHdhEVPJwHLhPGK5StQjzBMZ6ueP0NNM-psieMOTkzeBCx9iDjSD85-h5yd5lOQreK-llKoxD4ZoOfRc-MhLoILByDwyTMOyjgzLtU3ThN6ivEmTEM4XWxH874vgdxGs6cSwLcMyTWPkOjsh9mavZZIgY40_X0gDLtijhBXLmaCKRZDykKYpKvHbyLatad94VcWRCwELS_R1xvEcF2Uexpp473Q2P4MzmkcY6Y7tKIoyvWtCwmkRswyXqaZS0ERgFiK59wbo7sbrdyL5Xwf5FchfJ59yXsBpdbR4BJnUAjUUf9JIOH0IY5qvWoZNZcGCVZXuKcWyQsnuYZtAVeY6-TyCJQk-Xi4JPFWEBzCLKX5HJjxv4ypMg9UnMV_AgoZ3TGHZidDVDM0BzKVyQR9m_wVa6y-SVayA30ITv75kvGC5hIILVfn4Gg5jf_nvn-ZWRYIXKIuP537Hoo2YeHa1DP4BGfwulV0Z_Ndl8DsJd2RwOhnsAzKk7HYzmzqTDRWc_SpswrxOBO-wCJhXvakWey-CYRhwJSjuJVZjUIYhY5HUf7cAXVCbtQYznhUpUwnPu0g_UlQHC2rbpLk7X_79GxtKyJJ7vObovGoW3kay25WCCB8wq-Q2YRLzD8VjoSlDhoMEMqrCmG1UhD-sr3VHfujNLtbl0NKmraA_WkEHq2dXFu9Azv7LnNu6QID3HSl7w1rY_Sl7LevDpTPT_jmO4SLGnh0wKXWwORK4p111bHVN3Vc32qPfh-EJBLqbR7oTi1aH5szX5n7TTQ-Yb8U4u5i_rewaQtWEeAOBF8Bb7JxMFCLJt-N8K-SVUXK0HiV4m3JZ3ePrAsWJ2B6OzRMIeNU5FIeL2QJfEVia0JuUbU-NbzPe1rk-_N6SnLE05fCBizRakkq_T7MEp49Q7EF97kAY5xO6_bzncUNjzmqfmwaVwxdBWlDNpHaKhUUGZCWSiLhKlGxAcPplVG_JkwYsidITcUlcXEZU3Gk_z4jBN6TfOc9amODlKibuLU0l7soiwmnavAuu_xVYskzMeJkr4lpH48oJcZ_IA27HtjE-to-nU9sx7bEzmQzII3GHzvHIcEzHtCam44xNZ_Q8IH9VcS1jYh_bR87UnoydsTPVCBYliotf61fSkOe3yYo8_w8n-h_M)

Steps:
1. **Initialization**: The app starts an HTTP web server and a UDP listener.
2. **Discovery**: The UDP layer uses a STUN server to get the public IP and open a connection.
3. **Secure Handshake**: Peers exchange public keys over UDP.
4. **Transport**: A reliable, encrypted stream is created for data transfer.

---

## 🚀 Features

- **End-to-End Encryption**: Uses X25519 keys and HKDF for secure communication.
- **Forward Secrecy**: Creates session keys for each connection.
- **Identity Verification**: Shows SAS codes so users can verify connections.
- **Reliable UDP**: Uses KCP for fast, reliable transport.
- **NAT Traversal**: Connects through networks using STUN.
- **Real-Time Updates**: Sends live updates to the web UI using SSE.

---

## 🛠️ Technology

| Component     | Technology             | Purpose                                           |
|---------------|------------------------|--------------------------------------------------|
| Runtime       | Tokio                  | Manages I/O and tasks.                          |
| Transport     | Tokio KCP              | Handles reliable UDP communication.             |
| Cryptography  | RustCrypto             | Provides secure key and encryption functions.   |
| Web Framework | Axum                   | HTTP REST API and real-time event streaming.    |
| State         | Arc/RwLock             | Ensures thread-safe state management.           |
| Discovery     | STUN                   | Resolves public IPs and opens connections.      |

---

## 🔒 Security

**STATUS: Encrypted**

GhostLink v1.1 uses encryption to secure data:
- **Key Exchange**: Uses X25519 elliptic-curve.
- **Ciphers**: Uses ChaCha20-Poly1305 or AES-256-GCM.
- **Verification**: Users can check fingerprints to avoid interception.

Private keys are only stored in memory and never sent or saved.

---

## 📦 Installation

### Requirements

Install the latest versions of Rust and Cargo.

### Quick Start

1. **Clone the repo**:
    ```bash
    git clone https://github.com/pushkar-gr/ghostlink.git
    cd ghostlink
    ```
2. **Build and run**:
    ```bash
    cargo run --release
    ```
3. **Create a connection**:
    - Open `http://localhost:8080` in your browser.
    - Copy your public IP.
    - Share it with a peer.
    - Set an optional alias.
    - Press **Establish Link**.
    - Verify the fingerprint matches your peer’s.

---

## 🤝 Contributing

1. Fork the repository.
2. Create a branch:
   ```bash
   git checkout -b feature/example-feature
   ```
3. Make and commit your changes:
   ```bash
   git commit -m "Explain the feature"
   ```
4. Push the branch:
   ```bash
   git push origin feature/example-feature
   ```
5. Open a Pull Request.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0**. See the [LICENSE](./LICENSE) file for details.

---

*Start chatting today!* 👻
