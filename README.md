<p align="center">
  <img src="assets/logo-bindkey.png" alt="BindKey Logo" width="450"/>
</p>

<h1 align="center">BindKey</h1>

<p align="center"><i>Security at your fingertip</i></p>

---

## Project overview

**BindKey** is a hardware cybersecurity solution that resolves the trade-off between offline data security and the need for enterprise collaboration. The device sits between the host PC and a standard storage medium (USB stick, SSD, SD reader) and acts as a **legitimate Man-in-the-Middle**: every byte that flows through it is sealed and encrypted on-the-fly in **AES-256-GCM** by a secure microcontroller, and is decrypted only for users who have been **biometrically** authenticated and whose BindKey holds the access rights to the target volume. Any modification performed outside the BindKey environment makes the content unreadable. The whole system works **off-cloud**, **with no host driver**, on Windows / Linux / macOS.

### The three pillars of the project

1. **The BindKey hardware proxy** — the physical box that handles local biometric authentication, key derivation through an ATECC608A secure element, and on-the-fly encryption of the data. Made of two ESP32-S3 microcontrollers:
   - a **master** (USB MSC emulation + biometrics + AES-GCM crypto + secure element) — repo [`bindkey-tinyesp`](https://github.com/bindkey-project/bindkey-tinyesp)
   - a **slave** (drives the real physical media in USB Host mode) — repo [`bindkey-esp`](https://github.com/bindkey-project/bindkey-esp)
2. **A backend server (API)** — repo [`bindkey-server`](https://github.com/bindkey-project/bindkey-server) **← this repo** — manages users' public identities and orchestrates access delegation between BindKeys in *Zero-Knowledge* mode: only wrapped keys (ECDH-wrapped) ever travel over the network, never the plaintext volume key.
3. **The desktop software** — repo [`bindkey-software`](https://github.com/bindkey-project/bindkey-software) — Rust application that drives the BindKey through UART and provides the GUI: volume creation / deletion, sharing with a colleague, formatting, reset, and any administration operation that requires the physical presence of the key.

### Main features

- **Transparent encrypted collaboration** between BindKeys using Zero-Knowledge cryptographic delegation
- **Session-based authentication** with HMAC-SHA256 hashed tokens
- **Role-Based Access Control (RBAC)** with USER / ENROLLER / ADMIN roles
- **Secure BindKey enrollment** and lifecycle management
- **X.509 certificate generation** for enrolled BindKeys
- **Collaborative encrypted sharing** using ECDH P-256 wrapped keys
- **AES-encrypted sensitive database fields**
- **Tamper-evident centralized audit logs** for forensic traceability and GDPR compliance
- **TLS-secured API communication**
- **Air-gapped compatible workflows** for isolated infrastructures

This repository contains the **backend API server** of the BindKey ecosystem.

---

# bindkey-server

BindKey - Secure Backend API Server

> Rust backend server for the BindKey project.

`bindkey-server` is the trusted orchestration layer of the BindKey architecture.
It exposes a secure REST API used by the desktop software and the hardware ecosystem.

The server never handles plaintext volume keys and follows a strict
**Zero-Knowledge** security model.

Its responsibilities include:

1. **User and session management**
2. **BindKey enrollment and lifecycle management**
3. **Collaborative encrypted sharing orchestration**
4. **Certificate authority operations**
5. **Audit logging and traceability**
6. **Role-Based Access Control (RBAC)**

---

## Place in the BindKey architecture

```
                ┌────────────────────┐
                │  Desktop Software  │
                │  bindkey-software  │
                └─────────┬──────────┘
                          │ HTTPS REST API
                          ▼
              ┌──────────────────────────┐
              │     bindkey-server       │   ← THIS REPO
              │  Rust + Axum + SQLx      │
              │  PostgreSQL + TLS        │
              │  Zero-Knowledge Backend  │
              └─────────┬────────────────┘
                        │
                        ▼
              ┌──────────────────────────┐
              │       PostgreSQL         │
              │ Sessions / Audit / RBAC │
              └──────────────────────────┘
```

The backend server is intentionally designed so that:

- volume encryption keys never appear in plaintext,
- wrapped ECDH blobs remain encrypted end-to-end,
- sensitive database fields are encrypted,
- session tokens are stored only as HMAC hashes,
- all sensitive actions are audited.

---

## Features

### Authentication & Sessions

- Session token generation
- HMAC-SHA256 token hashing
- Expiration validation middleware
- Bearer token authentication
- Hardware-assisted authentication workflow

### RBAC (Role-Based Access Control)

Supported roles:

- `USER`
- `ENROLLER`
- `ADMIN`

Protected routes enforce privilege separation.

### BindKey Management

- BindKey enrollment
- BindKey status update
- Device reset tracking
- Lifecycle management

### Certificate Authority

- Root CA management
- X.509 certificate generation
- Certificate storage and retrieval

### Collaborative Sharing

- Share request orchestration
- Wrapped encrypted key exchanges
- Pending share management
- Secure acknowledgment flow

### Security

- AES encryption for sensitive database fields
- TLS-secured communication
- Audit logs
- Zero-Knowledge architecture
- SQLx compile-time verified queries

---

## Tech stack

| Component      | Technology |
|----------------|------------|
| Language       | Rust |
| Web framework  | Axum |
| Database       | PostgreSQL |
| ORM layer      | SQLx |
| Cryptography   | AES-GCM / HMAC-SHA256 / ECDH |
| Authentication | Session-based authentication |
| TLS            | OpenSSL |
| Deployment     | Docker / Kubernetes |
| CI/CD          | GitHub Actions |

---

## System requirements

### Required software

- Rust (Edition 2024 recommended)
- Cargo
- PostgreSQL 16+
- OpenSSL
- Docker (optional)
- Kubernetes / Minikube (optional)

### Environment variables

The backend requires secure secrets:

```bash
DATABASE_URL=
ROOT_CA_CERT_PEM=
ROOT_CA_KEY_PEM=
TOKEN_HASH_SECRET=
PWD_ENCRYPTION_KEY=
RUST_LOG=info
```

---

## Installation

### Clone repository

```bash
git clone https://github.com/bindkey-project/bindkey-server.git
cd bindkey-server
```

---

## Database setup

### Start PostgreSQL

```bash
docker compose up -d
```

### Run migrations

```bash
sqlx migrate run
```

---

## Build, run and tests

### Development mode

```bash
cargo run
```

Default server:

```text
https://localhost:8080
```

### Release build

```bash
cargo build --release
```

Binary location:

```bash
./target/release/bindkey-server
```

---

## Quality and security pipeline

### Formatting

```bash
cargo fmt
```

### Compilation check

```bash
cargo check
```

### Clippy strict lint

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

### Test suite

```bash
cargo test
```

---

## Source tree

```
src/
├── api/
│   ├── auth/                 ← authentication & RBAC
│   ├── handlers/             ← REST API endpoints
│   ├── middleware/           ← auth middleware, encryption, CA
│   ├── models/               ← SQLx database models
│   └── audit/                ← audit logging system
│
├── db/                       ← PostgreSQL connection pool
├── tests/                    ← integration tests
├── main.rs                   ← application entrypoint
└── lib.rs                    ← shared initialization logic
```

---

## Security architecture

### Zero-Knowledge principles

The backend server:

- never stores plaintext volume keys,
- never decrypts collaborative wrapped blobs,
- never stores raw session tokens,
- never accesses biometric templates.

### Sensitive database encryption

Encrypted fields include:

- `bindkeys.pub_ecdh`
- `bindkeys.certificate`
- `volume_keys.encrypted_key`

### Session security

Session tokens:

- generated randomly,
- hashed using HMAC-SHA256,
- validated through middleware,
- expiration checked on every request.

---

## Continuous Integration

GitHub Actions pipeline automatically validates:

```bash
cargo fmt
cargo check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

The backend is considered production-ready only if all stages succeed.

---

## Related repositories

| Repository | Purpose |
|------------|---------|
| `bindkey-tinyesp` | Master ESP32 firmware |
| `bindkey-esp` | Slave ESP32 firmware |
| `bindkey-software` | Desktop application |
| `bindkey-server` | Backend API server |

---

## License and authors

BindKey academic project — INIZIATO William, LOPEZ Pierre-Louis, MATTEI Jean-Baptiste, ZAIETER Jassime, ADDOUH Marwa

