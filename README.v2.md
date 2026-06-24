# BindKey Server — v2

> Backend de **BindKey** : API HTTPS en Rust qui gère les utilisateurs, les clés matérielles
> **BindKey**, les volumes chiffrés, leur montage et leur partage entre clés.
>
> Cette page est une **v2** de la documentation. L'ancien `README.md` (notes d'exploitation
> rapides : commandes `kubectl`, inserts SQL de bootstrap) reste valable et complémentaire.

---

## 📑 Sommaire

- [Stack technique](#-stack-technique)
- [Architecture du code](#-architecture-du-code)
- [Prérequis](#-prérequis)
- [Configuration (variables d'environnement)](#-configuration-variables-denvironnement)
- [Démarrage en local](#-démarrage-en-local)
- [Base de données & migrations](#-base-de-données--migrations)
- [Sécurité](#-sécurité)
- [Référence de l'API](#-référence-de-lapi)
- [Tests](#-tests)
- [Déploiement (Docker / Kubernetes)](#-déploiement-docker--kubernetes)

---

## 🧰 Stack technique

| Domaine | Choix |
|---|---|
| Langage | Rust (edition **2024**) |
| Framework HTTP | [`axum`](https://docs.rs/axum) 0.7 |
| Serveur TLS | `axum-server` + `rustls` (HTTPS natif) |
| Runtime async | `tokio` |
| Base de données | PostgreSQL via [`sqlx`](https://docs.rs/sqlx) 0.8 (mode `offline` / `.sqlx`) |
| Hash secrets | `argon2` |
| Chiffrement | `aes-gcm` (AES-256-GCM) |
| Crypto / signatures | `ed25519-dalek`, `p256` / `ecdsa`, `ring`, `sha2` |
| PKI | `rcgen` (certificats X.509 signés par une Root CA) |
| Logs | `tracing` + `tracing-subscriber` |

---

## 🗂️ Architecture du code

```
src/
├── main.rs              # Point d'entrée : TLS + bind du serveur
├── lib.rs               # create_app_instance() : pool PG, migrations, chargement Root CA
├── config.rs            # Config::from_env() (port, DATABASE_URL)
├── db.rs                # AppState (pool + Root CA PEM)
└── api/
    ├── mod.rs           # create_app() : assemble routes publiques + protégées
    ├── auth.rs          # logique d'authentification
    ├── error.rs         # type d'erreur API
    ├── audit.rs         # journalisation (audit_logs)
    ├── middleware/      # auth_middleware, AES, Argon2, CA (PKI)
    ├── models/          # structs SQLx (user, bindkey, volume, session, share, …)
    ├── handlers/        # logique métier par domaine
    └── routes/          # déclaration des routes Axum par domaine
```

**Flux de démarrage** (`lib.rs`) : connexion PostgreSQL avec retry (anti-CrashLoop K8s) →
`sqlx::migrate!()` → chargement de la Root CA depuis l'environnement → construction du routeur.

**Découpage des routes** (`api/mod.rs`) :
- `public_routes` — `/health` + toutes les routes `/sessions/*` (login, etc.)
- `protected_routes` — users, bindkeys, volumes, mount, share — protégées par
  `auth_middleware` (sauf en `cfg(test)`, où le middleware est désactivé).

---

## ✅ Prérequis

- **Rust** (toolchain nightly — voir `Dockerfile`) pour le développement local
- **Docker** + **Docker Compose** (base de données / build)
- **PostgreSQL** accessible via `DATABASE_URL`
- Une **Root CA** (cert + clé PEM) pour signer les certificats des BindKeys

---

## 🔧 Configuration (variables d'environnement)

Le serveur lit ces variables (via `.env` en local, via Secrets en K8s) :

| Variable | Requis | Description |
|---|---|---|
| `DATABASE_URL` | ✅ | URL de connexion PostgreSQL |
| `BINDKEY_PORT` | — | Port d'écoute (défaut `8080`) |
| `RUST_LOG` | — | Niveau de logs `tracing` (ex. `info`, `bindkey_server=debug`) |
| `PWD_ENCRYPTION_KEY` | ✅ | Clé de chiffrement des secrets (AES-256-GCM) |
| `ROOT_CA_CERT_PEM` | ✅ | Certificat Root CA (Secret K8s `bindkey-rootca`) |
| `ROOT_CA_KEY_PEM` | ✅ | Clé privée Root CA — **le serveur refuse de démarrer si absente** |
| `SQLX_OFFLINE` | — | `true` pour compiler sans connexion DB (utilise `.sqlx/`) |

> ⚠️ Ne committez jamais les valeurs réelles. Le `.env` doit rester local / non versionné.

Exemple de `.env` :

```dotenv
DATABASE_URL=postgres://admin_bindkey:password@localhost:5432/bindkey
BINDKEY_PORT=8080
RUST_LOG=info
PWD_ENCRYPTION_KEY=<clé base64 32 octets>
```

---

## ▶️ Démarrage en local

```bash
# 1. Lancer PostgreSQL
docker compose up -d

# 2. Renseigner le .env (voir ci-dessus) + exporter la Root CA
export ROOT_CA_CERT_PEM="$(cat rootca.crt)"
export ROOT_CA_KEY_PEM="$(cat rootca.key)"

# 3. Lancer le serveur (migrations appliquées automatiquement au démarrage)
cargo run
```

Le serveur démarre en **HTTPS** sur `https://localhost:8080/` (certificat auto-signé généré
au démarrage par `rcgen` pour `localhost` / `127.0.0.1`).

Vérification rapide :

```bash
curl -k https://localhost:8080/health   # -> OK
```

---

## 🗄️ Base de données & migrations

Les migrations SQLx vivent dans `migrations/` (paires `*.up.sql` / `*.down.sql`) et sont
**appliquées automatiquement au démarrage** via `sqlx::migrate!()`.

Tables principales : `users`, `bindkeys`, `disks`, `volumes`, `volume_keys`,
`volume_shares`, `sessions`, `bindkey_resets`, `mounted_volumes`, `audit_logs`.

```bash
# Outils SQLx (optionnel)
cargo install sqlx-cli --no-default-features --features postgres

sqlx migrate run            # appliquer les migrations à la main
sqlx migrate revert         # annuler la dernière migration

# Régénérer le cache offline après modif d'une requête SQL
cargo sqlx prepare
```

> 💡 Côté API volumes, on renvoie au client le **label** du volume (pas l'UUID) : la BindKey
> ne comprend que le label.

---

## 🔐 Sécurité

- **TLS** de bout en bout (`rustls`).
- **Authentification** : header `Authorization: Bearer <token>` validé par `auth_middleware`
  sur toutes les routes protégées ; injecte un `AuthUser` dans les extensions de la requête.
- **Secrets au repos** : mots de passe hachés (Argon2), données sensibles chiffrées AES-256-GCM.
- **PKI** : chaque BindKey peut recevoir un certificat X.509 signé par la Root CA du serveur.
- **Audit** : actions sensibles tracées dans `audit_logs`.
- **RBAC** : rôles `ADMIN` / `ENROLLER` pour les routes `/admin/*` et certaines opérations.

Voir `BINDKEY_RISK_ASSESSMENT_MATRIX.md` pour la matrice de risques, et `share_server.md`
pour le détail du protocole de partage de volumes.

---

## 📡 Référence de l'API

> Base URL : `https://<host>:<port>` — toutes les routes hors `Public` exigent
> `Authorization: Bearer <token>`.

### Public

| Méthode | Route | Description |
|---|---|---|
| GET | `/health` | Liveness probe (`OK`) |
| POST | `/sessions/login` | Ouvre une session |
| POST | `/sessions/verify` | Vérifie une session / un challenge |
| POST | `/sessions/refresh` | Rafraîchit la session |
| POST | `/sessions/logout` | Ferme la session |
| POST | `/sessions/test` | Endpoint de test de session |

### Utilisateurs

| Méthode | Route | Description |
|---|---|---|
| POST | `/users` | Crée un utilisateur |
| GET | `/users` | Récupère un utilisateur par email |
| GET | `/users/search` | Recherche un utilisateur par email |
| GET | `/users/:id` | Détail d'un utilisateur |
| PATCH | `/users/:id/status` | Met à jour le statut |
| POST | `/auth/register` | Enregistre un utilisateur avec sa clé |
| GET | `/admin/users` | Liste les utilisateurs *(ADMIN)* |
| GET | `/admin/users/search` | Recherche *(ADMIN)* |
| DELETE | `/admin/users/:id` | Supprime un utilisateur *(ADMIN)* |

### BindKeys

| Méthode | Route | Description |
|---|---|---|
| POST | `/bindkeys/enroll` | Enrôle une nouvelle BindKey |
| GET | `/bindkeys/:id` | Détail d'une BindKey |
| GET | `/users/:id/bindkeys` | BindKeys d'un utilisateur |
| PATCH | `/bindkeys/:id/status` | Change le statut |
| POST | `/bindkeys/:id/reset` | Réinitialise une BindKey |
| PATCH | `/admin/bindkeys/:serial_number/status` | Statut par n° de série *(ADMIN)* |
| POST | `/bindkeys/:id/certificate` | Génère le certificat X.509 (retourné **une seule fois**) |
| GET | `/bindkeys/:id/certificate` | Récupère le certificat X.509 PEM |

### Volumes

| Méthode | Route | Description |
|---|---|---|
| POST | `/volumes/prepare` | Prépare un volume |
| POST | `/volumes/verify` | Vérifie si un label de volume existe déjà |
| GET | `/volumes/find_id` | Retrouve l'ID d'un volume |
| POST | `/volumes` | Crée un volume |
| GET | `/volumes/:id` | Détail d'un volume |
| GET | `/volumes/:id/key` | Récupère la clé (chiffrée) du volume |
| GET | `/users/:id/volumes` | Volumes d'un utilisateur |
| PATCH | `/volumes/:id` | Met à jour un volume |
| DELETE | `/volumes/:id` | Supprime un volume |
| DELETE | `/volumes/delete_id/:id` | Supprime un volume par label |

### Montage

| Méthode | Route | Description |
|---|---|---|
| POST | `/mount` | Trace le montage d'un volume |
| POST | `/unmount/:id` | Trace le démontage d'un volume |

### Partage de volumes

| Méthode | Route | Description |
|---|---|---|
| POST | `/share_request` | Demande de partage d'un volume |
| POST | `/share_complete` | Finalise un partage |
| POST | `/share_acknowledged` | Accuse réception d'un partage |
| GET | `/shares/received` | Partages reçus |
| GET | `/shares/pending` | Partages en attente |
| POST | `/shares/:id/accept` | Accepte un partage |
| POST | `/shares/:id/deny` | Refuse un partage |
| DELETE | `/shares/received/:id` | Retire un partage reçu |
| DELETE | `/shares/sent` | Révoque un partage envoyé |

---

## 🧪 Tests

La suite d'intégration vit dans `Tests/bindkey_tests.rs`. Elle s'appuie sur la feature
`skip-auth` qui **désactive `auth_middleware`** pour les tests.

```bash
cargo test
```

> En mode test (`cfg(test)`), le middleware d'auth est court-circuité et un utilisateur réel
> est injecté pour éviter les violations de clés étrangères (`owner_id`, `created_by`, …).

---

## 🚀 Déploiement (Docker / Kubernetes)

**Build de l'image** (multi-stage, compilation `--release` en mode SQLx offline) :

```bash
docker build -t bindkey-server .
```

Le binaire s'exécute sur le port `8080` (exposé dans le `Dockerfile`).

**Kubernetes** — manifests fournis à la racine :
- `bindkey-deployment.yaml`, `bindkey-ingress.yaml`, `kustomization.yaml`
- Root CA injectée via le Secret `bindkey-rootca` (`ROOT_CA_CERT_PEM` / `ROOT_CA_KEY_PEM`)

Commandes d'exploitation courantes (port-forward de l'Ingress, accès `psql`, inserts de
bootstrap admin) : voir le **`README.md`** d'origine.

---

*BindKey — Master Project · Server Code Repository.*
