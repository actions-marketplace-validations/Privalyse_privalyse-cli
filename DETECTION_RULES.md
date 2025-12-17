# Privalyse Detection Rules

This document lists all active detection rules in the Privalyse Scanner v0.1.

**Total Rules:** 30+
**Categories:** Code Privacy & Security, Frontend Privacy, Infrastructure Security

---

## 1. Code Privacy & Security (Backend)
*Focus on Server-Side Security, Data Flow, and GDPR Compliance*

### Cryptography & Secrets
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `PASSWORD_HARDCODED` | **Critical** | Hardcoded passwords or credentials found in the source code. | Art. 32 |
| `HARDCODED_SECRET` | **Critical** | Hardcoded API keys, tokens, or secrets in backend code. | Art. 32 |
| `PASSWORD_HASH_WEAK` | **Critical** | Use of weak hashing algorithms (MD5, SHA1) for passwords. | Art. 32 |
| `CRYPTO_ECB_MODE` | **Critical** | Use of ECB cipher mode (no semantic security). | Art. 32 |
| `CRYPTO_WEAK_CIPHER` | **Critical** | Use of weak encryption algorithms (e.g., DES). | Art. 32 |
| `CRYPTO_WEAK_HASH` | **High** | Use of weak hashing algorithms (MD5, SHA1) in non-password contexts. | Art. 32 |
| `CRYPTO_INSECURE_RANDOM` | **High** | Use of insecure random number generators in a security context. | Art. 32 |

### Session & Network Security
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `SESSION_INSECURE` | **High** | Insecure session configuration (e.g., `signed_cookies=False`, missing secure flags). | Art. 32 |
| `COOKIE_INSECURE` | **High** | Cookies set without the `Secure` flag (transmission over unencrypted connections). | Art. 32 |
| `COOKIE_TRACKING_CONSENT` | **High** | Tracking cookies set without a corresponding consent check mechanism. | Art. 6 |
| `CORS_WILDCARD` | **High** | CORS configuration allows all origins (`*`). | Art. 32 |
| `HTTP_PLAIN` | **High** | Usage of unencrypted HTTP instead of HTTPS. | Art. 32 |
| `HEADER_HSTS_MISSING` | **High** | Missing `Strict-Transport-Security` header (Enforces HTTPS). | Art. 32 |
| `COOKIE_NO_HTTPONLY` | **Medium** | Cookies set without the `HttpOnly` flag (XSS risk). | Art. 32 |
| `HEADER_XFRAME_MISSING` | **Medium** | Missing `X-Frame-Options` header (Clickjacking protection). | Art. 32 |
| `HEADER_CSP_MISSING` | **Medium** | Missing `Content-Security-Policy` header (XSS protection). | Art. 32 |
| `HEADER_CONTENT_TYPE_MISSING` | **Low** | Missing `X-Content-Type-Options` header (MIME sniffing protection). | Art. 32 |

### Data Privacy & Leakage
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `API_RESPONSE_LEAK` | **High** | Potential leak of PII in API responses. | Art. 32 |
| `HTTP_SEND_PII` | **High** | Detects PII being sent outbound via HTTP clients (requests, httpx). | Art. 32 |
| `PRINT_PII` | **Med/High** | Detects PII variables being printed to console or stdout. | Art. 32 |
| `LOG_PII` | **Medium** | Detects PII being sent to logging frameworks. | Art. 32 |
| `DB_WRITE_PII` | **Medium** | Writing PII to the database without clear encryption/hashing evidence. | Art. 32 |
| `BACKEND_PII_INPUT` | **Medium** | Unvalidated PII input detected in backend endpoints (Express/NestJS). | Art. 25 |

## 2. Frontend Privacy (React/JS)
*Focus on Client-Side Data Collection and Storage*

### Data Leakage & Storage
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `JS_DATA_LEAK` | **High** | Tainted PII variable passed to a sink (e.g., `console.log`, external API). | Art. 32 |
| `LOCAL_STORAGE_SENSITIVE` | **High** | Storage of sensitive data (tokens, PII) in `localStorage` or `sessionStorage`. | Art. 32 |
| `API_CALL_SENSITIVE` | **High** | Detects PII being sent via `fetch` or `axios` calls. | Art. 32 |

### Data Collection
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `TRACKING_SCRIPT` | **High** | Presence of third-party tracking scripts (Google Analytics, FB Pixel) without consent gates. | Art. 6 |
| `PII_FORM_FIELD` | **Var** | Detects form fields collecting personal data (Email, Password, Credit Card, etc.). | Art. 5 |

## 3. Infrastructure Security
*Focus on Docker, Cloud Config, and Server Hardening*

### Container Security (Docker)
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `DOCKER_SENSITIVE_ENV` | **Critical** | Sensitive environment variables (passwords, keys) hardcoded in Dockerfile. | Art. 32 |
| `DOCKER_ROOT_USER` | **High** | Container running as root user. | Art. 32 |
| `DOCKER_SENSITIVE_COPY` | **High** | Detects copying of sensitive files (`.env`, keys) into Docker images. | Art. 32 |
| `DOCKER_NO_HEALTHCHECK` | **Medium** | Missing HEALTHCHECK instruction in Dockerfile. | Art. 32 |
| `DOCKER_ADD_USAGE` | **Low** | Using `ADD` instead of `COPY` (potential for remote file inclusion). | Art. 32 |
| `DOCKER_LATEST_TAG` | **Low** | Using `latest` tag for base images (reproducibility/security risk). | Art. 32 |

### Server Configuration
| Rule ID | Severity | Description | GDPR Relevance |
| :--- | :--- | :--- | :--- |
| `CONFIG_HARDCODED_SECRET` | **High** | Detects secrets in generic config files (`.ini`, `.toml`, `.json`, `.yaml`). | Art. 32 |
| `INFRA_EXPRESS_HELMET_MISSING` | **Medium** | Express.js application missing `helmet` middleware for security headers. | Art. 32 |
| `INFRA_EXPRESS_FINGERPRINT` | **Low** | Server fingerprinting enabled (`X-Powered-By` header not disabled). | Art. 32 |

---

## Understanding Rule Coverage

While Privalyse lists **30+ Meta-Rules**, the effective coverage is much higher because each rule is **Semantic** and covers multiple data types.

For example, the single rule `PRINT_PII` automatically detects logging of **15+ different PII types**:
*   **Contact:** Email, Phone, Address
*   **Identity:** SSN, Passport, Driver License, Tax ID
*   **Financial:** Credit Card, IBAN, Bank Account
*   **Security:** Passwords, API Keys, Tokens
*   **Special Category (Art. 9):** Health Data, Biometric Data, Religion, Ethnicity

In a traditional SAST tool (like Bearer), these might be counted as separate rules (e.g., "Log Email", "Log SSN", "Log Credit Card"), resulting in hundreds of rules.

**Privalyse Philosophy:**
We focus on **Data Flow** and **Privacy Context** rather than just pattern matching. A single "Data Leak" rule in Privalyse covers the entire matrix of:
`[15 PII Types] x [10+ Sink Types (Log, DB, API, etc.)]` = **150+ Detection Scenarios**

This approach reduces noise and focuses on what matters for GDPR/CCPA compliance: **Where is personal data going?**
