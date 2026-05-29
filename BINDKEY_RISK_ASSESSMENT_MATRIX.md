# BINDKEY – RISK ASSESSMENT MATRIX

**Status legend:**
- **PLANNED** — Risk identified, no mitigation in place yet
- **IN PROGRESS** — Mitigation measures currently being implemented
- **MITIGATED** — All measures (prevention/detection/correction) are in place and tested
- **MONITORED** — Residual risk accepted, continuous monitoring (typically performance-related)

---

## 1. BindKey Firmware Compromise
**Responsible**: William
**Status**: IN PROGRESS

*A malicious or altered firmware could be installed on the BindKey, allowing security mechanisms to be bypassed.*

- Prevention: Use only verified and approved firmware versions
- Detection: Check firmware authenticity at device startup
- Correction: Reinstall a trusted firmware version

---

## 2. Physical Attack on the Secure Element
**Responsible**: Pierre-Louis
**Status**: PLANNED

*An attacker could physically tamper with the device to try to extract sensitive cryptographic keys.*

- Prevention: Physically protect the device and critical components
- Detection: Detect signs of physical tampering
- Correction: Automatically block access to stored keys

---

## 3. Biometric Data Leakage
**Responsible**: Pierre-Louis
**Status**: IN PROGRESS

*Sensitive biometric data could be exposed, leading to privacy and regulatory issues.*

- Prevention: Store biometric data only inside the BindKey
- Detection: Monitor access to biometric information
- Correction: Reset biometric data and notify the user

---

## 4. Server Compromise
**Responsible**: Jassime & Marwa
**Status**: IN PROGRESS

*The central server could be compromised, exposing user information, access rights, or recovery keys.*

- Prevention: Restrict access and protect stored data
- Detection: Monitor abnormal access attempts
- Correction: Restore the server and rotate compromised keys

---

## 5. Fake Enroller Creating Unauthorized BindKeys
**Responsible**: Jean-Baptiste
**Status**: IN PROGRESS

*An unauthorized person could impersonate an enroller and create fraudulent BindKeys.*

- Prevention: Secure access to enroller features
- Detection: Detect unusual enrollment activities
- Correction: Block the enroller account and revoke affected BindKeys

---

## 6. Loss or Corruption of Volume Encryption Keys
**Responsible**: Jassime & Marwa
**Status**: IN PROGRESS

*Encryption keys associated with a volume could be lost or corrupted, making data inaccessible.*

- Prevention: Securely back up encryption keys
- Detection: Verify that volumes can be correctly opened
- Correction: Generate new keys when recovery is possible

---

## 7. API Attack (Injection or Token Theft)
**Responsible**: Jassime
**Status**: MITIGATED

*Attackers could exploit the communication interfaces to gain unauthorized access.*

- Prevention: Validate all incoming data; use parameterized queries (sqlx) preventing SQL injection by design; JWT tokens with short TTL
- Detection: Monitor abnormal behavior and requests
- Correction: Invalidate access tokens and fix vulnerabilities

---

## 8. Unauthorized BindKey Reset
**Responsible**: Jean-Baptiste
**Status**: IN PROGRESS

*A BindKey could be reset without proper authorization, resulting in loss of control or data.*

- Prevention: Require identity verification or a recovery code
- Detection: Monitor reset attempts
- Correction: Cancel the reset and block the device

---

## 9. Volume Key Sent to the Wrong User
**Responsible**: Marwa
**Status**: MITIGATED

*During volume sharing, a key could be mistakenly sent to an unauthorized user.*

- Prevention: Verify user identity and permissions before sharing (owner check + recipient validation on every share route)
- Detection: Review assigned access rights
- Correction: Cancel the sharing and change the encryption key

---

## 10. Offline Mode Bypass
**Responsible**: William
**Status**: IN PROGRESS

*A BindKey could remain usable offline for longer than intended, especially after being lost or stolen.*

- Prevention: Limit the allowed offline usage duration
- Detection: Detect long periods without synchronization
- Correction: Block the device until synchronization

---

## 11. Malicious USB Device Connected to the BindKey
**Responsible**: William
**Status**: IN PROGRESS

*A malicious USB storage device could disrupt or compromise the BindKey.*

- Prevention: Verify that connected USB devices are compliant
- Detection: Detect abnormal device behavior
- Correction: Reject the USB device

---

## 12. Incorrect Time Synchronization
**Responsible**: Jean-Baptiste & William
**Status**: IN PROGRESS

*Incorrect system time can affect offline access duration and security checks.*

- Prevention: Synchronize time during server connections
- Detection: Detect inconsistent timestamps
- Correction: Automatically correct the system time

---

## 13. Server Overload
**Responsible**: Jassime
**Status**: MONITORED

*High usage could overload the server and degrade system availability.*

- Prevention: Properly size the server infrastructure
- Detection: Monitor response times
- Correction: Optimize or reconfigure the server

---

## 14. Biometric Authentication Failure or Bypass
**Responsible**: Pierre-Louis
**Status**: IN PROGRESS

*The biometric system may fail to recognize a legitimate user or be bypassed.*

- Prevention: Properly configure biometric parameters
- Detection: Detect repeated authentication failures
- Correction: Re-enroll biometric data

---

## 15. Information Leakage During Key Sharing
**Responsible**: Marwa
**Status**: IN PROGRESS

*Sensitive information could be exposed when encryption keys are shared between users.*

- Prevention: Restrict and control key sharing
- Detection: Audit key transfer operations
- Correction: Revoke shared keys

---

## 16. Slow Encryption Performance on Large Files
**Responsible**: William
**Status**: MONITORED

*Encrypting large files may significantly slow down data transfers.*

- Prevention: Optimize overall system performance
- Detection: Regular performance testing
- Correction: Improve firmware efficiency

---

## 17. Delayed Log Synchronization
**Responsible**: Jassime
**Status**: MONITORED

*Logs may not be synchronized in time, reducing traceability in case of incidents.*

- Prevention: Schedule regular log synchronization
- Detection: Detect synchronization delays
- Correction: Force manual or automatic synchronization

---

## 18. Privilege Escalation on Admin Workstation
**Responsible**: Jean-Baptiste
**Status**: PLANNED

*Malware on the PC running the Desktop Management Software could issue rogue administrative commands (unauthorized reassignment, enrollment, revocation).*

- Prevention: Require physical presence and biometric validation on the BindKey for every critical admin command
- Detection: Detect administrative commands issued without recent biometric confirmation
- Correction: Revoke the admin session and audit recent privileged actions

---

## 19. Side-Channel Attack (Timing or Power Analysis)
**Responsible**: Pierre-Louis & William
**Status**: PLANNED

*An attacker with physical possession of the BindKey could analyze power consumption or execution timing to extract cryptographic keys.*

- Prevention: Use constant-time cryptographic libraries and side-channel resistant implementations
- Detection: Perform side-channel evaluation during hardware validation
- Correction: Update firmware with hardened cryptographic primitives

---

## 20. Recovery Code Compromise
**Responsible**: Jean-Baptiste & Marwa
**Status**: IN PROGRESS

*The recovery code allowing key restoration on a new BindKey could be leaked (phishing, poor user storage), allowing an attacker to clone the cryptographic identity.*

- Prevention: Generate high-entropy recovery codes and require secure offline storage
- Detection: Log all recovery code usage attempts and alert on unusual locations
- Correction: Invalidate the compromised code, regenerate a new one and re-bind the user identity

---

# RISK ASSESSMENT MATRIX

| Impact → / Probability ↓ | LOW   | MODERATE | MAJOR        | CRITICAL              |
|--------------------------|-------|----------|--------------|-----------------------|
| **VERY LIKELY**          |       |          | #5           |                       |
| **LIKELY**               | #17   |          | #7           | #1, #4, #8, #10, #11, #18 |
| **UNLIKELY**             |       | #12, #13 | #6, #9, #15, #20 | #2, #3, #14, #19  |
| **VERY UNLIKELY**        | #16   |          |              |                       |

---

# STATUS CHANGE LOG

| # | Risk | Previous | New | Reason |
|---|---|---|---|---|
| 2 | Physical Attack on Secure Element | IN PROGRESS | **PLANNED** | Hardware-level tamper detection not yet implemented on prototype |
| 7 | API Attack (Injection / Token Theft) | IN PROGRESS | **MITIGATED** | sqlx parameterized queries prevent SQL injection by design; JWT validation in place |
| 9 | Volume Key Sent to Wrong User | IN PROGRESS | **MITIGATED** | Owner + recipient checks already enforced on share routes |
| 13 | Server Overload | IN PROGRESS | **MONITORED** | Capacity is sized for current load; ongoing performance monitoring |
| 16 | Slow Encryption on Large Files | IN PROGRESS | **MONITORED** | Inherent firmware limitation, tracked through perf benchmarks |
| 17 | Delayed Log Synchronization | IN PROGRESS | **MONITORED** | Sync delay is acceptable within tolerance, monitored continuously |
| 18 | Privilege Escalation Admin | *(new)* | **PLANNED** | Hardware confirmation of admin commands not yet wired |
| 19 | Side-Channel Attack | *(new)* | **PLANNED** | Side-channel hardening will start at hardware revision phase |
| 20 | Recovery Code Compromise | *(new)* | **IN PROGRESS** | Code generation in place, secure storage UX still in design |
