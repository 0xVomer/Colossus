
# Case-Study: Zero-Trust Healthcare Sharing with CP-ABE, UCAN and DID

## Overview

The scenario is a trauma case in an emergency department.
-  The **Patient** owns their encrypted record.
-  A **Doctor** on duty needs immediate read/write access.
-  A **Nurse** shall update vitals but not prescribe drugs.
-  An **Attribute Authority (AA)** manages medical roles and revocations.
-  A **DID Registry** anchors every principal to a tamper-evident DID document.
-  A **Zero-Trust Policy Engine** continuously scores each request before letting UCAN invoke CP-ABE decryption.


```rust



             (((((((((((((( \\\\
             ))) ~~      ~~  (((
             ((( (*)-----(*) )))
             )))     <       (((
             ((( '\______/`  )))
             )))\___________/(((          (1) Records are
                    _) (_                 encrypted under     .--.                                                  _ _.-'`-._ _
                   / \_/ \                  access-policy     |__| .-------.             (4) Acquire               ;.'________'.;
                  /(     )\   ◀═══════════════════════════▶   |=.| |.-----.|      Access-Rights Keys    _________n.[____________].n_________

                 \\(     )//             ║Encrypted███████║   |  | |'-----'|                           |"""""""""""||..||..||..||"""""""""""|
                  (       )              ║Record██████████║   |__|~')_____('                           |LI LI LI LI||LI||LI||LI||LI LI LI LI|
                   |  |  |               ╚════════════════╝          ▲                                 |.. .. .. ..||..||..||..||.. .. .. ..|
                    | | |                                            ║                                 |LI LI LI LI||LI||LI||LI||LI LI LI LI|
                    | | |                                 (5) Nurse  ║  (3) Submit                  ,,;;,;;;,;;;,;;;,;;;,;;;,;;;,;;,;;;,;;;,;;,,
                   _|_|_|_                                  granted  ║  Access-Request             ;;jgs;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
                   Doctor                                   accesss  ║  with UCAN + DID                            Root Authority
                                                                     ║
                     ║                                               ▼      ╭────────────╮
                     ║                                          ////^\\\\   │░░░░░░░░░░░░│
       (2) Delegate  ║                                          | ^   ^ |   │░UCAN░+░DID░│
     UCAN for Nurse  ║                                         @ (o) (o) @  │░░░░░░░░░░░░│
                     ║                                          |   <   |   ╰────────────╯
                     ║                                          |  ___  |
                     ║                                           \_____/
                     ║           ╭────────────╮                ____|  |____
                     ║           │░░░░░░░░░░░░│               /    \__/    \
                     ╚═════════▶ │░░░░UCAN░░░░│═══════════▶  /              \
                                 │░░░░░░░░░░░░│             /\_/|        |\_/\
                                 ╰────────────╯            / /  | Nurse  |  \ \
                                                          ( <   |        |   > )
                                                           \ \  |        |  / /
                                                            \ \ |________| / /
                                                             \ \|

```

## 2  Actors and Trust Domains


| Actor | DID namespace | Main secrets | Typical devices |
|-------|---------------|--------------|-----------------|
| Patient | did:iota:pat-xxx | user key pair + CP-ABE MSK fragment | mobile app |
| Doctor  | did:iota:doc-yyy | UCAN signing key + CP-ABE user key | hospital workstation |
| Nurse   | did:iota:nur-zzz | delegated UCAN + limited CP-ABE key | tablet on ward |
| AA (Policy CA) | did:iota:aa-org | Covercrypt master keys | HSM |
| DID Registry | IOTA Stardust | ledger state | node cluster |
| Zero-Trust Gate | did:web:zt-edge | TLS certs | API gateway |

## 3  End-to-End Flow

1. **Provisioning**
   * AA creates the global Covercrypt policy with axes *Role*, *Department*, *Clearance* and *Hospital*.
   * DID Manager issues and publishes DID documents for every staff member.

2. **Encryption (patient discharge)**
   * Doctor encrypts the PDF summary under policy `Role::Doctor && Department::Emergency && Clearance::Advanced`.
   * Ciphertext is stored in the hospital object store.

3. **Capability Delegation**
   * Doctor issues a UCAN delegating `read,update_vitals` for the specific record to the Nurse, valid until shift end.

4. **Access Request**
   * Nurse’s app sends a request with her UCAN and DID.
   * Zero-Trust engine evaluates identity, device posture, behaviour, time and location, returning confidence 0.86 ⇒ *Allow*.

5. **Decryption**
   * CP-ABE layer checks that the Nurse’s key matches the policy embedded in the header and decrypts the symmetric key.
   * Vitals are appended; write is re-encrypted.

6. **Audit**
   * The gate logs UCAN chain, DID, risk score and CP-ABE key-ID to immutable storage.

## 4  Library Components

-  **cpabe_manager** – builds healthcare attribute axes, encrypts records, generates & refreshes user keys with Covercrypt.
-  **ucan_manager** – creates, delegates and validates UCAN tokens with custom healthcare capabilities.
-  **did_manager** – crafts and updates DID documents and verifiable credentials on the IOTA network.
-  **zt_manager** – calculates risk scores from identity, device, behaviour and threat-intel before deciding *Allow / Deny / Challenge*.
-  **lib** – shared domain structs (Patient, HealthcareProvider, MedicalRecord, UCANToken, etc.).

## 5  How the Layers Interlock

### 5.1  CP-ABE (Covercrypt)
-  Encryption policy is a boolean expression over healthcare attributes; only keys derived from matching attributes can unwrap the AES-GCM payload.
-  Attribute rotation lets the AA revoke *Doctor* keys instantly without re-encrypting old data.

### 5.2  UCAN Capabilities
-  UCANs are signed JWT-like tokens; each carries a DAG of delegations proving how a principal obtained authority.
-  The Doctor’s UCAN lists two capabilities on the record URL: `read` and `update_vitals` — the Nurse cannot prescribe because that action is absent.

### 5.3  Decentralised Identifiers
-  Each staff DID document embeds the public keys used both for CP-ABE key derivation and UCAN signing.
-  Verification is offline-capable: the gateway fetches DID documents once, caches them, then checks the signature inside every UCAN.

### 5.4  Zero-Trust Controls

| Factor | Example check | Weight |
|--------|---------------|--------|
| Identity | DID signature valid & MFA present | 0.25 |
| Device   | OS patch level & disk encryption | 0.20 |
| Behaviour | Access during previous shifts | 0.15 |
| Location  | Inside hospital geofence | 0.15 |
| Resource  | Sensitivity tag “medical” | 0.15 |
| Threat    | No brute-force indicators | 0.10 |

If the weighted score exceeds the policy threshold, the UCAN invocation is forwarded; otherwise the request is *Challenged* (additional MFA) or *Denied*.

## 6  Security Discussion

* **Least Privilege** – cryptographic policy and capability token must both authorise the exact action.
* **Continuous Verification** – every request is rescored; a device that drifts out of compliance will be blocked even if the UCAN is still valid.
* **Cryptographic Revocation** – AA can rotate an attribute (e.g., suspended license) and immediately render all corresponding CP-ABE keys useless.
* **Non-repudiation** – audit log stores hash of UCAN proof chain and DID public key for forensic traceability.
