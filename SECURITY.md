# Security Model

This document describes the security properties, threat model, and known
limitations of Aether LITE. It targets **developers integrating the Aether
SDK** — not end users.

---

## Threat Model

Aether operates on a **LAN-only peer-to-peer** basis. There is no
internet-facing server in the data path. The relevant threat actors are:

| Threat | Description | Defense |
|--------|-------------|---------|
| Passive eavesdropping | Sniffing LAN traffic | Session encryption (ChaCha20) hides file payload |
| Active MITM | Intercept + modify traffic in flight | HMAC-SHA256 ticket auth; ECDH key exchange |
| Replay attack | Re-use a captured ticket | SHA-256 digest cache with 120 s TTL + periodic background eviction |
| Tampering | Modify file bytes during transfer | Inline SHA-256 verification during streaming |
| Manifest forgery | Distribute malicious model updates | ECDSA-P256-SHA256 manifest signatures |
| Key extraction | Extract ECDH private key from device | Android Keystore TEE / iOS Secure Enclave storage |

---

## Authentication Modes

### QR Pinning (recommended for production)

Out-of-band key exchange via camera. The seeder encodes its public key into a
QR payload; the leecher scans it and pins the key before any network
interaction.

- Immune to network-level MITM — the key is exchanged over a visual channel,
  not the LAN.
- After pinning, all subsequent sessions verify the stored pin against the
  seeder's `/identity` endpoint.

**When to use:** Any deployment where devices are not pre-paired or where the
LAN is shared with untrusted hosts.

### Trust-On-First-Use (TOFU)

> ⚠️ **WARNING:** In TOFU mode, the **first handshake is vulnerable to active
> MITM** on the local network. An attacker on the same LAN can intercept the
> plaintext HTTP `/identity` fetch and substitute their own public key, gaining
> the ability to decrypt all model traffic in that session.
>
> Use TOFU **only for development and testing**. For production deployments,
> always perform initial peer onboarding via QR code.

In TOFU mode, the leecher trusts the first public key it receives from the
seeder's `/identity` endpoint and stores it locally. Future sessions verify
the stored pin against subsequent `/identity` responses.

### Subsequent Sessions

After the first TOFU or QR pin, future sessions:

1. Fetch `/identity` from the seeder.
2. Compare the returned public key against the stored pin.
3. Abort if the key differs (pin mismatch → potential MITM).
4. Proceed with ECDH if the key matches.

**Key rotation:** To rotate a seeder's key, all leechers must re-onboard via
QR. There is no automatic key rotation mechanism.

**Pin revocation:** A leecher can clear its stored pin for a peer, which
forces re-onboarding (QR or TOFU) on the next session.

---

## Transport Security

| Property | Mechanism |
|----------|-----------|
| Session encryption | ChaCha20 with HKDF-derived per-session key + random 12-byte nonce |
| Key derivation | HKDF-SHA256 from ECDH shared secret, domain-separated labels (`aether-hmac-v1`, `aether-transport-v1`, `aether-stream-session-v1`) |
| Ticket authentication | HMAC-SHA256, constant-time comparison, ±60 s timestamp window |
| Anti-replay | SHA-256 digest of ticket stored in `DashMap`; expired entries evicted by periodic background task (30 s cycle, 120 s TTL) |
| Memory hygiene | `ZeroizeOnDrop` wipes HMAC/transport keys from RAM on drop |
| Rate limiting | `Semaphore` caps concurrent download sessions (default: 10) |

---

## Known Limitations

1. **Control plane is plaintext.** HTTP headers, query parameters, and the
   `/identity` endpoint are unencrypted on the LAN. An eavesdropper can see
   peer IDs, model IDs, and protocol metadata.

2. **`/identity` endpoint is unauthenticated.** This is by design — a peer
   must fetch the seeder's public key *before* it has a shared secret. The
   security of this step depends entirely on the authentication mode (QR pin
   vs TOFU).

3. **No forward secrecy per message.** The session key is derived from static
   ECDH keys. Compromise of a device's long-term private key allows
   decryption of all past and future sessions with that peer. Forward secrecy
   would require an interactive key agreement (e.g., X3DH) which is not yet
   implemented.

4. **Discovery is manual.** mDNS/Bonjour auto-discovery is not yet
   implemented. Peers must be configured with explicit IP addresses. This
   limits the attack surface (no rogue service advertisement) but increases
   friction.

---

## Reporting

To report a security vulnerability, please email
**security@b-one-labs.dev** with the subject line
`[Aether Security] <brief description>`.

Do **not** file public issues for security vulnerabilities.

We aim to acknowledge reports within 48 hours and provide a fix or mitigation
within 7 calendar days.
