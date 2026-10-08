# Historical lab report

> Archival coursework, not a fresh experiment. Team context is retained; individual responsibility is not inferred. Screenshots and raw captures are not bundled. Source evidence placeholders remain incomplete. Read [review notes](../docs/report-review-notes.md).

# COMP4337/9337 Lab 5 Report

## Security Analysis Using TShark / Wireshark

**Group Name:**  T16A-05
**Member Names and zIDs:**  

---

# Part B: Analysing Transport Layer Security

## Q1. TLS Packet Table (Packets 12, 14, 16, 18, 20, 30)

A `tls` display filter was applied in Wireshark to isolate TLS traffic. Each of the six packets was inspected individually in the packet details pane.

| Packet No. | Source | No. of TLS Records | Record Type(s) |
| ---------- | ------ | ------------------ | -------------- |
| 12         | Client | 1                  | Handshake (Client Hello) |
| 14         | Server | 4                  | Handshake (Server Hello), Handshake (Certificate), Handshake (Server Key Exchange), Handshake (Server Hello Done) |
| 16         | Client | 3                  | Handshake (Client Key Exchange), Change Cipher Spec, Handshake (Encrypted Handshake Message) |
| 18         | Server | 1                  | Change Cipher Spec |
| 20         | Server | 1                  | Handshake (Encrypted Handshake Message) |
| 30         | Client | 1                  | Handshake (Encrypted Handshake Message) |

---

## Q2. Client Hello Analysis

### (a) Nonce (Random)

```
Random: 1ed24d31eb077f45cf6cb0145390c4f1c86f3b7dc3e9868c00fdcf791e414acc
    GMT Unix Time: May 22, 1986 08:33:21
    Random Bytes: eb077f45cf6cb0145390c4f1c86f3b7dc3e9868c00fdcf791e414acc
```

- Yes, the Client Hello does contain a nonce.
- Value: **`1ed24d31eb077f45cf6cb0145390c4f1c86f3b7dc3e9868c00fdcf791e414acc`** (32 bytes: 4-byte GMT Unix Time + 28 random bytes)

---

### (b) Cipher Suites

```
Cipher Suites Length: 196 bytes
Cipher Suites (98 suites)
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 (0xc02c)
    ...
```

- Yes, the Client Hello does advertise cipher suites. There are 98 suites in total.
- For the first listed suite `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (0xc030)`:
  - Key exchange protocol: ECDHE (Elliptic Curve Diffie-Hellman Ephemeral)
  - Digital signature algorithm: RSA
  - Encryption algorithm: AES-256-GCM
  - Hash algorithm: SHA-384

---

### (c) Signature Hash Algorithms

```
Extension: signature_algorithms
    Signature Hash Algorithms (15 algorithms)
        Signature Algorithm: rsa_pkcs1_sha512 (0x0601)  [Hash: SHA512, Sig: RSA]
        ...
        Signature Algorithm: ecdsa_sha1 (0x0203)        [Hash: SHA1, Sig: ECDSA]
```

- The client supports 15 signature hash algorithm pairs.
- The last listed algorithm:
  - Hash algorithm:** SHA1
  - Signature algorithm: ECDSA

---

## Q3. Server Hello Analysis

### (a) Chosen Cipher Suite

The Server Hello is the first TLS record in Packet 14.

```
TLSv1.2 Record Layer: Handshake Protocol: Server Hello
    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)
```

- Yes, the Server Hello specifies a chosen cipher suite: `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 (0x006b)`
  - Key exchange: DHE (Ephemeral Diffie-Hellman)
  - Authentication / Digital signature: RSA
  - Encryption: AES-256-CBC
  - MAC / Hash: SHA-256

---

### (b) Server Nonce and Purpose of Nonces

```
Handshake Protocol: Server Hello
    Random: 54cb6b9fe38ab4db7875903c5d093a809fb62db3142b2a7043d2dffd742fed76
        GMT Unix Time: Jan 30, 2015 22:31:43
        Random Bytes: e38ab4db7875903c5d093a809fb62db3142b2a7043d2dffd742fed76
```

**Answer:**

- Yes, the Server Hello includes a nonce. It is 32 bytes long (same structure as the client nonce).
- Value: `54cb6b9fe38ab4db7875903c5d093a809fb62db3142b2a7043d2dffd742fed76`
- Both nonces are fed into the PRF (Pseudo-Random Function) together with the pre-master secret to derive the master secret and then the session keys to preventing replay attacks.

---

### (c) Session ID and Its Purpose

```
Handshake Protocol: Server Hello
    Session ID Length: 32
    Session ID: [REDACTED]
```

- Yes, the Server Hello includes a session ID (32 bytes):
  `[REDACTED HISTORICAL SESSION ID]`
- Session ID enables session resumption. If the client reconnects and provide this ID, server can reesume previously negotiated master secret and skip the full handshake, reducing latency on reconnected connections.

---

### (d) Certificate

The certificate arrives as a **separate TLS record** within the same Packet 14 (the second of the four records), immediately after Server Hello.

```
TLSv1.2 Record Layer: Handshake Protocol: Certificate
    Certificates (723 bytes)
        subject: CN=mail.example.com, C=NL
        issuer:  CN=mail.example.com, C=NL  (self-signed)
        validity: 2015-01-30 to 2018-01-29
```

**Answer:**

- The certificate is sent in a **separate Certificate record**, not inside Server Hello.
- Packet 14 is **1939 bytes** in total, which exceeds the standard Ethernet MTU of 1500 bytes. It does **not** fit into a single standard Ethernet frame. (In this capture it appears as one frame because the traffic runs over the loopback interface, which supports an MTU of 65535 bytes.)
- **Certificate owner (Subject CN):** **`mail.example.com`**

---

### (e) Diffie-Hellman Parameters (Server Key Exchange)

The Server Key Exchange is the third record in Packet 14.

```
TLSv1.2 Record Layer: Handshake Protocol: Server Key Exchange
    Diffie-Hellman Server Params
        p Length: 256 bytes
        p:      ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1b54b1597b61d0a7
                5e6fa141df95a56dbaf9a3c407ba1df15eb3d688a309c180e1de6b85a1274a0
                a66d3f8152ad6ac2129037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12
                207c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0
        g Length: 256 bytes
        g:      ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf74866a08cfe4ffe
                3a6824a4e10b9a6f0dd921f01a70c4afaab739d7700c29f52c57db17c620a86
                52be5e9001a8d66ad7c17669101999024af4d027275ac1348bb8a762d0521bc
                98ae247150422ea1ed409939d54da7460cdb5f6c6
        Pubkey Length: 256 bytes
        Pubkey: 375ac727e893eaa252cd21368d644f594329f5bf8d920d7958c79c82337f581
                ba90d4326a3d042d08bb3eb896f2f124e77d6af14aeb74de01a48d59f7e109a
                373d7ff531050ea5956f89223b84a6e0de797d434e8865e73a4e26d25f126ba
                2c4e80b229aa34f8ee38774fa429f008f2a8
```

**Answer:**

- **g (256 bytes):** `ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf74866a08cfe4ffe3a6824a4e10b9a6f0dd921f01a70c4afaab739d7700c29f52c57db17c620a8652be5e9001a8d66ad7c17669101999024af4d027275ac1348bb8a762d0521bc98ae247150422ea1ed409939d54da7460cdb5f6c6`
- **p (256 bytes):** `ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1b54b1597b61d0a75e6fa141df95a56dbaf9a3c407ba1df15eb3d688a309c180e1de6b85a1274a0a66d3f8152ad6ac2129037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12207c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0`
- **Server public key (256 bytes):** `375ac727e893eaa252cd21368d644f594329f5bf8d920d7958c79c82337f581ba90d4326a3d042d08bb3eb896f2f124e77d6af14aeb74de01a48d59f7e109a373d7ff531050ea5956f89223b84a6e0de797d434e8865e73a4e26d25f126ba2c4e80b229aa34f8ee38774fa429f008f2a8`

---

## Q4. Client Key Exchange, Change Cipher Spec, and Encrypted Handshake Message

### (a) Client Key Exchange — Public Key and Pre-Master Secret

All three client records are in Packet 16. The Client Key Exchange is the first.

```
TLSv1.2 Record Layer: Handshake Protocol: Client Key Exchange
    Diffie-Hellman Client Params
        Pubkey Length: 256 bytes
        Pubkey: 589c62500568139e8d5e3419df3d4918c1e25a5556608ebabd41dcbd9784d9d
                93813e92d2935235517659e4c8a5caa53aea932d825a58a70c3a89f3b189cfe
                65865abd172af09064e5d1956a1270f0a8e0e9baa9d6d36e12d2944dfc0af16
                c65fba4f8213f973ecc594ebc8d3baa87660
```

**Answer:**

- **Client DH public key (256 bytes):** `589c62500568139e8d5e3419df3d4918c1e25a5556608ebabd41dcbd9784d9d93813e92d2935235517659e4c8a5caa53aea932d825a58a70c3a89f3b189cfe65865abd172af09064e5d1956a1270f0a8e0e9baa9d6d36e12d2944dfc0af16c65fba4f8213f973ecc594ebc8d3baa87660`
- **Does this record contain a pre-master secret?** No. In DHE, the pre-master secret is never transmitted. Both sides independently compute `g^(ab) mod p`: the client computes `server_pubkey^client_privkey mod p` and the server computes `client_pubkey^server_privkey mod p`. Only public keys are exchanged over the wire.

---

### (b) Change Cipher Spec — Purpose and Size

```
TLSv1.2 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec
    Content Type: Change Cipher Spec (20)
    Version: TLS 1.2 (0x0303)
    Length: 1
    Change Cipher Spec Message
```

**Answer:**

- **Purpose:** Signals to the peer that all subsequent records from this sender will be encrypted using the newly negotiated cipher suite and session keys, marking the transition from the plaintext handshake to the encrypted channel.
- **Record size:** The payload is **1 byte** (`0x01`). Including the 5-byte TLS record header (1 content-type + 2 version + 2 length), the total on the wire is **6 bytes**.

---

### (c) Encrypted Handshake Message — Content and Encryption

```
TLSv1.2 Record Layer: Handshake Protocol: Encrypted Handshake Message
    Content Type: Handshake (22)
    Version: TLS 1.2 (0x0303)
    Length: 80
```

Answer:

- The TLS Finished message, which contains a PRF-derived hash computed over the entire handshake transcript combined with the master secret and the label `"client finished"`. This allows the server to verify that the handshake was not tampered with and that both parties derived the same session keys.
- Encrypted with AES-256-CBC using the client write key, and integrity-protected with HMAC-SHA-256 using the client write MAC key — both derived from the master secret via the PRF.

---

## Q5. Server's Change Cipher Spec and Encrypted Handshake Message

The server sends its Change Cipher Spec in Packet 18 and its Encrypted Handshake Message (Finished) in Packet 20.

Yes, the server also sends both records. Packet 18 signals the server's switch to the negotiated cipher suite, and Packet 20 carries the server's Finished message confirming the handshake transcript.

Differences from the client's records:

- Encryption key: The server's records are encrypted with the server write key and server write MAC key, which are distinct from the client's write keys even though both are derived from the same master secret. TLS derives independent keys for each direction.
- Finished label: The PRF input uses `"server finished"` instead of `"client finished"`, so the resulting MAC values differ.
- Payload size: The server's Encrypted Handshake Message has a 272-byte payload (Packet 20), significantly larger than the client's 80-byte payload (Packet 16), due to additional handshake data included by the server.

---

## Q6. Application Data Encryption

- **How is Application Data encrypted: Using AES-256-CBC with HMAC-SHA-256 for integrity, as negotiated in the cipher suite `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`. Session keys (encryption key, MAC key, IV) are derived from the master secret via the PRF.
- Application layer protocol: SMTP over TLS (STARTTLS). This capture shows a standard SMTP session on port 25: the client sent `EHLO`, the server advertised `STARTTLS`, the client issued `STARTTLS`, and TLS was negotiated on top of the existing TCP connection. Post-handshake records carry encrypted SMTP commands and responses.
- Do client and server use the same encryption key? No. TLS derives separate write keys for each direction. The client write key encrypts data from client to server; the server write key encrypts data from server to client. Independent keys per direction prevent reflection attacks.

---

## Q7. TLS Handshake Timing Diagram

| # | Pkt | Direction | Record | Brief Description |
|---|-----|-----------|--------|-------------------|
| 1 | 12 | Client → Server | Client Hello | Client sends its nonce and 98 supported cipher suites. |
| 2 | 14 | Server → Client | Server Hello | Server selects `TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`, sends its nonce and session ID. |
| 3 | 14 | Server → Client | Certificate | Server sends its X.509 certificate (`CN=mail.example.com`) for authentication. |
| 4 | 14 | Server → Client | Server Key Exchange | Server sends DHE parameters (g, p) and its public key, signed with RSA-SHA256. |
| 5 | 14 | Server → Client | Server Hello Done | Server signals it has finished the hello phase. |
| 6 | 16 | Client → Server | Client Key Exchange | Client sends its DHE public key; both sides now compute the pre-master secret independently. |
| 7 | 16 | Client → Server | Change Cipher Spec | Client signals that all subsequent messages will be encrypted with the negotiated keys. |
| 8 | 16 | Client → Server | Finished | Client sends an encrypted PRF hash of the handshake transcript (`"client finished"`). |
| 9 | 18 | Server → Client | Change Cipher Spec | Server signals that all subsequent messages will be encrypted with the negotiated keys. |
| 10 | 20 | Server → Client | Finished | Server sends an encrypted PRF hash of the handshake transcript (`"server finished"`). Handshake complete. |
| 11 | 22+ | Both | Application Data | Encrypted SMTP traffic exchanged over the established secure channel (AES-256-CBC). |
