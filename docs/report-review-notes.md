# Review Notes for Historical Wireless Reports

These reports describe coursework observations. Original screenshots and captures are not included, and the lab was not rerun.

- WEP's reported 11,364 IVs is a historical observation from one setup, not a universal cracking threshold. The IV-space calculation is a theoretical exhaustion bound; random collisions can happen much earlier. Nominal 128-bit WEP includes the 24-bit IV.
- MITM Part A concerns plaintext HTTP. Redirecting TCP port 443 to a proxy does not automatically decrypt correctly validated HTTPS. The Evil Twin section is theoretical, not a completed experiment. Screenshot placeholders remain incomplete.
- A historical WHOIS address describes a registry contact, not a verified physical location of a host.
- Port 5050 alone does not identify malware. IRC commands, channel participation, and the trace context support the report's interpretation; they do not demonstrate every listed malware capability.
- The TLS report concerns an old TLS 1.2 capture. It is not a description of TLS 1.3.
- The displayed DH hex strings are abbreviated despite labels saying 256 bytes; they are not complete parameters.
- A 272-byte encrypted handshake record does not prove “additional handshake data.” Record overhead, padding, coalescing, and exact bytes must be examined. The usual TLS 1.2 Finished verify_data is 12 bytes; see [RFC 5246 section 7.4.9](https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.9).
- TLS 1.2 CBC uses an explicit per-record IV. The archival prose saying its IV comes from the master-secret key block is inaccurate; see [RFC 5246 section 6.2.3.2](https://datatracker.ietf.org/doc/html/rfc5246#section-6.2.3.2).
- An oversized captured packet alone does not establish loopback transport: offload and capture/reassembly behavior are alternative explanations.
- The local Snort document has blank rule blocks and evidence placeholders. It is excluded from the completed-report list.
