# Secure chat client

Implementing [Signal](https://signal.org/docs/specifications/doubleratchet/) double ratchet algorithm.

## Idea

Asymmetric key exchange + symmetric key message encryption is **insecure** because leaking one private key will destroy the entire sequence.

We want to be able to provide:
1) Forward secrecy (prevent adversary from seeing entire convo if they break one key)
2) Break-in recovery (A sends a single message with new keypair and adversary unable to decrypt again)

This works by **chaining** and updating the ratchet key pair (priv/pubkey) each time

## steps
- HKDF key derivation function
- AES-GCM = ctr mode + galois
  - both [integrity and confidentiality](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#aes-gcm)
	- galois multiplication to compute a tag from AD (authenticated data)
- passes the pubKey back and forth, keeps the ratchet key pair
- out of order messages (section 2.6)
	- compute the chain, only throw it away when receiver <-> sender changes
	- advance the chain that many messages, then when you receive you'll already have computed prev msg_keys and just move b

---

Project for [CS255](https://crypto.stanford.edu/~dabo/cs255/)
