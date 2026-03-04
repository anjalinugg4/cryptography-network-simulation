CS105 Assignment 4:
Authors: Anjali Nuggehali, Liam Hochman



========== SETUP ==========

All commands are run from the 'python/' directory inside the submission.

cd python
python3 -m venv venv
source venv/bin/activate
pip install cryptography

When done, deactivate venv with: 
deactivate


========== USAGE ==========

Generating keys:

1.  source venv/bin/activate
2.  python3 Gen.py
   This makes: alice_public.pem, alice_private.pem, bob_public.pem, bob_private.pem
   In a real situation these keys would have to be manually distributed (there is not
   a centralized computer that could store these for Alice and Bob).
       For local testing, all files stay in the same directory.


Running the System (3 different terminals, each with venv activated):

- Mode can be set as 'none', 'enc', 'mac', or 'encmac'

Terminal 1 (Bob):
- source venv/bin/activate
- python3 Bob.py <port> <mode>
    - ex: python3 Bob.py 9000 none

Terminal 2 (Mallory):
- source venv/bin/activate
- python3 Mallory.py <listen_port> <bob_host> <bob_port> <mode>
    - ex: python3 Mallory.py 8000 127.0.0.1 9000 none

Terminal 3 (Alice):
- source venv/bin/activate
- python3 Alice.py <mallory_host> <mallory_port> <mode>
    - ex: python3 Alice.py 127.0.0.1 8000 none

Experiment 1: No crypto
- Start Bob, Mallory, Alice with mode "none"
- Type messages in Alice. They appear in Mallory and can be forwarded to
Bob as plaintext.
- In Mallory: [f]orward, [m]odify (bit flip), [d]elete, or [r]eplay

Experiment 2: Encryption only
- Start all three with mode "enc".
- Alice sends RSA-wrapped AES key, then AES-CTR encrypted messages.
- Mallory needs to forward AES key for the symmetric encryption to work.
- Mallory sees ciphertext only. Bit flip goes undetected by Bob.

Experiment 3: MAC only
- Start all three with mode "mac".
- Alice sends RSA-wrapped MAC key, then message || HMAC-SHA256 tag.
- Mallory sees plaintext + tag; Bob detects any modification or forgery.
- Replay: Mallory's [r] resends a prior message. Bob cannot detect replay.

Experiment 4: Encryption thenMAC
- Start all three with mode "encmac".
- Alice sends RSA-wrapped shared key, then AES-CTR ciphertext || HMAC tag.
- Bob verifies the MAC before decrypting. both modification and replay are detectable
only if the replayed ciphertext and tag pair has already been seen (no counter).


========== RATIONALE ==========

Mode: none
  Plaintext message Alice -> Mallory -> Bob.  
  Mallory can read, modify, delete, or replay messages as MITM.
  No confidentiality or integrity protection.

Mode: enc
  1. Alice generates a 256-bit AES key.
  2. Alice encrypts the AES key with Bob's RSA-2048 public key (OAEP/SHA-256).
  3. Alice -> Mallory -> Bob: RSA_encrypt(Bob_pub, AES_key)
  4. Bob decrypts payload from 3 to recover the AES_key.
  5. For each message:
     Alice -> Mallory -> Bob: AES-CTR(AES_key, IV || ciphertext)
     IV is a fresh 16-byte random value for each message.

Mode: mac
  1. Alice generates a 256-bit MAC key.
  2. Alice encrypts the MAC key with Bob's RSA-2048 public key (OAEP/SHA-256).
  3. Alice -> Mallory -> Bob: RSA_encrypt(Bob_pub, MAC_key)
  4. Bob decrypts payload from 3 to recover the MAC_key.
  5. For each message:
     Alice -> Mallory -> Bob: plaintext || HMAC-SHA256(MAC_key, plaintext)
     Bob verifies the tag, prints "Tampering detected!" upon failure.

Mode: encmac
  1. Alice generates a 256-bit shared key (used for both AES and HMAC).
  2. Alice encrypts the shared key with Bob's RSA-2048 public key (OAEP/SHA-256).
  3. Alice -> Mallory -> Bob: RSA_encrypt(Bob_pub, shared_key)
  4. Bob decrypts payload from 3 to recover shared_key.
  5. For each message:
     ciphertext = AES-CTR(shared_key, IV || ciphertext)
     tag = HMAC-SHA256(shared_key, ciphertext)
     Alice -> Mallory -> Bob: ciphertext || tag
     Bob verifies tag first, then decrypts (Enc-then-MAC ordering).

--------------------------------

RSA-2048 with OAEP/SHA-256:
  Standard choice for asymmetric key encapsulation. 2048-bit keys provide
  ~112 bits of security, sufficient for a course project. OAEP is semantically
  secure under CPA; avoids the malleability of PKCS#1 v1.5.

AES-256 in CTR mode:
  CTR turns AES into a stream cipher, is parallelizable, and requires no
  padding. 256-bit key provides a large security margin. A fresh random IV
  is generated per message to ensure ciphertexts are non-repeating.

HMAC-SHA256:
  Industry-standard MAC. SHA-256 is collision-resistant and widely supported.
  32-byte (256-bit) tags are appended to messages and verified by Bob.

--------------------------------

- Single shared key for encmac: the same 256-bit key is used as both the AES
  key and the MAC key. Ideally two independent keys would be derived (e.g.,
  via HKDF), but a single key is acceptable here since AES-CTR and HMAC are
  domain-separated in practice.

- No sequence numbers or nonces: replay attacks are possible in mac and encmac modes 
because there is no per-message counter. A real system would include
  a sequence number inside the authenticated payload.

- Mallory modify action: flips the first bit of the raw bytes. In enc mode
  this corrupts the ciphertext undetectably (CTR mode is malleable). In mac and 
  encmac modes Bob detects the change via HMAC verification failure.

- Key distribution: Gen.py places all key files in the current directory.
  For the demo, Alice, Bob, and Mallory all run from the same directory.
  In a real deployment, private keys would never be co-located.

- Configuration is passed as a CLI argument and is not hardcoded, satisfying
  requirement 2. All hostnames and ports are also CLI arguments to satisfy requirement 1.


========== LIBRARY USED ==========

cryptography (PyPI):
- cryptography.hazmat.primitives.asymmetric.rsa: RSA key generation in Gen.py
- cryptography.hazmat.primitives.asymmetric.padding: OAEP padding for RSA
- cryptography.hazmat.primitives.ciphers: AES-CTR encryption/decryption
- cryptography.hazmat.primitives.hmac: HMAC-SHA256 computation and verification
- cryptography.hazmat.primitives.serialization: PEM key serialization


========== KNOWN PROBLEMS ==========

- Mallory does not explicitly forward the key-exchange packet separately from
messages. This works in practice because Mallory transparently forwards
all bytes she receives, but it means Mallory cannot effectively intercept
or display the key exchange step herself.

- Single key for encmac: the same key is used as both the AES key and the MAC key. 
Ideally two independent keys would be derived (e.g., via HKDF), but a single key works
here since AES-CTR and HMAC affect the key with different enough mathematical operations.
Having separate keys for enc and mac would be better, because it adheres to the
principle of least privilege.

- No replay protection: there are no sequence numbers or timestamps for the 
messages in our implementation. In mac mode, a replayed message has a valid HMAC tag
(the key hasn't changed and the message hasn't changed), so Bob accepts it as a 
legitimate message with no warning. In encmac mode the same is true, because the replayed
ciphertext and tag pair is still valid, so Bob verifies the MAC, decrypts, 
and then displays the old message as if it were new. Mallory can replay stale or 
duplicate messages to Bob in both modes without detection. Having encrypted timestamps
that Alice and Bob check against 2 synched clocks would be one way to protect against
replay attacks.

- recv(1024) buffer: very long messages in mac/encmac mode may
be split across multiple recv calls. This is not an issue for our scope
since our demo messages are relatively short.

- Bob only handles one connection per run. To restart a demo, all three
programs must be restarted.