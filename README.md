# ClearCipher

ClearCipher is a hands-on, interactive CLI program (written in C) that demonstrates classic ciphers step-by-step, with verbose output intended to help de-mystify the logic behind encryption.

Currently implemented:
- Caesar Cipher
- Vigenère Cipher  
- Vernam Cipher (One-Time Pad)
- DES
Planned / stubbed:
- ChaCha20
- Salsa20
- AES
- BLAKE3
- HMAC

---

## Goals

- Provide a **learning-focused** implementation of ciphers (not production cryptography).
- Show *how* and *why* each character changes during encryption/decryption.
- Keep the project simple to build and run (just `gcc` + `make`).

---

## Disclaimer (Read this first)

This project is for **educational purposes**. The ciphers implemented here are **not secure** for protecting real data. If you need real-world cryptography, use well-reviewed libraries (e.g., libsodium, OpenSSL) and modern authenticated encryption schemes.


AES is based on https://csrc.nist.gov/pubs/fips/198-1/final
HMAC is based on https://csrc.nist.gov/pubs/fips/198-1/final

---

## Build & Run

### Requirements
- `gcc`
- `make`

### Build
```bash
make build
```

The binary is created at:
- `bin/binary`

### Run
```bash
./bin/binary -h
```

Or use the convenience target:
```bash
make run
```

---

## Usage

### Help
```bash
./bin/binary -h
```

### List available ciphers
```bash
./bin/binary -l
```

### Try a cipher (interactive)
```bash
./bin/binary -s caesar
./bin/binary -s vigenere
./bin/binary -s vernam   # currently a stub
```

> Note: the program is interactive: it will prompt for text, key/shift, and whether to encrypt/decrypt.

---

## What you’ll see (example)

Both Caesar and Vigenère implementations print verbose “character mapping” output so you can follow the math/logic (e.g., showing shift amounts and modular arithmetic).

---

## Project Structure

- `src/`
  - `main.c` — CLI flags (`-h`, `-l`, `-s <cipher>`)
  - `cipher_parser.c` — routes `-s` arguments to a cipher module
  - `caesar.c` — Caesar cipher implementation + interactive prompts
  - `vigenere.c` — Vigenère cipher implementation + interactive prompts
  - `constants.c` — shared constants (alphabet)
- `include/` — headers
- `Makefile` — builds all `src/*.c` into `bin/binary`

---

## Roadmap / Ideas

- Add unit tests (and CI) to validate encryption/decryption correctness.
- Add more ciphers (ChaCha20, Salsa20, AES, etc.) with explanations.
- Improve UI

---

## Contributing

Issues and PRs are welcome—especially:
- new cipher modules
- clearer explanations / improved UX
- tests and build improvements

If you add a cipher, please:
1. Create `src/<cipher>.c` + `include/<cipher>.h`
2. Add it to the cipher list and parser
3. Keep output explanation-oriented (this repo’s main purpose)

---

## License

No license file is currently included. If you want others to use/modify the code easily, consider adding an OSI-approved license (e.g., MIT, Apache-2.0, GPL-3.0).
