Minimal CLI password manager in Rust. Single binary, single vault file (vault.pm).
AES-256-GCM encryption. Commands: start (interactive REPL with master password).
Key derived from master password + salt via iterated SHA-256 — never stored on disk.
Dependencies: aes-gcm, rand, base64, sha2.