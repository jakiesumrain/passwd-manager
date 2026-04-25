# passwd-manager

Minimal, portable CLI password manager with AES-256-GCM encryption.

## Usage

```bash
passwd-manager start
```

The master password is hidden as you type. On first run, you'll be prompted to create one:

```
Set master password: ········
pm> encrypt example.com my-password
ok
pm> retrieve example.com
my-password
pm> list
example.com
pm> change example.com new-password
ok
pm> remove example.com
ok
pm> help
commands:
  encrypt <place> <password>   Store a new encrypted password
  retrieve <place>             Retrieve a stored password
  list                         List all stored places
  remove <place>               Remove a stored password
  change <place> <password>    Change a stored password
  exit                         Exit
  help                         Show this help
pm> exit
```

Place names with spaces must be quoted:

```
pm> encrypt "my work account" pass123
pm> retrieve "my work account"
pass123
```

Other commands:

- `passwd-manager help` — print usage
- `passwd-manager version` — print version

## Build

```bash
cargo build --release
```

Binary at `target/release/passwd-manager`.

## How it works

- The vault (`vault.pm`) is stored next to the binary
- A random 32-byte salt is stored in the vault file
- The AES-256-GCM key is derived from your master password + salt using iterated SHA-256 (10000 rounds)
- All entries are encrypted at rest — the key is **never** stored on disk
- On each `encrypt`/`change`/`remove`, the vault is re-encrypted and written back immediately

## Portability

Copy the binary anywhere — `vault.pm` is created next to it on first use.

## Dependencies

5 external crates: `aes-gcm`, `rand`, `base64`, `sha2`, `rpassword`.
Everything else uses the Rust standard library.
