# passwd-manager

Minimal, portable CLI password manager with AES-256-GCM encryption.

## Usage

Start the interactive shell:

```bash
passwd-manager start [<vault>] ["<description>"]
```

The master password is hidden as you type. On first run, you'll be prompted to create one.
You can optionally name the vault to work with multiple vaults (e.g. `start work`, `start personal`).
An optional quoted description can be attached to a vault, shown in `help` and `list-vault`:

```
$ passwd-manager start work "my work passwords"
Set master password: ········
pm> help
vault: work.pm (my work passwords)
commands:
  encrypt <place> <password>   Store a new encrypted password
  retrieve <place|#>           Retrieve by name or list number
  list                         List all stored places (numbered)
  remove <place|#>             Remove by name or list number
  change <place|#> <password>  Change by name or list number
  exit                         Exit
  help                         Show this help

Use a list number (from 'list') in place of a name —
e.g. 'retrieve 1' instead of 'retrieve example.com'.
pm> encrypt example.com my-password
ok
pm> encrypt another.com pass456
ok
pm> list
1. example.com
2. another.com
pm> retrieve 2
pass456
pm> change 1 new-password
ok
pm> remove 2
ok
pm> exit
```

Place names with spaces must be quoted:

```
pm> encrypt "my work account" pass123
pm> retrieve "my work account"
pass123
```

Work with multiple vaults (each has its own master password):

```
passwd-manager start work    # creates/opens work.pm
passwd-manager start personal  # creates/opens personal.pm
```

Other commands:

- `passwd-manager list-vault` — list all vaults (with descriptions) in the binary directory
- `passwd-manager remove <vault>` — delete a vault (asks for confirmation twice)
- `passwd-manager help` — print usage
- `passwd-manager version` — print version

```
$ passwd-manager list-vault
personal
work (my work passwords)

$ passwd-manager remove work
Are you sure you want to remove vault 'work'? (y/N): y
Are you really sure? This cannot be undone. (y/N): y
Vault 'work' removed.
```

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
