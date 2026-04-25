use std::io::{self, Write};
use std::path::Path;

use crate::crypto;
use crate::error::AppError;
use crate::vault;
use crate::vault::VaultEntry;

fn prompt_password(msg: &str) -> String {
    print!("{}", msg);
    let _ = io::stdout().flush();
    rpassword::read_password().unwrap_or_default()
}

fn print_help() {
    println!("commands:");
    println!("  encrypt <place> <password>   Store a new encrypted password");
    println!("  retrieve <place>             Retrieve a stored password");
    println!("  list                         List all stored places");
    println!("  remove <place>               Remove a stored password");
    println!("  change <place> <password>    Change a stored password");
    println!("  exit                         Exit");
    println!("  help                         Show this help");
}

// Quote-aware tokenizer: "foo bar" is a single argument, foo bar is two.
fn tokenize(line: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut chars = line.chars().peekable();
    while chars.peek().is_some() {
        while chars.peek().is_some_and(|c| c.is_ascii_whitespace()) {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        if chars.peek() == Some(&'"') {
            chars.next();
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c == '"' {
                    chars.next();
                    break;
                }
                s.push(c);
                chars.next();
            }
            args.push(s);
        } else {
            let mut s = String::new();
            while let Some(&c) = chars.peek() {
                if c.is_ascii_whitespace() {
                    break;
                }
                s.push(c);
                chars.next();
            }
            args.push(s);
        }
    }
    args
}

pub fn run() -> Result<(), AppError> {
    let vault_path = vault::vault_path();
    let is_new = !vault_path.exists();
    let pw_prompt = if is_new {
        "Set master password: "
    } else {
        "Master password: "
    };

    let master_password = prompt_password(pw_prompt);
    if master_password.is_empty() {
        return Err(AppError::VaultIo("password cannot be empty".to_string()));
    }

    let (mut entries, salt) = vault::read_vault(&vault_path, &master_password)?;
    let key = vault::derive_key(&master_password, &salt);

    if is_new {
        vault::write_vault(&vault_path, &master_password, &salt, &entries)?;
    }

    let mut input = String::new();
    loop {
        print!("pm> ");
        let _ = io::stdout().flush();
        input.clear();

        match io::stdin().read_line(&mut input) {
            Ok(0) => break,
            Ok(_) => {}
            Err(_) => break,
        }

        let line = input.trim();
        if line.is_empty() {
            continue;
        }

        let parts = tokenize(line);
        if parts.is_empty() {
            continue;
        }

        let cmd = &parts[0];
        let args: Vec<&str> = parts[1..].iter().map(|s| s.as_str()).collect();

        let result = match cmd.as_str() {
            "exit" | "quit" => break,
            "encrypt" => cmd_encrypt(&args, &mut entries, &key, &vault_path, &master_password, &salt),
            "retrieve" => cmd_retrieve(&args, &entries, &key),
            "list" => cmd_list(&entries),
            "remove" => cmd_remove(&args, &mut entries, &vault_path, &master_password, &salt),
            "change" => cmd_change(&args, &mut entries, &key, &vault_path, &master_password, &salt),
            "help" => {
                print_help();
                Ok(())
            }
            _ => {
                eprintln!("unknown command: {}", cmd);
                Ok(())
            }
        };

        if let Err(e) = result {
            eprintln!("error: {}", e);
        }
    }

    println!();
    Ok(())
}

fn cmd_encrypt(args: &[&str], entries: &mut Vec<VaultEntry>, key: &[u8; 32], vault_path: &Path, password: &str, salt: &[u8; 32]) -> Result<(), AppError> {
    if args.len() < 2 {
        return Err(AppError::VaultIo("usage: encrypt <place> <password>".to_string()));
    }
    let place = args[0];
    let pw = args[1];

    if vault::find_entry(entries, place).is_some() {
        return Err(AppError::PlaceExists(place.to_string()));
    }

    let ciphertext = crypto::encrypt(key, pw)?;
    entries.push(VaultEntry {
        place: place.to_string(),
        ciphertext,
    });
    vault::write_vault(vault_path, password, salt, entries)?;
    println!("ok");
    Ok(())
}

fn cmd_retrieve(args: &[&str], entries: &[VaultEntry], key: &[u8; 32]) -> Result<(), AppError> {
    if args.is_empty() {
        return Err(AppError::VaultIo("usage: retrieve <place>".to_string()));
    }
    let place = args[0];

    let entry = vault::find_entry(entries, place)
        .ok_or_else(|| AppError::PlaceNotFound(place.to_string()))?;

    let pw = crypto::decrypt(key, &entry.ciphertext)?;
    println!("{}", pw);
    Ok(())
}

fn cmd_list(entries: &[VaultEntry]) -> Result<(), AppError> {
    for entry in entries {
        println!("{}", entry.place);
    }
    Ok(())
}

fn cmd_remove(args: &[&str], entries: &mut Vec<VaultEntry>, vault_path: &Path, password: &str, salt: &[u8; 32]) -> Result<(), AppError> {
    if args.is_empty() {
        return Err(AppError::VaultIo("usage: remove <place>".to_string()));
    }
    let place = args[0];

    let before = entries.len();
    entries.retain(|e| e.place != place);
    if entries.len() == before {
        return Err(AppError::PlaceNotFound(place.to_string()));
    }

    vault::write_vault(vault_path, password, salt, entries)?;
    println!("ok");
    Ok(())
}

fn cmd_change(args: &[&str], entries: &mut Vec<VaultEntry>, key: &[u8; 32], vault_path: &Path, password: &str, salt: &[u8; 32]) -> Result<(), AppError> {
    if args.len() < 2 {
        return Err(AppError::VaultIo("usage: change <place> <password>".to_string()));
    }
    let place = args[0];
    let pw = args[1];

    let before = entries.len();
    entries.retain(|e| e.place != place);
    if entries.len() == before {
        return Err(AppError::PlaceNotFound(place.to_string()));
    }

    let ciphertext = crypto::encrypt(key, pw)?;
    entries.push(VaultEntry {
        place: place.to_string(),
        ciphertext,
    });
    vault::write_vault(vault_path, password, salt, entries)?;
    println!("ok");
    Ok(())
}
