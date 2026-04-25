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

fn print_help(vault_display: &str, description: &str) {
    if description.is_empty() {
        println!("vault: {}", vault_display);
    } else {
        println!("vault: {} ({})", vault_display, description);
    }
    println!("commands:");
    println!("  encrypt <place> <password>   Store a new encrypted password");
    println!("  retrieve <place|#>           Retrieve by name or list number");
    println!("  list                         List all stored places (numbered)");
    println!("  remove <place|#>             Remove by name or list number");
    println!("  change <place|#> <password>  Change by name or list number");
    println!("  exit                         Exit");
    println!("  help                         Show this help");
    println!();
    println!("Use a list number (from 'list') in place of a name —");
    println!("e.g. 'retrieve 1' instead of 'retrieve example.com'.");
    println!("Use double quotes for arguments with spaces,");
    println!("e.g. encrypt \"example.com (work)\" \"my pass phrase\".");
}

fn resolve_place<'a>(entries: &'a [VaultEntry], arg: &'a str) -> &'a str {
    if let Ok(n) = arg.parse::<usize>()
        && n > 0
        && let Some(entry) = entries.get(n - 1)
    {
        return &entry.place;
    }
    arg
}

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

pub fn run(vault_name: Option<&str>, description: Option<&str>) -> Result<(), AppError> {
    let vault_path = vault::vault_path(vault_name);
    let vault_display = vault_name.map(|n| format!("{}.pm", n)).unwrap_or_else(|| "vault.pm".to_string());
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

    let (mut entries, salt, mut vault_desc) = vault::read_vault(&vault_path, &master_password)?;

    if is_new {
        if let Some(d) = description {
            vault_desc = d.to_string();
        }
        vault::write_vault(&vault_path, &master_password, &salt, &entries, &vault_desc)?;
    }

    let key = vault::derive_key(&master_password, &salt);

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
            "encrypt" => cmd_encrypt(&args, &mut entries, &key, &vault_path, &master_password, &salt, &vault_desc),
            "retrieve" => cmd_retrieve(&args, &entries, &key),
            "list" => cmd_list(&entries),
            "remove" => cmd_remove(&args, &mut entries, &vault_path, &master_password, &salt, &vault_desc),
            "change" => cmd_change(&args, &mut entries, &key, &vault_path, &master_password, &salt, &vault_desc),
            "help" => {
                print_help(&vault_display, &vault_desc);
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

fn cmd_encrypt(args: &[&str], entries: &mut Vec<VaultEntry>, key: &[u8; 32], vault_path: &Path, password: &str, salt: &[u8; 32], description: &str) -> Result<(), AppError> {
    if args.len() < 2 {
        return Err(AppError::VaultIo("usage: encrypt <place> <password>".to_string()));
    }
    let place = args[0];
    let pw = args[1];

    if place.parse::<usize>().is_ok() {
        eprintln!("warning: '{}' is a number — use 'retrieve {}' or 'list' to access by index", place, place);
    }

    if vault::find_entry(entries, place).is_some() {
        return Err(AppError::PlaceExists(place.to_string()));
    }

    let ciphertext = crypto::encrypt(key, pw)?;
    entries.push(VaultEntry {
        place: place.to_string(),
        ciphertext,
    });
    vault::write_vault(vault_path, password, salt, entries, description)?;
    println!("ok");
    Ok(())
}

fn cmd_retrieve(args: &[&str], entries: &[VaultEntry], key: &[u8; 32]) -> Result<(), AppError> {
    if args.is_empty() {
        return Err(AppError::VaultIo("usage: retrieve <place>".to_string()));
    }
    let place = resolve_place(entries, args[0]);

    let entry = vault::find_entry(entries, place)
        .ok_or_else(|| AppError::PlaceNotFound(place.to_string()))?;

    let pw = crypto::decrypt(key, &entry.ciphertext)?;
    println!("{}", pw);
    Ok(())
}

fn cmd_list(entries: &[VaultEntry]) -> Result<(), AppError> {
    for (i, entry) in entries.iter().enumerate() {
        println!("{}. {}", i + 1, entry.place);
    }
    Ok(())
}

fn cmd_remove(args: &[&str], entries: &mut Vec<VaultEntry>, vault_path: &Path, password: &str, salt: &[u8; 32], description: &str) -> Result<(), AppError> {
    if args.is_empty() {
        return Err(AppError::VaultIo("usage: remove <place>".to_string()));
    }
    let place = resolve_place(entries, args[0]).to_string();

    let before = entries.len();
    entries.retain(|e| e.place != place);
    if entries.len() == before {
        return Err(AppError::PlaceNotFound(place));
    }

    vault::write_vault(vault_path, password, salt, entries, description)?;
    println!("ok");
    Ok(())
}

fn cmd_change(args: &[&str], entries: &mut Vec<VaultEntry>, key: &[u8; 32], vault_path: &Path, password: &str, salt: &[u8; 32], description: &str) -> Result<(), AppError> {
    if args.len() < 2 {
        return Err(AppError::VaultIo("usage: change <place> <password>".to_string()));
    }
    let place = resolve_place(entries, args[0]).to_string();
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
    vault::write_vault(vault_path, password, salt, entries, description)?;
    println!("ok");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_empty() {
        assert!(tokenize("").is_empty());
        assert!(tokenize("   ").is_empty());
    }

    #[test]
    fn tokenize_simple() {
        assert_eq!(tokenize("encrypt example.com mypass"), vec!["encrypt", "example.com", "mypass"]);
    }

    #[test]
    fn tokenize_extra_spaces() {
        assert_eq!(tokenize("  encrypt   example.com   mypass  "), vec!["encrypt", "example.com", "mypass"]);
    }

    #[test]
    fn tokenize_quoted() {
        assert_eq!(tokenize(r#"encrypt "my account" mypass"#), vec!["encrypt", "my account", "mypass"]);
    }

    #[test]
    fn tokenize_quoted_at_end() {
        assert_eq!(tokenize(r#"retrieve "my place""#), vec!["retrieve", "my place"]);
    }

    #[test]
    fn tokenize_unterminated_quote() {
        assert_eq!(tokenize(r#"encrypt "hello world"#), vec!["encrypt", "hello world"]);
    }

    #[test]
    fn tokenize_single_word() {
        assert_eq!(tokenize("list"), vec!["list"]);
    }

    #[test]
    fn resolve_place_by_index() {
        let entries = vec![
            VaultEntry { place: "alpha.com".into(), ciphertext: vec![] },
            VaultEntry { place: "beta.com".into(), ciphertext: vec![] },
        ];
        assert_eq!(resolve_place(&entries, "1"), "alpha.com");
        assert_eq!(resolve_place(&entries, "2"), "beta.com");
    }

    #[test]
    fn resolve_place_by_name() {
        let entries = vec![
            VaultEntry { place: "alpha.com".into(), ciphertext: vec![] },
        ];
        assert_eq!(resolve_place(&entries, "alpha.com"), "alpha.com");
    }

    #[test]
    fn resolve_place_index_out_of_range() {
        let entries = vec![
            VaultEntry { place: "alpha.com".into(), ciphertext: vec![] },
        ];
        // Out-of-range index falls back to literal
        assert_eq!(resolve_place(&entries, "5"), "5");
        assert_eq!(resolve_place(&entries, "0"), "0");
    }

    #[test]
    fn resolve_place_non_numeric() {
        let entries = vec![
            VaultEntry { place: "alpha.com".into(), ciphertext: vec![] },
        ];
        assert_eq!(resolve_place(&entries, "not-a-number"), "not-a-number");
    }

    #[test]
    fn tokenize_password_with_spaces() {
        assert_eq!(
            tokenize(r#"encrypt example.com "my secret pass phrase""#),
            vec!["encrypt", "example.com", "my secret pass phrase"]
        );
    }

    #[test]
    fn tokenize_place_and_password_both_quoted() {
        assert_eq!(
            tokenize(r#"encrypt "my site (work)" "my pass""#),
            vec!["encrypt", "my site (work)", "my pass"]
        );
    }

    #[test]
    fn resolve_place_empty_entries() {
        assert_eq!(resolve_place(&[], "1"), "1");
    }
}
