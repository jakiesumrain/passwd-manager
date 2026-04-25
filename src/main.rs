mod crypto;
mod error;
mod repl;
mod vault;

use std::fs;
use std::io::{self, Write};
use std::process;

fn print_usage() {
    eprintln!("usage: passwd-manager <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  start [<vault>] [\"description\"]  Enter interactive shell (default vault: vault.pm)");
    eprintln!("  list-vault                      List all vaults in the binary directory");
    eprintln!("  remove <vault>                  Delete a vault with confirmation");
    eprintln!("  help                            Show this help message");
    eprintln!("  version                         Show version information");
}

fn print_version() {
    println!("passwd-manager {}", env!("CARGO_PKG_VERSION"));
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_usage();
        process::exit(1);
    }

    let command = &args[1];

    let result = match command.as_str() {
        "start" => repl::run(args.get(2).map(|s| s.as_str()), args.get(3).map(|s| s.as_str())),
        "remove" => {
            fn confirm(prompt: &str) -> bool {
                print!("{}", prompt);
                io::stdout().flush().ok();
                let mut input = String::new();
                io::stdin().read_line(&mut input).ok();
                input.trim().to_lowercase() == "y"
            }

            let vault_name = args.get(2).map(|s| s.as_str()).unwrap_or("");
            if vault_name.is_empty() {
                eprintln!("passwd-manager: error: usage: passwd-manager remove <vault>");
                process::exit(1);
            }
            let vault_path = vault::vault_path(Some(vault_name));
            if !vault_path.exists() {
                eprintln!("passwd-manager: error: vault '{}' not found", vault_name);
                process::exit(1);
            }

            let prompts = [
                format!("Are you sure you want to remove vault '{}'? (y/N): ", vault_name),
                "Are you really sure? This cannot be undone. (y/N): ".to_string(),
            ];
            if !prompts.iter().all(|p| confirm(p)) {
                println!("cancelled");
                Ok(())
            } else {
                fs::remove_file(&vault_path).unwrap_or_else(|e| {
                    eprintln!("passwd-manager: error: cannot remove vault: {}", e);
                    process::exit(2);
                });
                println!("Vault '{}' removed.", vault_name);
                Ok(())
            }
        }
        "list-vault" => {
            let vaults = vault::list_vaults();
            if vaults.is_empty() {
                println!("no vaults found");
            } else {
                for (name, desc) in &vaults {
                    if desc.is_empty() {
                        println!("{}", name);
                    } else {
                        println!("{} ({})", name, desc);
                    }
                }
            }
            Ok(())
        }
        "help" => {
            print_usage();
            Ok(())
        }
        "version" => {
            print_version();
            Ok(())
        }
        _ => {
            eprintln!("passwd-manager: error: unknown command '{}'", command);
            eprintln!("Run 'passwd-manager help' for usage.");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("{}", e);
        process::exit(e.exit_code());
    }
}
