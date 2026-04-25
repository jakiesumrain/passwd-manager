mod crypto;
mod error;
mod repl;
mod vault;

use std::process;

fn print_usage() {
    eprintln!("usage: passwd-manager <command>");
    eprintln!();
    eprintln!("commands:");
    eprintln!("  start    Enter interactive shell with master password");
    eprintln!("  help     Show this help message");
    eprintln!("  version  Show version information");
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
        "start" => repl::run(),
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
