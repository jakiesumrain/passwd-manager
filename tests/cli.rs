use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};

/// Locate the compiled binary relative to the test runner.
fn binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    // Test binary:  target/debug/deps/passwd_manager-<hash>.exe
    // Main binary:  target/debug/passwd-manager.exe
    path.pop(); // deps (or debug if run with --bin)
    if path.file_name().unwrap_or_default() == "deps" {
        path.pop(); // debug
    }
    path.push("passwd-manager.exe");
    path
}

fn binary_dir() -> PathBuf {
    let bin = binary_path();
    bin.parent().unwrap().to_path_buf()
}

fn run(args: &[&str]) -> (String, String, bool) {
    let output = Command::new(binary_path())
        .args(args)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

/// Write a minimal v2-format vault file (header only, no real encrypted data).
fn write_dummy_vault(path: &PathBuf, desc: &str) {
    let desc_bytes = desc.as_bytes();
    let mut data = Vec::new();
    data.extend_from_slice(b"PMv2");
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&(desc_bytes.len() as u16).to_le_bytes());
    data.extend_from_slice(desc_bytes);
    fs::write(path, &data).unwrap();
}

// ---------------------------------------------------------------------------
// help / version / error handling
// ---------------------------------------------------------------------------

#[test]
fn test_help() {
    let (stdout, stderr, ok) = run(&["help"]);
    assert!(ok);
    // print_usage writes to stderr (eprintln!)
    assert!(stderr.contains("start"));
    assert!(stderr.contains("list-vault"));
    assert!(stderr.contains("remove"));
    assert!(stdout.is_empty());
}

#[test]
fn test_version() {
    let (stdout, stderr, ok) = run(&["version"]);
    assert!(ok);
    assert!(!stdout.is_empty());
    assert!(stderr.is_empty());
}

#[test]
fn test_no_args() {
    let (_stdout, stderr, ok) = run(&[]);
    assert!(!ok);
    assert!(stderr.contains("usage:"));
}

#[test]
fn test_unknown_command() {
    let (_stdout, stderr, ok) = run(&["bogus"]);
    assert!(!ok);
    assert!(stderr.contains("unknown command"));
}

// ---------------------------------------------------------------------------
// list-vault / remove
// ---------------------------------------------------------------------------

#[test]
fn test_list_vault_empty() {
    let (_stdout, stderr, ok) = run(&["list-vault"]);
    assert!(ok);
    assert!(stderr.is_empty());
}

#[test]
fn test_list_vault_with_files() {
    let dir = binary_dir();

    let v1 = dir.join("pm-integ-a.pm");
    let v2 = dir.join("pm-integ-b.pm");
    write_dummy_vault(&v1, "first vault");
    write_dummy_vault(&v2, "");

    let (stdout, stderr, ok) = run(&["list-vault"]);
    assert!(ok);
    assert!(stderr.is_empty());
    assert!(stdout.contains("pm-integ-a"));
    assert!(stdout.contains("first vault"));
    assert!(stdout.contains("pm-integ-b"));

    let _ = fs::remove_file(&v1);
    let _ = fs::remove_file(&v2);
}

#[test]
fn test_remove_non_existent() {
    let (_stdout, stderr, ok) = run(&["remove", "pm-integ-nonexistent"]);
    assert!(!ok);
    assert!(stderr.contains("not found"));
}

#[test]
fn test_remove_empty_arg() {
    let (_stdout, stderr, ok) = run(&["remove"]);
    assert!(!ok);
    assert!(stderr.contains("usage:"));
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> (String, String, bool) {
    let mut child = Command::new(binary_path())
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    use std::io::Write;
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    (stdout, stderr, output.status.success())
}

#[test]
fn test_remove_cancelled_first_prompt() {
    let vault = binary_dir().join("pm-integ-remove-me.pm");
    write_dummy_vault(&vault, "");
    assert!(vault.exists());

    let (stdout, _stderr, ok) = run_with_stdin(&["remove", "pm-integ-remove-me"], b"n\n");
    assert!(stdout.contains("cancelled"));
    assert!(ok);
    assert!(vault.exists());

    fs::remove_file(&vault).ok();
}

#[test]
fn test_remove_cancelled_second_prompt() {
    let vault = binary_dir().join("pm-integ-remove-me-2.pm");
    write_dummy_vault(&vault, "");
    assert!(vault.exists());

    let (stdout, _stderr, ok) = run_with_stdin(&["remove", "pm-integ-remove-me-2"], b"y\nn\n");
    assert!(stdout.contains("cancelled"));
    assert!(ok);
    assert!(vault.exists());

    fs::remove_file(&vault).ok();
}

#[test]
fn test_remove_confirmed() {
    let vault = binary_dir().join("pm-integ-remove-me-3.pm");
    write_dummy_vault(&vault, "");
    assert!(vault.exists());

    let (stdout, _stderr, ok) = run_with_stdin(&["remove", "pm-integ-remove-me-3"], b"y\ny\n");
    assert!(stdout.contains("removed"));
    assert!(ok);
    assert!(!vault.exists());
}
