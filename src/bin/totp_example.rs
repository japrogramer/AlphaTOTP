// src/bin/totp_example.rs
use AlphaTOTP::{generate_totp, generate_secret}; // Import from your library
use std::{thread, time}; // Import thread and time modules
use clap::{Arg, App};

#[tokio::main]
async fn main() {
    // Generate a default secret if one isn't provided
    let default_secret = generate_secret(20);
    let blocking = true;

    let matches = App::new("TOTP Example")
        .version("1.0")
        .author("Your Name")
        .about("Generates TOTP tokens")
        .arg(Arg::with_name("secret")
            .short("s")
            .long("secret")
            .value_name("SECRET")
            .help("Base32 encoded secret key (defaults to a generated secret)")
            .takes_value(true)
            .default_value(&default_secret)) // Use default_secret as the default value
        .get_matches();

    // Extract the secret from the command-line arguments
    let secret = matches.value_of("secret").unwrap();

    println!("Using Secret: {}", secret);

    let duration = time::Duration::from_secs(1);

    for i in 0..31 {
        match generate_totp(&secret, 30, blocking).await {
            Ok(token) => println!("{}: TOTP Token: {}", i, token),
            Err(err) => eprintln!("{}: Error generating TOTP: {}", i, err),
        }

        thread::sleep(duration); // Use the pre-defined duration
    }
}
