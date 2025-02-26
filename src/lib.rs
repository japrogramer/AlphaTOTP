use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use base32;
use rand::Rng;

use std::time::Duration;
use tokio::time::sleep;



// Define a custom character set that includes both letters and numbers.
const CHARACTERS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; //RFC4648 base32 without padding
const TOKEN_LENGTH: usize = 6; // Max token length

/// Generates a TOTP token.
///
/// # Arguments
///
/// * `secret` - The secret key used to generate the TOTP. Should be base32 encoded.
/// * `time_step` - The time step in seconds (usually 30).
///
/// # Returns
///
/// A `Result` containing the TOTP token as a `String` if successful, or an error message as a `String` if not.
pub async fn generate_totp(secret: &str, time_step: u64, blocking: bool) -> Result<String, String> {
    // Decode the secret from base32.
    let secret_bytes = match base32::decode(base32::Alphabet::Rfc4648 { padding: false }, secret) {
        Some(bytes) => bytes,
        None => return Err("Invalid base32 secret".to_string()),
    };

    // Get the current timestamp.
    let now = Utc::now();
    let timestamp = now.timestamp();

    // Calculate the number of time steps since the Unix epoch.
    let counter = (timestamp / time_step as i64) as u64;

    //Calculate the time remaining for the current time step
    let time_remaining = (time_step as i64) - (timestamp % (time_step as i64));

    // Wait until the next time step if blocking is enabled
    if blocking {
        sleep(Duration::from_secs(time_remaining as u64)).await;
    }

    // Increment the counter for the *next* time step
    let counter = counter+1;

    // Generate the HMAC-SHA256 hash.
    let hash = generate_hmac_sha256(&secret_bytes, counter);

    // Truncate the hash to get the dynamic offset.
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;

    // Extract 4 bytes from the hash based on the offset.
    let binary_code = ((hash[offset] as u32 & 0x7f) << 24)
        | ((hash[offset + 1] as u32 & 0xff) << 16)
        | ((hash[offset + 2] as u32 & 0xff) << 8)
        | (hash[offset + 3] as u32 & 0xff);


    // Calculate the TOTP value using modulo operation.
    let totp_value = binary_code % (CHARACTERS.len() as u32).pow(TOKEN_LENGTH as u32);

    // Convert the TOTP value to a string of alphanumeric characters.
    let token = format_token(totp_value, TOKEN_LENGTH);

    Ok(token)
}

/// Generates an HMAC-SHA256 hash.
///
/// # Arguments
///
/// * `key` - The secret key.
/// * `counter` - The counter value.
///
/// # Returns
///
/// The HMAC-SHA256 hash as a `Vec<u8>`.
fn generate_hmac_sha256(key: &[u8], counter: u64) -> Vec<u8> {
    let mut hmac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");

    // Convert the counter to big-endian bytes.
    let counter_bytes = counter.to_be_bytes();

    hmac.update(&counter_bytes);
    let result = hmac.finalize();

    result.into_bytes().to_vec()
}


/// Formats the TOTP value into a string using the custom character set.
///
/// # Arguments
///
/// * `value` - The TOTP value.
/// * `length` - The desired length of the token.
///
/// # Returns
///
/// The formatted TOTP token as a `String`.
fn format_token(value: u32, length: usize) -> String {
    let mut token = String::new();
    let base = CHARACTERS.len() as u32;
    let mut temp_value = value;

    for _ in 0..length {
        let index = (temp_value % base) as usize;
        token.push(CHARACTERS[index] as char);
        temp_value /= base;
    }

    token.chars().rev().collect()
}



/// Generates a random base32 secret.
///
/// # Arguments
///
/// * `length` - The desired length of the secret in bytes.
///
/// # Returns
///
/// The random base32 secret as a `String`.
pub fn generate_secret(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = vec![0u8; length];
    rng.fill(&mut bytes[..]);

    base32::encode(base32::Alphabet::Rfc4648 { padding: false }, &bytes)
}


#[cfg(test)]
mod tests {
    use super::*;
    use tokio::test;


    #[test]
    async fn test_generate_totp() {
        // Test with a known secret and time step.
        // Note: This is just an example, you'll need to update the expected value if the time has changed.
        let secret = "JBSWY3DPEHPK3PXP"; // Example base32 secret
        let time_step = 30; // Standard time step
        let blocking = false;

        match generate_totp(secret, time_step, blocking).await {
            Ok(token) => {
                println!("Generated token: {}", token);
                assert_eq!(token.len(), 6);
                for c in token.chars() {
                    assert!(CHARACTERS.contains(&(c as u8)));
                }
            }
            Err(err) => panic!("Error generating TOTP: {}", err),
        }
    }

    #[test]
    async fn test_generate_secret() {
        let secret = generate_secret(10);
        println!("Generated secret: {}", secret);
        assert!(secret.len() > 0);
    }

    #[test]
    async fn test_invalid_secret() {
        let invalid_secret = "ThisIsNotBase32";
        let time_step = 30;
        let blocking = false;

        let result = generate_totp(invalid_secret, time_step, blocking).await;
        assert!(result.is_err());
        assert_eq!(result.err(), Some("Invalid base32 secret".to_string()));
    }

    #[test]
    async fn test_format_token() {
        let value = 12345;
        let length = 6;
        let token = format_token(value, length);
        println!("Formatted token: {}", token);
        assert_eq!(token.len(), 6);
    }
}
