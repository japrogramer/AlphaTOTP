# Alpha TOTP Generator

This project provides a Rust library and a command-line application for generating Time-based One-Time Passwords (TOTP) as defined by RFC 6238.  The generated TOTP tokens consist of 6 alphanumeric characters (A-Z, 2-7) by default, providing a human-readable and secure alternative to purely numeric tokens.

## Features

*   **TOTP Token Generation:** Generates TOTP tokens based on a secret key and the current time.
*   **Customizable Token Format:** Uses a custom alphanumeric character set (A-Z, 2-7) to generate tokens, enhancing readability.
*   **Command-Line Interface:**  The included binary allows you to generate TOTP tokens from the command line.
*   **Secret Key Generation:**  The library includes a function to generate random base32 encoded secret keys.
*   **Base32 Encoding/Decoding:**  Uses base32 encoding (RFC4648) for the secret key for compatibility with common TOTP authenticators.
*   **HMAC-SHA256:** Employs HMAC-SHA256 for robust hashing.
*   **Configurable Time Step:** Allows you to specify the time step (usually 30 seconds) for TOTP generation.
*   **Command-Line Secret:** Can accept the base32 encoded secret key via the command line.
*   **Default Secret Generation**: If no secret is provided via the command line, a new random secret key will be generated and displayed.

## Getting Started

### Prerequisites

*   Rust (stable version) and Cargo (Rust's package manager) installed. You can install Rust from [https://www.rust-lang.org/](https://www.rust-lang.org/).

### Installation

1.  Clone the repository:

    ```bash
    git clone <repository_url>
    cd  AlphaTOTP
    ```

2.  Build the project:

    ```bash
    cargo build
    ```

### Usage (Command-Line)

1.  **Generate a TOTP token using a secret:**

    ```bash
    cargo run --bin totp_example -- --secret YOUR_BASE32_SECRET
    ```

    Replace `YOUR_BASE32_SECRET` with your base32 encoded secret key.

2.  **Generate a TOTP token using a default generated secret:**

    If no secret is specified, the application will generate a new one for you.

    ```bash
    cargo run --bin totp_example --
    ```

    The output will show the generated secret and the TOTP token. The secret is for testing only, please do not rely on it for security.

### Usage (Library)

Add the `AlphaTOTP` library to your project's `Cargo.toml` file:

```toml
[dependencies]
AlphaTOTP = { path = "./path/to/AlphaTOTP" } # Replace with the actual path
