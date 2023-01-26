extern crate dirs;
extern crate anyhow;
extern crate argon2;

use data_encoding::BASE64_NOPAD;
use std::fs;
use dirs::home_dir;
use argon2::Config as ArgonConfig;

use ryp::crypto::{ gen_key, gen_salt, gen_nonce, encrypt_to_base64, decrypt_from_base64, decode_salt, verify_password };
use ryp::io::{ input, read_four_lines };
use ryp::error::MyError;

fn main() -> Result<(), MyError> {

    let home = home_dir().expect("Could not find $HOME directory.");
    let text_file = home.join("passwords.txt");
    let encrypted_file = home.join("passwords.ryp");

    // Case 1.
    //      Neither passwords.txt nor passwords.ryp can be found. Exit with error.
    if !text_file.exists() && !encrypted_file.exists() {
        eprintln!("*** Error: Could not find file $HOME/passwords.txt or $HOME/passwords.ryp");
        std::process::exit(1);
    }

    // Case 2.
    //      Only txt file exists, so encrypt it and create passwords.ryp.
    if text_file.exists() && !encrypted_file.exists() {
        let password: String = input("\nEnter password for encryption:")?.into();
        let password_confirmation: String = input("Confirm password:")?.into();
        if password != password_confirmation {
            eprintln!("*** Error: the passwords don't match.");
            std::process::exit(0);
        }
        // Generate salt for the password.
        let salt = gen_salt()?;
        let salt_string = format!("{}", BASE64_NOPAD.encode(&salt));

        // Hash the password.
        let config = ArgonConfig::default();
        let hashed_password = argon2::hash_encoded(password.as_bytes(), &salt, &config).unwrap();
        
        let key = gen_key(salt, password);

        // Read the contents of the file
        let txt_content = fs::read_to_string(home.join("passwords.txt"))
                                    .expect("*** Error reading passwords.txt file.");
        
        // Generate nonce for encrypting the text.
        let nonce = gen_nonce()?;
        let nonce_string = format!("{}", BASE64_NOPAD.encode(&nonce));

        // Encrypt
        let cipher_string = encrypt_to_base64(txt_content, key, nonce);

        // Write hashed_password, salt, nonce, and ciphertext to passwords.ryp.
        println!("  Writing passwords.ryp");
        let dest = format!("{}", home.join("passwords.ryp").display());
        let out_vec = vec![hashed_password, salt_string, nonce_string, cipher_string];
        let output = out_vec.join("\n");
        fs::write(&dest, output)?;

        // Remove the plain text file.
        println!("  Deleting passwords.txt.");
        fs::remove_file(home.join("passwords.txt"))?;

        // Exit
        std::process::exit(0);
    }

    // Case 3.
    //      passwords.ryp exists but passwords.txt does not. So we must open passwords.ryp by decrypting it into
    //      passwords.txt. We will not destroy passwords.ryp so that we can reuse the password salt. So once
    //      you set your password in the beginning it doesn't change.
    if !text_file.exists() && encrypted_file.exists() {
        
        let password: String = input("\nEnter password for decryption:")?.into();
        let filename = format!("{}", home.join("passwords.ryp").display());
        let (hash_string, salt_string, nonce_string, ciphertext_string) = read_four_lines(filename);
        
        // Verify the password is correct, so that we don't decrypt the file with the wrong password-generated key.
        //   We could do that, but it would be a bad user experience to expect a decrypted password file and then
        //   seeing binary garbage.
        verify_password(&hash_string, &password);

        // Decode the salt into a [u8; 32].
        let salt = decode_salt(salt_string);

        // Generate the key from the salt and password.
        let key = gen_key(salt, password);

        // Decode the nonce into a [u8; 24].
        let decoded_nonce = BASE64_NOPAD.decode(nonce_string.as_bytes()).unwrap();
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&decoded_nonce[..24]);

        let text = decrypt_from_base64(ciphertext_string, key, nonce)?;
        let dest = format!("{}", home.join("passwords.txt").display());
        fs::write(&dest, text)?;
        println!("  Decrypted content in $HOME/passwords.txt");
        std::process::exit(0);
    }

    // Case 4.
    //      Both passwords.txt and passwords.ryp can be found. It means we just opened passwords.ryp for editing
    //      and we can reuses the password salt. We need the password to be input
    //      by the user again so that we can regenerate the key.
    if text_file.exists() && encrypted_file.exists() {
        // Make sure the password is the same as the original password before encrypting again.
        println!("WARNING: The original encrypted file will be overwritten!");
        println!("  Make sure passwords.txt is what you want to encrypt.");
        let password: String = input("\nEnter password for encryption:")?.into();
        let filename = format!("{}", home.join("passwords.ryp").display());
        let (hash_string, salt_string, _nonce_string, _ciphertext_string) = read_four_lines(filename);
        
        // Verify the password is correct, so that we don't decrypt the file with the wrong password-generated key.
        //   We could do that, but it would be a bad user experience to expect a decrypted password file and then
        //   seeing binary garbage.
        verify_password(&hash_string, &password);
        
        // Decode the salt into a [u8; 32].
        let salt = decode_salt(salt_string.clone());

        // Generate the key from the salt and password.
        let key = gen_key(salt, password);
        
        // Read the contents of the file
        let txt_content = fs::read_to_string(home.join("passwords.txt"))
                                    .expect("*** Error while reading passwords.txt file.");
        
        // Generate nonce for encrypting the text.
        let nonce = gen_nonce()?;
        let nonce_string = format!("{}", BASE64_NOPAD.encode(&nonce));
        
        // Encrypt content.
        let cipher_string = encrypt_to_base64(txt_content, key, nonce); 

        // Write hashed_password, salt, nonce, and ciphertext to passwords.ryp.
        let dest = format!("{}", home.join("passwords.ryp").display());
        let out_vec = vec![hash_string, salt_string, nonce_string, cipher_string];
        let output = out_vec.join("\n");
        fs::write(&dest, output)?;
        println!("  Encrypted passwords.txt overwrote passwords.ryp.");

        // Remove the plain text file.
        fs::remove_file(home.join("passwords.txt"))?;
        println!("  Deleted passwords.txt.");
        
        std::process::exit(0);
    }

    Ok(())
}
