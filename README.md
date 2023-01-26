# ryp
A command line utility `ryp` to encrypt and decrypt small files. Currently it only decrypts one file: ~/passwords.txt but I would like to generalize it to handle any file on the operating system. Written in Rust.

## Overview
This is a command line utility that encrypts and decrypts $HOME/passwords.txt to and from $HOME/passwords.ryp. I use it for encrypting my personal password file.

This is my first public Rust project, so I would love to get any feedback on my code especially about error handling, testing, and security.

If you see any security flaws in the code, or if you're able to decrypt a file that was encrypted using this utility, please let me know. I'm using the rust-argon2 crate for password verification and chacha20poly1305 for encryption. A password salt is generated once upon the first encryption event so that the same password can be used over and over again. A different nonce is used for every re-encryption event, because we're assuming that the file is being edited.

## Contact

I would love to know if you're using it. Feel free to email me here: thirdreplicator at gmail.

Thank you!

-- David 
