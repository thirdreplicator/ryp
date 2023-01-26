use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use crate::error::PasswordInputError;
use rpassword::read_password;

pub fn input(prompt: &str) -> Result<String, PasswordInputError> {
    print!("{} ", prompt);
    io::stdout().flush().unwrap();
    let password = read_password().unwrap();
    //password = password[..password.len()-1].to_string();
    Ok(password)
}

pub fn read_four_lines(file_path: String) -> (String, String, String, String) {
    let file = File::open(file_path.as_str()).expect("Unable to open file");
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let first_line = lines
        .next()
        .expect("Unable to read first line")
        .expect("Unable to parse first line");
    let second_line = lines
        .next()
        .expect("Unable to read second line")
        .expect("Unable to parse second line");
    let third_line = lines
        .next()
        .expect("Unable to read third line")
        .expect("Unable to parse third line");
    let fourth_line = lines
        .next()
        .expect("Unable to read fourth line")
        .expect("Unable to parse fourth line");

    (first_line, second_line, third_line, fourth_line)
}
