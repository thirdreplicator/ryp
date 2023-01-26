use std::fmt;
use std::convert::From;
use std::error::Error;
use std::str::Utf8Error;
use ring::error::Unspecified;

#[derive(Debug)]
pub struct MyError {
    message: String,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct PasswordInputError {
    message: String,
}

impl Error for MyError {}

impl fmt::Display for MyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl From<Unspecified> for MyError {
    fn from(error: Unspecified) -> MyError {
        MyError {
            message: format!("Ring error: {:?}", error),
        }
    }
}

impl From<std::io::Error> for MyError {
    fn from(error: std::io::Error) -> MyError {
        MyError {
            message: format!("std io error: {:?}", error),
        }
    }
}

impl From<Utf8Error> for MyError {
    fn from(error: Utf8Error) -> MyError {
        MyError {
            message: format!("Utf8 error: {:?}", error),
        }
    }
}

impl From<PasswordInputError> for MyError {
    fn from(error: PasswordInputError) -> MyError {
        MyError {
            message: format!("input error while reading password from user: {:?}", error),
        }
    }
}

impl From<std::io::Error> for PasswordInputError {
    fn from(error: std::io::Error) -> PasswordInputError {
        PasswordInputError {
            message: format!("std io error: {:?}", error),
        }
    }
}