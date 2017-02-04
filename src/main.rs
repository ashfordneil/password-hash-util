extern crate pwhash;
use pwhash::{bcrypt, bsdi_crypt, md5_crypt, sha1_crypt, sha256_crypt, sha512_crypt, unix_crypt};
use pwhash::error::Error;

extern crate rpassword;

extern crate clap;
use clap::{Arg, App};

fn check_hash(hash: String) -> Result<(), String> {
    match hash.as_ref() {
        "bcrypt" | "bsdi_crypt" | "md5_crypt" | "sha1_crypt" | "sha256_crypt" |
        "sha512_crypt" | "unix_crypt" => Ok(()),
        _ => Err(format!("{} is not a known hash function.", hash)),
    }
}

/// Takes a hash function and a matching verify function, and executes the main body of the
/// program. Asks the user to enter and confirm their password, then returns a hash.
fn execute(hash_function: Box<Fn(&str) -> Result<String, Error>>,
           verify: Box<Fn(&str, &str) -> bool>)
           -> Result<String, String> {
    let password = match rpassword::prompt_password_stdout("Please enter the password to hash: ") {
        Ok(password) => password,
        Err(error) => return Err(format!("{}", error)),
    };
    let hash = match hash_function(&password) {
        Ok(hash) => hash,
        Err(error) => return Err(format!("{}", error)),
    };
    let confirm = match rpassword::prompt_password_stdout("Please repeat the password: ") {
        Ok(confirm) => confirm,
        Err(error) => return Err(format!("{}", error)),
    };
    match verify(&confirm, &hash) {
        true => Ok(hash),
        false => Err(format!("Passwords do not match.")),
    }
}

fn main() {
    let arguments = App::new("Password Hash Utility")
        .version("0.1.0")
        .author("Neil Ashford <ashfordneil0@gmail.com>")
        .about("Hashes passwords on demand.")
        .arg(Arg::with_name("hash_type")
            .help("Sets the hashing algorithm to use")
            .validator(check_hash)
            .takes_value(true))
        .get_matches();
    let (hash, verify): (Box<Fn(&str) -> Result<String, Error>>, Box<Fn(&str, &str) -> bool>) =
        match arguments.value_of("hash_type") {
            Some("bcrypt") | None => (Box::new(bcrypt::hash), Box::new(bcrypt::verify)),
            Some("bsdi_crypt") => (Box::new(bsdi_crypt::hash), Box::new(bsdi_crypt::verify)),
            Some("md5_crypt") => (Box::new(md5_crypt::hash), Box::new(md5_crypt::verify)),
            Some("sha1_crypt") => (Box::new(sha1_crypt::hash), Box::new(sha1_crypt::verify)),
            Some("sha256_crypt") => (Box::new(sha256_crypt::hash), Box::new(sha256_crypt::verify)),
            Some("sha512_crypt") => (Box::new(sha512_crypt::hash), Box::new(sha512_crypt::verify)),
            Some("unix_crypt") => (Box::new(unix_crypt::hash), Box::new(unix_crypt::verify)),
            _ => unreachable!(),
        };

    match execute(hash, verify) {
        Ok(hash) => println!("{}", hash),
        Err(error) => println!("Error: {}", error),
    };
}
