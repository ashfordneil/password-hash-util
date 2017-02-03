extern crate pwhash;
use pwhash::bcrypt;
extern crate rpassword;

fn main() {
    let password = match rpassword::prompt_password_stdout("Please enter the password to hash: ") {
        Ok(password) => password,
        Err(error) => {
            println!("Error: {}", error);
            return;
        }
    };
    let hash = match bcrypt::hash(&password) {
        Ok(hash) => hash,
        Err(error) => {
            println!("Error: {}", error);
            return;
        }
    };
    let confirm = match rpassword::prompt_password_stdout("Please repeat the password: ") {
        Ok(confirm) => confirm,
        Err(error) => {
            println!("Error: {}", error);
            return;
        }
    };
    match bcrypt::verify(&confirm, &hash) {
        true => println!("{}", hash),
        false => println!("Passwords do not match."),
    }
}
