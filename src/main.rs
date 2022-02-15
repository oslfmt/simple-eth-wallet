mod login;
mod crypto;
mod utils;
mod db;

use std::io::Write;
use std::fs::OpenOptions;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use hex;
use rocksdb::{DB, Options};

use crate::login::{create_map_from_file};
use crate::utils::read_user_input;
use crate::db::*;
use crate::crypto::*;

#[derive(Decode, Encode, PartialEq, Debug)]
struct UserData {
    password_hash: [u8; 32],
    // TODO: encrypt the secret key
    secret_key: [u8; 32],
    public_key: Vec<u8>,
}

fn main() {
    println!("{}", "Starting Rwallet1.0, a simple ETH wallet...");

    // open the database containing login and keypair info
    let db = open_db("db");

    println!("{}", "1) Login");
    println!("{}", "2) Signup");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            run_user_login(db);
        },
        2 => {
            run_user_signup(db);
        },
        _ => println!("{}", "Invalid option"),
    }
}

/// Handles user login
fn run_user_login(db: DB) {
    println!("{}", "Enter Username: ");
    let username = read_user_input();
    println!("{}", "Enter Password: ");
    let password = read_user_input();
    let password_hash = keccak256(password.as_bytes());

    // check that the user exists
    match db.get(&username) {
        Ok(Some(d)) => {
            // deserialize data
            let decoded_data: UserData = UserData::from_ssz_bytes(&d).unwrap();
            if password_hash == decoded_data.password_hash {
                println!("{}", "Successfully logged in");

                // the main functionality of the wallet occurs here in a loop
                run_wallet_actions(decoded_data.secret_key, decoded_data.public_key);
            } else {
                println!("{}", "Invalid password");
            }
        },
        Ok(None) => println!("{}", "No user account found. You can sign up."),
        Err(e) => println!("{}", e),
    };
}

/// Handles user signup
fn run_user_signup(db: DB) {
    // 1. get username and password from user
    // 2. search if user exists in db, if so, cannot use username. if not, then:
    // 3. generate a new keypair, and store (username, keypair) into db

    println!("{}", "Enter Username: ");
    let username = read_user_input();
    println!("{}", "Enter Password: ");
    let password = read_user_input();

    // if username exists, cannot use. Otherwise, generate new key pair and create new user!
    match db.get(&username) {
        Ok(Some(_v)) => println!("Username already taken"),
        Ok(None) => {
            let (secret_key, public_key) = generate_secp256k1_keypair();
            let raw_key = public_key.serialize_uncompressed();
            let address = generate_eth_address(&raw_key[1..]);
            println!("Your ETH address: 0x{}", hex::encode(address));

            // store in db
            let data = UserData {
                password_hash: keccak256(password.as_bytes()),
                secret_key: secret_key.serialize_secret(),
                public_key: raw_key.to_vec(),
            };

            let bytes = data.as_ssz_bytes();
            db.put(username, bytes);

            // user can now use wallet
            // run_wallet_actions(secret_key, raw_key);
        }
        Err(e) => println!("Database error: {}", e),
    }
}

/// Handle actions like querying balance and sending transactions after user has logged in or signed up
fn run_wallet_actions(secret_key: [u8; 32], public_key: Vec<u8>) {
    // not the biggest fan of this, maybe just store the address
    let mut address = String::from("0x");
    address.push_str(&hex::encode(generate_eth_address(&public_key[1..])));

    println!("Your ETH address: {}", address);

    loop {
        println!("{}", "1) View account balance");
        println!("{}", "2) Send a transaction");
        let option = read_user_input().parse::<u8>().unwrap();

        match option {
            1 => {
                let resp: String = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
                    .set("Content-Type", "application/json")
                    .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBalance",
                        "params": [address, "latest"]
                    })).unwrap()
                    .into_string().unwrap();
                println!("{}", resp);
            },
            2 => {
                // TODO: Allow user to make a transaction (will need secret key)
            }
            _ => println!("{}", "Invalid option"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cannot_create_duplicate_user() {

    }

    #[test]
    fn user_can_login_with_correct_password() {

    }

    #[test]
    fn user_cannot_login_with_wrong_password() {

    }
}
