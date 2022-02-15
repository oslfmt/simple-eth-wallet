mod login;
mod crypto;
mod utils;
mod db;

use std::io::Write;
use std::fs::OpenOptions;

use serde::{Serialize, Deserialize};
use hex;

use crate::login::{create_map_from_file};
use crate::utils::read_user_input;
use crate::db::*;
use crate::crypto::*;

#[derive(Serialize, Deserialize, Debug)]
struct UserData {
    password: String,
    secret_key: Vec<u8>,
    public_key: Vec<u8>,
}

fn main() {
    println!("{}", "Starting Rwallet1.0, a simple ETH wallet...");

    let db = open_db("db");

    let login_file = OpenOptions::new()
        .read(true)
        .open("login.db")
        .unwrap();
    let mut login_map = create_map_from_file(login_file);

    println!("{}", "1) Login");
    println!("{}", "2) Signup");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            println!("{}", "Enter Username: ");
            let username = read_user_input();
            println!("{}", "Enter Password: ");
            let password = read_user_input();

            // check that password matches username
            match login_map.get(&username) {
                Some(v) => {
                    if password == v.to_string() {
                        println!("{}", "Successfully logged in");
                        // user can now query account balance
                        // more importantly, user now has access to private key to make transactions using this account
                        // fetch user keypair
                        let address = "username.getAddress()";

                        // the main functionality of the wallet occurs here in a loop
                        run_wallet_actions(address);
                    } else {
                        println!("{}", "Invalid password");
                    }
                },
                None => println!("{}", "No user account found. You can sign up."),
            };
        },
        2 => {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open("login.db")
                .unwrap();

            println!("{}", "Enter Username: ");
            let username = read_user_input();
            println!("{}", "Enter Password: ");
            let password = read_user_input();

            // if username exists, cannot use. Otherwise, generate new key pair and create new user!
            match db.get(&username) {
                Ok(Some(value)) => println!("Username already taken"),
                Ok(None) => {
                    let (secret_key, public_key) = generate_secp256k1_keypair();
                    let raw_key = public_key.serialize_uncompressed();
                    let address = generate_eth_address(&raw_key[1..]);
                    println!("Your ETH address: 0x{}", hex::encode(address));

                    // store in db
                    let data = UserData {
                        password,
                        secret_key: secret_key.serialize_secret().to_vec(),
                        public_key: raw_key.to_vec(),
                    };
                    // TODO: figure out serialization
                    db.put(username, data);
                }
                Err(e) => println!("{}", e),
            }
        },
        _ => println!("{}", "Invalid option"),
    }
}

fn run_wallet_actions(address: &str) {
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
                // TODO: Allow user to make a transaction
            }
            _ => println!("{}", "Invalid option"),
        }
    }
}
