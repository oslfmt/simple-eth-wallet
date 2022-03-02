mod login;
mod crypto;
mod utils;
mod db;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use hex;
use rocksdb::{DB};
use ethereum_tx_sign::RawTransaction;
use serde_json::Value;

use crate::utils::{read_user_input, wei_to_eth};
use crate::db::*;
use crate::crypto::{Secp, keccak256, generate_eth_address};

// TODO: list
// add HD wallet functionality
// test login security
// cleanup and modularize code
// enable sending transactions

const RINKEBY_CHAIN_ID: u8 = 4;

#[derive(Decode, Encode, PartialEq, Debug)]
struct UserData {
    password_hash: [u8; 32],
    // TODO: encrypt the secret key
    secret_key: [u8; 32],
    public_key: Vec<u8>,
    // TODO: add nonce
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
    let (username, password) = login::get_username_password();
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
    let (username, password) = login::get_username_password();

    // if username exists, cannot use. Otherwise, generate new key pair and create new user!
    match db.get(&username) {
        Ok(Some(_v)) => println!("Username already taken"),
        Ok(None) => {
            let secp = Secp::new();
            let (secret_key, public_key) = secp.create_keypair();
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
            match db.put(username, bytes) {
                Ok(()) => (),
                Err(e) => println!("Database error: {}", e),
            };

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
                query_balance(&address);
            },
            2 => {
                println!("Enter recipient address: ");
                let recipient = read_user_input();
                println!("Enter amount to send: ");
                let amount: u128 = read_user_input().parse::<u128>().unwrap();

                let tx = RawTransaction::new(
                    0,
                    hex::decode(recipient).unwrap(),
                    amount,
                    10000,
                    21240,
                    vec![]
                );

                let rlp_bytes = tx.sign(&secret_key, &RINKEBY_CHAIN_ID);
                let mut final_txn = String::from("0x");
                final_txn.push_str(&hex::encode(rlp_bytes));

                let resp: String = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
                    .set("Content-Type", "application/json")
                    .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_sendRawTransaction",
                        "params": [final_txn]
                    })).unwrap()
                    .into_string().unwrap();

                println!("{}", resp);
            }
            _ => println!("{}", "Invalid option"),
        }
    }
}

fn query_balance(address: &str) {
    let resp: Value = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
        .set("Content-Type", "application/json")
        .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBalance",
                        "params": [address, "latest"]
                    })).unwrap()
        .into_json().unwrap();

    match resp["result"].as_str() {
        Some(s) => {
            match s.strip_prefix("0x") {
                Some(v) => {
                    let balance = u128::from_str_radix(v, 16).unwrap();
                    println!("Balance: {} ETH", wei_to_eth(balance));
                },
                None => println!("String doesn't start with 0x"),
            }
        },
        None => println!("Value is not a string"),
    };
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_sign_transaction() {
        let txn = ureq::json!({
            "nonce": "0x0",
            "gasPrice": "0x09184e72a000",
            "gasLimit": "0x30000",
            "to": "0xb0920c523d582040f2bcb1bd7fb1c7c1ecebdb34",
            "value": "0x00",
            "data": "",
        }).to_string();

        let out = rlp::encode(&txn);
        let hash = keccak256(&out);

        let secp = Secp::new();
        let (secret_key, public_key) = secp.create_keypair();
        // sign the hash with the private key
        let sig = secp.sign_message(&hash, secret_key);
        let sig_bytes = sig.serialize_compact();
        let sig_r = &sig_bytes[..32];
        let sig_s = &sig_bytes[32..];

        let tx = ureq::json!({
            "nonce": "0x0",
            "gasPrice": "0x09184e72a000",
            "gasLimit": "0x30000",
            "to": "0xb0920c523d582040f2bcb1bd7fb1c7c1ecebdb34",
            "value": "0x00",
            "data": "",
            "v": "0x1c",
            "r": hex::encode(sig_r),
            "s": hex::encode(sig_s),
        }).to_string();
        let mut bytes = String::from("0x");
        bytes.push_str(&hex::encode(rlp::encode(&tx)));
        println!("{}", bytes);

        let resp: String = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
            .set("Content-Type", "application/json")
            .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_sendRawTransaction",
                        "params": [bytes]
                    })).unwrap()
            .into_string().unwrap();
        println!("{}", resp);
    }

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
