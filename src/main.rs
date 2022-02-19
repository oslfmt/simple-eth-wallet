mod login;
mod crypto;
mod utils;
mod db;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use hex;
use rocksdb::{DB};
use secp256k1::SecretKey;
use rlp::{Encodable, RlpStream};

use crate::utils::read_user_input;
use crate::db::*;
use crate::crypto::{Secp, keccak256, generate_eth_address};

// TODO: list
// add HD wallet functionality
// test login security
// cleanup and modularize code
// enable sending transactions

#[derive(Decode, Encode, PartialEq, Debug)]
struct UserData {
    password_hash: [u8; 32],
    // TODO: encrypt the secret key
    secret_key: [u8; 32],
    public_key: Vec<u8>,
}

#[derive(PartialEq, Debug)]
struct Transaction {
    nonce: u64,
    gas_price: u128,
    gas_limit: u128,
    to: Vec<u8>,
    value: u64,
    data: Vec<u8>,
    v: Vec<u8>,
    r: u8,
    s: u8
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {

    }
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
                let amount: u64 = read_user_input().parse::<u64>().unwrap();

                // 1. handle signing offline
                // 2. Send RLP-encoded txn with eth_sendRawTransaction call

                // create a hashed message with all transaction fields and sign it
                let mut txn = Transaction {
                    nonce: 0,
                    gas_price: 100000,
                    gas_limit: 100000,
                    to: hex::decode(recipient).unwrap(),
                    value: amount,
                    data: vec![],
                    v: hex::decode("1c").unwrap(),
                    r: 0,
                    s: 0
                };

                // rlp encode transaction
                // TODO: check if rlp is valid
                let txn_bytes = rlp::encode(&txn);
                println!("{:?}", txn_bytes);
                // hash the RLP-encoded txn
                let txn_bytes_hashed = keccak256(&txn_bytes);

                let secp = Secp::new();
                // sign the hash with the private key
                let mut sig = secp.sign_message(&txn_bytes_hashed, SecretKey::from_slice(&secret_key).unwrap());
                // get the (r,s) values from sig?
                sig.normalize_s();

                // append (v,r,s) values to the txn
/*                txn.r = sig.r;
                txn.s = sig.s;*/
                // re-encode txn?
                let updated_bytes = hex::encode(rlp::encode(&txn));

                let resp: String = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
                    .set("Content-Type", "application/json")
                    .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_sendRawTransaction",
                        "params": [updated_bytes]
                    })).unwrap()
                    .into_string().unwrap();

                println!("{}", resp);
            }
            _ => println!("{}", "Invalid option"),
        }
    }
}

fn query_balance(address: &str) {
    // TODO: use serde to deserialize JSON and extract balance, then convert from hex to decimal to make readable
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
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rlp_encode_json() {
        let txn = ureq::json!({
            "nonce": "0x0",
            "gasPrice": "0x09184e72a000",
            "gasLimit": "0x30000",
            "to": "0xb0920c523d582040f2bcb1bd7fb1c7c1ecebdb34",
            "value": "0x00",
            "data": "",
            "v": "0x1c",
            "r": '0',
            "s": '0',
        }).to_string();

        let out = rlp::encode(&txn);
        let hash = keccak256(&out);

        let secp = Secp::new();
        // sign the hash with the private key
        let mut sig = secp.sign_message(&hash, SecretKey::from_slice(&secret_key).unwrap());
        // get the (r,s) values from sig?
        sig.normalize_s();
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
