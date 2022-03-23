mod crypto;
mod utils;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use hex;
use rocksdb::{DB};
use ethereum_tx_sign::RawTransaction;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use ed25519_dalek_bip32::{DerivationPath, ExtendedSecretKey, ChildIndex, PublicKey};

use crate::utils::{read_user_input, wei_to_eth, xor};
use crate::crypto::{Secp, keccak256, keccak512, generate_eth_address};

// TODO: list
// add nonce management
// add HD wallet functionality

// TODO: store seed more securely
// 1. hash user password
// 2. xor password hash the seed
// 3. store result in database. Essentially, the seed is encrypted by xor with password hash
// 4. When user logs back in, the hash is xor with the stored result, to get the original seed back

const RINKEBY_CHAIN_ID: u8 = 4;

#[derive(Decode, Encode, PartialEq, Debug)]
struct UserData {
    password_hash: [u8; 32],
    // TODO: encrypt the secret key
    secret_key: [u8; 32],
    public_key: Vec<u8>,
    // TODO: add nonce
    // nonce: u64,
}

#[derive(Serialize, Deserialize)]
struct UserDataTwo {
    pad: Vec<u8>
}

fn main() {
    println!("{}", "Starting Rwallet2.0, an HD wallet...");

    // open the database containing login and keypair info
    let db = utils::open_db("db");

    if !Path::new("./userdata.txt").exists() {
        display_menu_one();
    } else {
        display_menu_two();
    }
}

fn display_menu_one() {
    println!("{}", "1) Create a new wallet");
    println!("{}", "2) Import wallet");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            create_new_wallet();
        },
        2 => {
            import_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

fn display_menu_two() {
    println!("{}", "1) Login");
    println!("{}", "2) Import wallet");
    let option = read_user_input().parse::<u8>().unwrap();

    match option {
        1 => {
            run_user_login();
        },
        2 => {
            // TODO: check that it should overwrite current file contents
            import_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

fn import_wallet() {
    // NOTE: importing wallet overwrites old wallet data. You can only have one wallet at any given time
    // recover seed
    println!("Enter your mnemonic phrase to restore your wallet:\n");
    let phrase = read_user_input();
    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    // create new password
    println!("{}", "Create Password: ");
    let password = read_user_input();
    let pad = xor(seed.as_bytes(), &keccak256(password.as_bytes())).unwrap().to_vec();

    let data = UserDataTwo { pad };
    let data_bytes = serde_json::to_vec(&data).unwrap();

    // write to file
    let mut file = File::create("userdata.txt").unwrap();
    file.write_all(&data_bytes);

    // TODO: use seed to access wallet
    // run_wallet_actions();
}

/// Handles user login
fn run_user_login() {
    // load in data file
    let mut file = File::open("./userdata.txt").unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf);
    let d: UserDataTwo = serde_json::from_str(&buf).unwrap();

    // prompt user to enter password
    println!("{}", "Enter Password: ");
    let password = read_user_input();
    let password_hash = keccak512(password.as_bytes());
    let seed = xor(&password_hash, &d.pad).unwrap();

    // use seed to generate wallet accounts
    // the current problem is that if the password is wrong, there's no way to tell the user that.
    // the seed will still be derived, but it will be incorrect.
}

fn create_new_wallet() {
    // create new password used for securing local app
    println!("{}", "Enter New Password: ");
    let password = read_user_input();

    // create a new mnemonic phrase
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    println!("Here is your secret recovery phrase: {}\n", phrase);
    println!("It is used to derive all your accounts and private keys. Thus, memorize it and keep it hidden.");

    // generate seed (no BIP39 password for now)
    let seed = Seed::new(&mnemonic, "");
    let pad = xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
    
    // use seed to derive master private key
    // TODO: In the future, follow BIP-44 spec to generate 1 account by default. After that have option to add new accounts
    // CHECK: this returns ed25519 public key? Not secp256k1??
    let pub_key = generate_default_account(seed.as_bytes());
    let address = generate_eth_address(&pub_key.to_bytes());

    println!("ETH Address: 0x{}", hex::encode(address));

    let data = UserDataTwo { pad };
    let data_bytes = serde_json::to_vec(&data).unwrap();

    // write to file
    let mut file = File::create("userdata.txt").unwrap();
    file.write_all(&data_bytes);

    // run_wallet_actions();
}

/// Generates the first account by default, when user first creates the wallet
fn generate_default_account(seed_bytes: &[u8]) -> PublicKey {
    let master_private_key = ExtendedSecretKey::from_seed(seed_bytes).unwrap();
    // this is key: m/0'
    let child_prv = master_private_key.derive_child(ChildIndex::Hardened(0)).unwrap();
    // TODO: each time a user creates a new key, we can store this key in storage, so we don't have to rederive it everytime?
    child_prv.public_key()
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
                send_transaction(&secret_key);
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

fn send_transaction(secret_key: &[u8]) {
    println!("Enter recipient address: ");
    let recipient = read_user_input();
    println!("Enter amount to send: ");
    let amount: u128 = read_user_input().parse::<u128>().unwrap();

    // TODO: add gas price and limit selection (need to be high enough to be mined)
    let tx = RawTransaction::new(
        1,
        hex::decode(recipient).unwrap().try_into().unwrap(),
        amount,
        2000000000,
        1000000,
        vec![]
    );

    let rlp_bytes = tx.sign(secret_key, &RINKEBY_CHAIN_ID);
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

/// DEPRECATED
fn run_user_signup(db: DB) {
    let (username, password) = utils::get_username_password();

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
