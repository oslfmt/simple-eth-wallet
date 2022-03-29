mod crypto;
mod utils;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;

use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use hex;
use rocksdb::{DB};
use ethereum_tx_sign::RawTransaction;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bip32::{XPrv, XPub, ChildNumber, DerivationPath, Prefix};
use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;

use crate::utils::{read_user_input, wei_to_eth, xor};
use crate::crypto::{Secp, keccak256, keccak512, generate_eth_address};

const RINKEBY_CHAIN_ID: u8 = 4;

#[derive(Serialize, Deserialize)]
struct UserData {
    // TODO: add nonce management
    pad: Vec<u8>,
    root_pub_key: Vec<u8>
}

fn main() {
    println!("{}", "Starting Rwallet2.0, an HD wallet...");

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
            //import_wallet();
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
            //run_user_login();
        },
        2 => {
            // TODO: check that it should overwrite current file contents
            //import_wallet();
        },
        _ => println!("{}", "Invalid option"),
    }
}

/*fn import_wallet() {
    // NOTE: importing wallet overwrites old wallet data. You can only have one wallet at any given time
    println!("Enter your mnemonic phrase to restore your wallet:\n");
    let phrase = read_user_input();
    let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
    let seed = Seed::new(&mnemonic, "");

    let master_prv_key = generate_master_prv_key(seed.as_bytes());

    // TODO: In the future, follow BIP-44 spec to generate 1 account by default. After that have option to add new accounts
    let (ext_prv_key, pub_key) = generate_default_keypair(master_prv_key);

    // create new password
    println!("{}", "Create Password: ");
    let password = read_user_input();

    let pad = xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap().to_vec();

    // TODO: to_bytes() returns SEC1-encoded, might not need first byte?
    match store_user_data(pad, pub_key.to_bytes()[1..].try_into().unwrap()) {
        Ok(()) => run_wallet_actions(ext_prv_key, pub_key.to_bytes()[1..].try_into().unwrap()),
        Err(e) => println!("{}", e),
    }
}

/// Handles user login
fn run_user_login() {
    // load in data file
    let mut file = File::open("./userdata.txt").unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf);
    let d: UserData = serde_json::from_str(&buf).unwrap();

    // prompt user to enter password
    println!("{}", "Enter Password: ");
    let password = read_user_input();
    let password_hash = keccak512(password.as_bytes());
    let seed = xor(&password_hash, &d.pad).unwrap();

    let master_prv_key = generate_master_prv_key(seed.as_bytes());
    // use seed to generate wallet accounts
    // the current problem is that if the password is wrong, there's no way to tell the user that.
    // the seed will still be derived, but it will be incorrect.
    let (ext_prv_key, pub_key) = generate_default_keypair(master_prv_key);
    let pub_key_type: [u8; 32] = pub_key.to_bytes()[1..].try_into().unwrap();
    if d.root_pub_key == pub_key_type {
        // then the correct master key was derived, so allow access to wallet
        run_wallet_actions(ext_prv_key, pub_key_type.to_vec());
    } else {
        println!("Incorrect password");
    }
}*/

fn create_new_wallet() {
    // create new password used for securing local app
    println!("{}", "Enter New Password: ");
    let password = read_user_input();

    // create a new mnemonic phrase
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    println!("Here is your secret recovery phrase: {}", phrase);
    // generate seed (no BIP39 password for now)
    let seed = Seed::new(&mnemonic, "");

    // generate default keys according to bip-44
    let (xprv, xpub) = generate_default_keypair(seed.as_bytes());
    println!("Private key: {:?}\nPublic key: {:?}", xprv.to_string(Prefix::XPRV), xpub.to_string(Prefix::XPUB));

    // Convert default acct pub_key to Ethereum address by taking hash of UNCOMPRESSED point
    let pub_key: [u8; 65] = xpub.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
    // only hash last 64B of pub_key because we want to leave out the prefix 0x04
    let addr = generate_eth_address(&pub_key[1..]);
    println!("ETHEREUM ADDRESS: 0x{}", hex::encode(addr));

    // store pad and default (uncompressed) public key
    let pad = xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
    match store_user_data(pad, &pub_key) {
        Ok(()) => run_wallet_actions(xprv, &pub_key),
        Err(e) => println!("{}", e),
    }
}

/// Generates the first account by default, when user first creates the wallet
fn generate_default_keypair(seed: &[u8]) -> (XPrv, XPub) {
    let default_acct_path = "m/44'/60'/0'/0/0";
    let child_xprv = XPrv::derive_from_path(
        seed,
        &DerivationPath::from_str(default_acct_path).unwrap()
    ).unwrap();
    // TODO: each time a user creates a new key, we can store this key in storage, so we don't have to rederive it everytime?
    let child_xpub = child_xprv.public_key();
    (child_xprv, child_xpub)
}

fn store_user_data(pad: Vec<u8>, root_pub_key: &[u8]) -> Result<(), String> {
    let data = UserData { pad, root_pub_key: root_pub_key.to_vec() };
    let data_bytes = serde_json::to_vec(&data).unwrap();
    let mut file = File::create("userdata.txt").unwrap();
    match file.write_all(&data_bytes) {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Error writing to file: {}", e)),
    }
}

/// Creates a new address within the wallet using HD wallet functionality
fn create_new_account(secret_key: &XPrv) -> XPrv {
    // derive new account from secret_key
    // m/44'/60'/0'/0/x (where x = 1,2,3...)
    secret_key.derive_child(ChildNumber::new(0, true).unwrap()).unwrap()
}

/// Handle actions like querying balance and sending transactions after user has logged in or signed up
fn run_wallet_actions(secret_key: XPrv, public_key: &[u8]) {
    let mut address = String::from("0x");
    address.push_str(&hex::encode(generate_eth_address(&public_key[1..])));

    loop {
        println!("{}", "1) View account balance");
        println!("{}", "2) Send a transaction");
        println!("{}", "3) Create another account");
        let option = read_user_input().parse::<u8>().unwrap();

        match option {
            1 => {
                query_balance(&address);
            },
            2 => {
                send_transaction(&secret_key);
            },
            3 => {
                let new_prv_key = create_new_account(&secret_key);
                let new_account = generate_eth_address(new_prv_key.public_key().to_bytes()[1..].try_into().unwrap());
                println!("Account 2 address: 0x{}", hex::encode(new_account));
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

fn send_transaction(secret_key: &XPrv) {
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

    let rlp_bytes = tx.sign(&secret_key.to_bytes()[..], &RINKEBY_CHAIN_ID);
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

#[cfg(test)]
mod test {
    use super::*;
    use bip32::{ExtendedKey, Prefix};

    fn base58_encode(data: ExtendedKey) -> String {
        let mut buffer = [0u8; 112];
        data.write_base58(&mut buffer).unwrap().to_string()
    }

    #[test]
    fn test_vector_one_bip32() {
        let seed = hex::decode("06f8f9d1cc0ffacd3cd59686ddbe6c5e71dfbf20a4c99fdd30ad6ba2f98f1c31c12091d72ed452d361c41e09aea84c2e3076ced658f2ea92d4ba45bc97de6566").unwrap();
        let master_prv = XPrv::new(seed.clone()).unwrap();
        let master_pub = master_prv.public_key();
    }

    #[test]
    fn test_generate_master_prv_key() {

    }
}
