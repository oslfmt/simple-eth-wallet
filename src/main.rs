mod crypto;
mod utils;
mod storage;

use std::path::Path;
use std::fs::File;
use std::io::prelude::*;

use hex;
use ethereum_tx_sign::RawTransaction;
use serde_json::Value;
use bip39::{Mnemonic, MnemonicType, Language, Seed};

use crate::utils::{read_user_input, wei_to_eth, xor};
use crate::crypto::{keccak512};
use crate::storage::{TempData, Account, UserData};

const RINKEBY_CHAIN_ID: u8 = 4;
// ATOM is coin 118
// const COSMOS_PATH: &str = "m/44'/118'/0'/0/0";

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
            run_user_login();
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
}*/

/// Handles user login
fn run_user_login() {
    // load in data file
    let mut file = File::open("./userdata.txt").unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf).unwrap();
    let d: UserData = serde_json::from_str(&buf).unwrap();

    // prompt user to enter password
    println!("{}", "Enter Password: ");
    let password = read_user_input();

    // if password is correct, this will be the correct seed
    match d.verify_password(password) {
        // TODO: need to somehow reinstantiate the temp data
        true => println!("todo"), //run_wallet(),
        false => println!("Incorrect password"),
    }
}

fn create_new_wallet() {
    println!("{}", "Enter New Password: ");
    let password = read_user_input();

    // create a new mnemonic phrase
    let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
    let phrase = mnemonic.phrase();
    println!("Here is your secret recovery phrase: {}", phrase);
    // generate seed (no BIP39 password for now)
    let seed = Seed::new(&mnemonic, "");

    // parent_xprv is stored in temp data in order to derive further accounts
    // verif_key is stored in permanent user data in order to verify password for future logins
    let (parent_derive_xprv, _) = UserData::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'/0");
    let (_, verification_key) = UserData::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'");

    let mut temp_data = TempData::new(parent_derive_xprv);
    temp_data.create_account(0);

    // store pad and default (uncompressed) public key
    let pad = xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
    let user_data = UserData::new(pad, verification_key);
    match user_data.store() {
        Ok(()) => run_wallet(&mut temp_data),
        Err(e) => println!("{}", e),
    }
}

fn run_wallet(temp_data: &mut TempData) {
    let mut account = temp_data.default_account();

    loop {
        let num = run_account_actions(&account);
        if num == 3 {
            // create new account
            // switch to account
            account = temp_data.create_account(temp_data.accounts.len());
        } else if num == 4 {
            // display list of accounts
            temp_data.print_accounts();
            let option = read_user_input().parse::<usize>().unwrap();
            // switch to account
            account = temp_data.get_account(option);
        }
    }
}

fn run_account_actions(account: &Account) -> u8 {
    let address = &account.address;
    let signing_key = account.private_key();

    println!("CURRENT ACCOUNT ADDRESS: {}", address);

    loop {
        println!("{}", "1) View account balance");
        println!("{}", "2) Send a transaction");
        println!("{}", "3) Create another account");
        println!("{}", "4) Switch account");
        let option = read_user_input().parse::<u8>().unwrap();

        match option {
            1 => {
                query_balance(address);
            },
            2 => {
                send_transaction(signing_key);
            },
            3 => {
                return 3;
            },
            4 => {
                return 4;
            },
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

#[cfg(test)]
mod test {
    use super::*;
    use bip32::{ExtendedKey, Prefix, XPrv};

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
