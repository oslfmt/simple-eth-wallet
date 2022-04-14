use std::fs::File;
use std::io::prelude::*;

use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bip32::{XPrv, ChildNumber, PrivateKeyBytes};
use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use hex;
use ethereum_tx_sign::RawTransaction;

use crate::crypto::{generate_eth_address, keccak512};
use crate::utils;

const RINKEBY_CHAIN_ID: u8 = 4;
// ATOM is coin 118
// const COSMOS_PATH: &str = "m/44'/118'/0'/0/0";

#[derive(Serialize, Deserialize)]
pub struct Wallet {
    /// Encoded wallet seed
    pub pad: Vec<u8>,
    /// The public key used to verify logins
    pub verification_key: Vec<u8>,
    /// Accounts associated with this wallet
    accounts_metadata: AccountMetadata,
}

impl Wallet {
    /// Creates a new wallet with the given password as the xor mask.
    pub fn new(password: String) -> Wallet {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase();
        println!("Here is your secret recovery phrase: {}", phrase);
        let seed = Seed::new(&mnemonic, "");

        let pad = utils::xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
        let (_, verification_key) = utils::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'");
        let (parent_derive_xprv, _) = utils::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'/0");

        Wallet {
            pad,
            verification_key: verification_key.to_bytes().to_vec(),
            accounts_metadata: AccountMetadata::new(parent_derive_xprv),
        }
    }

    /// Imports a wallet
    // TODO: very similar to new function except for a few lines, may refactor
    pub fn from(password: String) -> Wallet {
        println!("Enter your mnemonic phrase to restore your wallet:\n");
        let phrase = utils::read_user_input();
        let mnemonic = Mnemonic::from_phrase(&phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");

        let pad = utils::xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
        let (_, verification_key) = utils::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'");
        let (parent_derive_xprv, _) = utils::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'/0");

        Wallet {
            pad,
            verification_key: verification_key.to_bytes().to_vec(),
            accounts_metadata: AccountMetadata::new(parent_derive_xprv),
        }
    }

    /// Stores the key user data that is necessary for logging in again
    pub fn store(&mut self) -> Result<(), String> {
        let mut file = File::create("userdata.txt").unwrap();

        // clear all sensitive data
        self.accounts_metadata.deriving_key = None;
        for account in &mut self.accounts_metadata.accounts {
            account.prv_key = None;
        }

        let data_bytes = serde_json::to_vec(self).unwrap();

        match file.write_all(&data_bytes) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Error writing to file: {}", e)),
        }
    }

    pub fn verify_password(&mut self, password: String) -> bool {
        let password_hash = keccak512(password.as_bytes());
        let seed = utils::xor(&password_hash, &self.pad).unwrap();
        let (_, xpub) = utils::create_keys_from_path(&seed, "m/44'/60'/0'");

        if xpub.to_bytes().to_vec() == self.verification_key {
            // set the deriving key
            let (parent_derive_xprv, _) = utils::create_keys_from_path(&seed, "m/44'/60'/0'/0");
            self.accounts_metadata.deriving_key = Some(parent_derive_xprv);

            true
        } else {
            false
        }
    }

    /// Starts the wallet with the default account
    pub fn run(&mut self) {
        // fetch the deriving key
        let deriving_key = match &self.accounts_metadata.deriving_key {
            Some(k) => k.clone(),
            None => unreachable!("Deriving key must've been created if wallet was created"),
        };

        // start account actions
        match self.accounts_metadata.run(deriving_key) {
            5 => {
                match self.store() {
                    Ok(()) => println!("Stored wallet data safely"),
                    Err(e) => println!("{}", e),
                };
            },
            _ => unreachable!("Code should only return quit flag (5)"),
        };
    }

    // TODO: move this to utils

}

#[derive(Serialize, Deserialize)]
struct AccountMetadata {
    /// The parent private key deriving all accounts
    #[serde(skip)]
    pub deriving_key: Option<XPrv>,
    /// A vector of derived accounts
    pub accounts: Vec<Account>,
}

impl AccountMetadata {
    /// Creates AccountMetadata with the private deriving key and a default account
    pub fn new(deriving_key: XPrv) -> Self {
        AccountMetadata {
            deriving_key: Some(deriving_key.clone()),
            accounts: vec![Account::new(&deriving_key, 0)]
        }
    }

    /// Creates a new account with specified index. Returns a clone of the created account
    pub fn create_account(&mut self, index: usize) -> Account {
        match &self.deriving_key {
            Some(k) => {
                let account = Account::new(k, index);
                self.accounts.push(account.clone());
                account
            },
            None => unreachable!(),
        }
    }

    /// Returns a clone of the first account of the accounts vector
    pub fn default_account(&self) -> Account {
        self.accounts[0].clone()
    }

    /// Prints all the created accounts in the wallet
    pub fn print_accounts(&self) {
        for (index, acc) in self.accounts.iter().enumerate() {
            println!("{}) {}", index, acc.address);
        }
    }

    /// Returns the account with given index
    pub fn get_account(&self, index: usize) -> Account {
        self.accounts[index].clone()
    }

    /// Runs an account, allowing for creation of new accounts and switching between accounts
    /// when user opts to do so.
    pub fn run(&mut self, deriving_key: XPrv) -> u8 {
        let mut account = self.default_account();

        loop {
            match account.run(&deriving_key) {
                3 => {
                    // create new account
                    let index = self.accounts.len();
                    account = self.create_account(index);
                },
                4 => {
                    self.print_accounts();
                    // switch to user selected account
                    let option = utils::read_user_input().parse::<usize>().unwrap();
                    account = self.get_account(option);
                },
                5 => {
                    return 5;
                },
                _ => print!("Invalid option"),
            }
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct Account {
    pub nonce: u64,
    pub path: String,
    pub address: String,
    prv_key: Option<PrivateKeyBytes>,
}

impl Account {
    /// Creates a new account with nonce as 0 and private_key set to none. Private key can later be
    /// instantiated when needed for signing a transaction.
    /// deriving_key - the parent key with path m/44'/60'/0'/0, used to derive all child accounts
    /// index - the index of the child account
    ///
    /// The returned key has path: m/44'/60'/0'/0/x, where x = 0,1,2,3...
    pub fn new(deriving_key: &XPrv, index: usize) -> Self {
        let child_xprv = deriving_key.derive_child(ChildNumber::new(index as u32, false).unwrap()).unwrap();
        let child_xpub = child_xprv.public_key();

        // Convert default acct pub_key to Ethereum address by taking hash of UNCOMPRESSED point
        let pub_key: [u8; 65] = child_xpub.public_key().to_encoded_point(false).as_bytes().try_into().unwrap();
        // only hash last 64B of pub_key because we want to leave out the prefix 0x04
        let addr_bytes = generate_eth_address(&pub_key[1..]);
        let address = String::from("0x") + &hex::encode(addr_bytes);

        let mut path = String::from("m/44'/60'/0'/0/");
        path.push_str(&index.to_string());

        Account {
            nonce: 0,
            path,
            prv_key: None,
            address,
        }
    }

    pub fn run(&mut self, deriving_key: &XPrv) -> u8 {
        println!("CURRENT ACCOUNT ADDRESS: {}", &self.address);

        loop {
            println!("{}", "1) View account balance");
            println!("{}", "2) Send a transaction");
            println!("{}", "3) Create another account");
            println!("{}", "4) Switch account");
            println!("{}", "5) Quit");
            let option = utils::read_user_input().parse::<u8>().unwrap();

            match option {
                1 => {
                    self.query_balance();
                },
                2 => {
                    // if prv_key is non-existent, derive it and set it. Then send transaction.
                    if let None = self.prv_key {
                        self.prv_key = Some(utils::derive_child_secret_key(deriving_key, 0));
                    }
                    self.send_transaction();
                },
                3 => {
                    return 3;
                },
                4 => {
                    return 4;
                },
                5 => {
                    return 5;
                },
                _ => println!("{}", "Invalid option"),
            }
        }
    }

    fn query_balance(&self) {
        let resp: Value = ureq::post("https://rinkeby.infura.io/v3/39f702e71cd84987bd1ec2550a54375e")
            .set("Content-Type", "application/json")
            .send_json(ureq::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "eth_getBalance",
                        "params": [self.address, "latest"]
                    })).unwrap()
            .into_json().unwrap();

        match resp["result"].as_str() {
            Some(s) => {
                match s.strip_prefix("0x") {
                    Some(v) => {
                        let balance = u128::from_str_radix(v, 16).unwrap();
                        println!("Balance: {} ETH", utils::wei_to_eth(balance));
                    },
                    None => println!("String doesn't start with 0x"),
                }
            },
            None => println!("Value is not a string"),
        };
    }

    fn send_transaction(&self) {
        println!("Enter recipient address: ");
        let recipient = utils::read_user_input();
        println!("Enter amount to send: ");
        let amount: u128 = utils::read_user_input().parse::<u128>().unwrap();

        // TODO: add gas price and limit selection (need to be high enough to be mined)
        let tx = RawTransaction::new(
            self.nonce as u128,
            hex::decode(recipient).unwrap().try_into().unwrap(),
            amount,
            2000000000,
            1000000,
            vec![]
        );

        let rlp_bytes = tx.sign(&self.prv_key.unwrap(), &RINKEBY_CHAIN_ID);
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
}

