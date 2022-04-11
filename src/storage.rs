use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use std::cell::RefCell;

use bip39::{Mnemonic, MnemonicType, Language, Seed};
use bip32::{XPrv, XPub, ChildNumber, DerivationPath, PrivateKeyBytes};
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
    pub accounts: Vec<AccountData,
}

#[derive(Serialize, Deserialize)]
struct AccountData {
    pub nonce: u32,
    pub path: String,
}

impl Wallet {
    /// Creates a new wallet with the given password as the xor mask
    pub fn new(password: String) -> Wallet {
        let mnemonic = Mnemonic::new(MnemonicType::Words12, Language::English);
        let phrase = mnemonic.phrase();
        println!("Here is your secret recovery phrase: {}", phrase);
        let seed = Seed::new(&mnemonic, "");

        let pad = utils::xor(seed.as_bytes(), &keccak512(password.as_bytes())).unwrap();
        let (_, verification_key) = Wallet::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'");
        let (parent_derive_xprv, _) = Wallet::create_keys_from_path(seed.as_bytes(), "m/44'/60'/0'/0");

        Wallet {
            pad,
            verification_key: verification_key.to_bytes().to_vec(),
            accounts: vec![AccountData::new()],
        }
    }

    /// Stores the key user data that is necessary for logging in again
    pub fn store(&self) -> Result<(), String> {
        let mut file = File::create("userdata.txt").unwrap();
        let data_bytes = serde_json::to_vec(self).unwrap();

        match file.write_all(&data_bytes) {
            Ok(()) => Ok(()),
            Err(e) => Err(format!("Error writing to file: {}", e)),
        }
    }

    pub fn verify_password(&self, password: String) -> bool {
        let password_hash = keccak512(password.as_bytes());
        let seed = utils::xor(&password_hash, &self.pad).unwrap();
        let (_, xpub) = Wallet::create_keys_from_path(&seed, "m/44'/60'/0'");

        if xpub.to_bytes().to_vec() == self.verification_key {
            true
        } else {
            false
        }
    }

    pub fn run(&self) {
        let mut account = &self.accounts[0];

        loop {
            let num = account.run();
            if num == 3 {
                // create new account
                // switch to account
                account = temp_data.create_account(temp_data.accounts.len());
            } else if num == 4 {
                // display list of accounts
                temp_data.print_accounts();
                let option = utils::read_user_input().parse::<usize>().unwrap();
                // switch to account
                account = temp_data.get_account(option);
            }
        }
    }

    /// Generate the key pair from a given path
    pub fn create_keys_from_path(seed: &[u8], path: &str) -> (XPrv, XPub) {
        let child_xprv = XPrv::derive_from_path(
            seed,
            &DerivationPath::from_str(path).unwrap()
        ).unwrap();
        let child_xpub = child_xprv.public_key();
        (child_xprv, child_xpub)
    }

    pub fn recreate(&self) {
        for account in self.accounts {
            let (xprv, xpub) = create_keys_from_path(self.seed, account.path);
            
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Accounts {
    /// The parent private key deriving all accounts
    pub deriving_key: PrivateKeyBytes,
    /// A vector of derived accounts
    pub accounts: Vec<Account>,
}

impl Accounts {
    /// Instantiates TempData struct with the deriving key, which will be used to derive all child accounts
    pub fn new(deriving_key: PrivateKeyBytes) -> Self {
        Accounts {
            deriving_key,
            accounts: vec![Account::new(&deriving_key, 0)]
        }
    }

    /// Creates a new account using the deriving key stored in TempData, with specified index
    /// and adds the created account to the TempData vector
    /// Returns a clone of the created account
    pub fn create_account(&mut self, index: usize) -> Account {
        let account = Account::new(&self.deriving_key, index);
        self.accounts.push(account.clone());
        account
    }

    /// Returns a clone of the first account of the accounts vector
    pub fn default_account(&self) -> Account {
        self.accounts[0].clone()
    }

    /// Prints all the accounts associated with user
    pub fn print_accounts(&self) {
        for (index, acc) in self.accounts.iter().enumerate() {
            println!("{}) {}", index, acc.address);
        }
    }

    pub fn get_account(&self, index: usize) -> Account {
        self.accounts[index].clone()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Account {
    pub nonce: u64,
    prv_key: PrivateKeyBytes,
    pub address: String,
}

impl Account {
    /// Creates a new address within the wallet using HD wallet functionality
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

        Account {
            nonce: 0,
            prv_key: child_xprv.to_bytes(),
            address,
        }
    }

    /// Returns a reference to the private key associated with the account
    pub fn private_key(&self) -> &[u8] {
        &self.prv_key
    }

    pub fn run(&self) -> u8 {
        let address = &account.address;
        let signing_key = account.private_key();

        println!("CURRENT ACCOUNT ADDRESS: {}", address);

        loop {
            println!("{}", "1) View account balance");
            println!("{}", "2) Send a transaction");
            println!("{}", "3) Create another account");
            println!("{}", "4) Switch account");
            let option = utils::read_user_input().parse::<u8>().unwrap();

            match option {
                1 => {
                    self.query_balance(address);
                },
                2 => {
                    self.send_transaction(signing_key);
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
                        println!("Balance: {} ETH", utils::wei_to_eth(balance));
                    },
                    None => println!("String doesn't start with 0x"),
                }
            },
            None => println!("Value is not a string"),
        };
    }

    fn send_transaction(secret_key: &[u8]) {
        println!("Enter recipient address: ");
        let recipient = utils::read_user_input();
        println!("Enter amount to send: ");
        let amount: u128 = utils::read_user_input().parse::<u128>().unwrap();

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
}

