# Rwallet1.0
## A simple Ethereum wallet
NOTE: Do NOT use for actual funds. This wallet is still in development.

To install and run this wallet, you must have Rust and Cargo installed.
After that, simply clone this repository, `cd` into it, and type `cargo run`.

This will build and start the application.

To install Rust and Cargo, follow the instructions [here](https://www.rust-lang.org/tools/install).

## A primer on wallets
The simple Ethereum wallet housed in this repo is the simplist of all wallets. It only generates
one keypair for users, which is reused for every transaction thereafter. This works, but is terrible
for privacy, because one can easily track and link all transactions from this one user. Even though
there identity may not be known, one can deduce everything that this person is doing.

On the flip side, we can use a different key for every transaction. This is much better for user
privacy, although harder to manage. [TODO: how are diff keys used?? Metamask is "HD" but still all
transaction history is from one account?"]

There are two main types of wallets, distinguished by whether the keys used are related or not:

1. Nondeterministic - JBOK wallet. The keys are independently generated from a random number,
and are not related
2. Deterministic - all keys are derived from a single master key (the seed). Thus, all keys
are related to each other and can be derived again if one has the seed.

### Nondeterministic Wallets
- To maximize privacy, you want to use a new address everytime you receive funds
- You can use a new address each time you transact, but this is expensive because first you
need to receive funds in account x, then transfer to account y.
- Nondeterministic wallets create a new random key everytime you want to create a new account.
The key pairs are stored in a wallet file, and this means you need to make regular backups
of your wallet file as new key pairs are added
- NOTE: see keystore files, a way to securely store private keys

### Deterministic Wallets
- A seed, which is a random number combined with other data (chain code), which can be used
to derive any number of private keys
- Since the seed can derive any keys, only a single backup is needed, at wallet creation time,
in order to secure all the funds in the wallet
- The seed also allows for easy import/export, thus migrating all keys between different wallet
implementations

#### HD Wallets
This is the most advanced form of deterministic wallet. The keys are derived in
a tree-like structure, meaning that parent keys derive a sequence of child keys,
which derive a sequence of grandchild keys, etc. The standard is defined in the
BIP-32 specification.


