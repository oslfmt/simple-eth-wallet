# Notes on building a Cosmos wallet
- Most of the core wallet primitives remain the same. Cosmos uses secp256k1
to generate public and private keypairs, so the process to derive keys is
the same as any ETH wallet
- Furthermore, I can build Cosmos wallets to fit the BIP39 standard to
use mnemonic phrases to generate a seed, and then follow the BIP32 standard
to create an HD Cosmos wallet
- I can follow BIP44 as well to make a multicurrency wallet, with ATOM being
just one particular branch in the tree path. Specifically, it is 118'.

## Differences
- The main difference will be in creating and sending transactions.
  - Creation: Cosmos TXNs have a different format than ETH transactions. I
    must follow the Cosmos specification or else Cosmos nodes will not
    recognize the format of the transaction and mark it as invalid.
  - Signing: This process will just involve signing the transaction with
    the private keys, which are the same keys used in ETH. However, the
    exact steps may differ, ie, signing the hash of the txn.
  - Sending: Currently, I'm relying on Infura to send my signed ETH txn to
    and ETH node, which then broadcasts the TXN to the network. Obviously
    this won't work for Cosmos, so I'll have to figure out a way to broadcast
    the Cosmos txns created by this wallet

## Solutions
1. Creation: lookup the Cosmos specification for txns. Since Cosmos defines
   txns in Go/protobuf format, I'll need some way to interface with this.
   It seems that a rust crate implements the txn protobufs in Rust instead
   of Go, so I can just use this.
2. Sending: look into how Keplr, other Cosmos wallets send their transactions.
   Is there a 3rd party service analogous to Infura but for Cosmos? Alternatively,
   I can look into running my own node.
