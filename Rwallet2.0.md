# Rwallet2.0
## An HD Wallet

### Notes on Security
- previously we had a traditional account-based signup/signin. Users create
a username and password. This is stored in a database. On later accesses to
this account, one must enter the username password pair. Only if authorized,
then the user will get access to their private key, which will perform
signatures on their behalf
- Metamask takes a different approach. There is no username, but there is
a password, a mnemonic phrase, and private keys.
  - the mnemonic phrase encodes the seed, from which all other keys are
    derived from.
  - private keys are derived from the seed, but they are never shown to the
    user. Since they can be derived, they never need to be shown.
  - the password is used to secure the app itself, ie, to open the app. I
    think the password only serves to boost local security. If there was no
    password, then once someone creates a wallet, then that wallet will be
    open and accessible to all who gain access to the local machine. Anyone
    could then create transactions and drain all funds. However, with just
    the password, an attacker cannot possibly hack into an account, since
    to sign transactions, they need the private key, which is derived from
    the seed, and thus they need the mnemonic phrase.
- what complicates things is BIP39 and its optional passphrase. The passphrase
is used to salt the mnemonic, deriving a different seed from just the mnemonic.
It adds an additional layer of security, since now an attacker must know both
the BIP39-passphrase in addition to the mnemonic phrase itself in order to
derive the correct wallet.
- I think that the BIP39-passphrase is different from Metamask's generic
passphrase.
  - The BIP39-passphrase serves as an extra layer of security for the mnemonic
    phrase. It does not secure the local app at all.
  - The generic passphrase secures the app itself from local breaches.

### BIP-39
BIP-39 generates a mnemonic passphrase which essentially encodes the seed used
to generate all keys in the wallet. Essentially, the mnemonic words are used
to encode 128-256 bits of entropy. Each word encodes 11 bits of entropy. This
is much easier than say, memorizing 128 1s and 0s; instead, you just memorize
12 words. The entropy itself is used to derive a longer 512-bit seed. This is
done by using a key-stretching function, which essentially stretches the entropy
with 2048 rounds of hashing, in the end, generating a 512-bit hash. This is
the seed of the wallet. 

- I would like to explore how the salt works and how it adds extra security
to prevent against brute force attacks

### BIP-32

