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
The goal of a deterministic wallet is to derive many keys from a single master
key in a deterministic fashion. In this way, you only have to remember and
secure the master key, while getting a potentially unbounded number of keys.
This allows you to use one wallet, and have many accounts available for you to
use, thus bettering user privacy.

The simplist way to do this is by taking a master (private) key and hashing it.
Hash functions produce a random yet deterministic value. The result serves as
the child private key. If you use something like SHA-256, you will get a 256-bit
number, which is exactly what a private key is. This private key can be used
to derive a corresponding public key. Furthermore, the private key can also be
hashed, deriving a grandchild private key. One may continue this process
indefinitely, deriving a single, long chain of private keys.

So where do HD wallets come into play?
- With the simple design, we can only generate one long chain, ie, each key can
only generate one other child key. What if we wanted each key to be able to
generate many child keys. This would form a branching structure. Why would this
be useful? Well each branch could serve a specific purpose.
- The second thing is if we wanted to share our wallet, it happens on an all
or nothing basis because there is only one chain. With a branch structure however,
we can share only particular branches of keys, thus keeping the rest secure.
- So the main advantage of an HD wallet is its tree-like structure. The CKD functions
don't require a tree structure, we can use it in a simple deterministic wallet
just as easily.
  - Going from private parent to private child is easy enough (same hashing)
  - Going from public parent to public child can also be done, but the math
  is slightly more complex
  - Going from private parent to public child is done using a combination of steps

- By adding an index, we can derive many keys from one parent key. The index
essentially serves as a nonce, and each child key can be deterministically generated
by simply specifying the index.
- But why do we need a chain code? In the spec it says this adds an extra 256 bits
of entropy, thus making the derivation functions not rely solely on the keys.
  - The argument is that the chain code adds an extra layer of security to the xpub
  keys. However, the chain code is not really necessary

