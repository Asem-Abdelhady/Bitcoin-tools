# bitcoin-tools-cli

A command-line interface over [`bitcoin-tools-core`](../core/README.md).

A sibling of the [axum server](../server/README.md), not a layer under or over
it: both are front ends, the core is shaped by neither, and where they answer
the same question they answer it the same way.

```console
$ bitcoin-tools converter unit --bitcoin 1.5
satoshi         150000000
microbitcoin    1500000
millibitcoin    1500
bitcoin         1.5
in money range  yes

$ bitcoin-tools keys public --private-key-file key.hex
network             mainnet
compressed          yes

publicKey           0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
…
addresses
  p2pkh
    address         1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    scriptPubkey    76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
    version         0 (00)
    hash            751e76e8199196d454941c45d1b3a323f1433bd6
    checksum        510d1634
  …

$ bitcoin-tools blocks header 01000000…1dac2b7c --json | jq .difficulty
1.0
```

```console
$ cargo run -p bitcoin-tools-cli -- converter base --decimal 255
$ cargo install --path crates/cli        # installs the `bitcoin-tools` binary
```

`publish = false`. Requires Rust 1.87.

## Commands

Fourteen, in six groups — the server's endpoints, named the way the server names
them. Everything is pure computation over bytes: no node, no network, no chain
state.

Every command below also takes `--json`, and `--input <FILE>` in place of its
arguments.

The examples are real output, with long values elided at a `…`. The key in the
`keys generate` example is a throwaway from an actual run — this command draws a
new one every time, so it is not a key anyone holds.

### `converter` — representation

```console
$ bitcoin-tools converter base --hex 0xab12
binary       1010101100010010
decimal      43794
hexadecimal  ab12
bits         16
bytes        2

$ bitcoin-tools converter unit --bitcoin 1.5
satoshi         150000000
microbitcoin    1500000
millibitcoin    1500
bitcoin         1.5
in money range  yes

$ bitcoin-tools converter reverse-bytes 0xdeadbeef
input     deadbeef
reversed  efbeadde
bytes     4
```

`reverse-bytes` is the operation relating the order a hash is stored in to the
order an explorer shows it — a txid copied from a block explorer never appears
verbatim in the raw transaction that produced it. One command covers both
directions, because reversal is an involution.

### `keys` — private keys, public keys, addresses

```console
$ bitcoin-tools keys generate --network testnet
network     testnet
compressed  yes

wif         cUhaQvXo1T7HR6yG4naiXNPSz5kah7AhPsTg1ABBttmfmK2mhokG
hex         d4660f07421e139f8e1f88eb1965c05ed49d4b69c0952437d3bcaa1be3c48aa9
decimal     96070646022137682132945058910275331120979634050011197683278170290075103169193
binary      1101010001100110000011110000011101000010000111100001001110011111…

$ bitcoin-tools keys public --private-key-file key.hex
network             mainnet
compressed          yes

publicKey           0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
compressedKey       0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
uncompressedKey     0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798…
xOnly               79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
x                   79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
y                   483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
pubkeyHash          751e76e8199196d454941c45d1b3a323f1433bd6
p2wpkhRedeemScript  0014751e76e8199196d454941c45d1b3a323f1433bd6

addresses
  p2pkh
    address         1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH
    scriptPubkey    76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
    version         0 (00)
    hash            751e76e8199196d454941c45d1b3a323f1433bd6
    checksum        510d1634
  p2shP2wpkh
    address         3JvL6Ymt8MVWiCNHC7oWU6nLeHNJKLZGLN
    …
  p2wpkh
    address         bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
    hrp             bc
    witnessVersion  0
    program         751e76e8199196d454941c45d1b3a323f1433bd6
    checksum        v8f3t4
  p2tr
    address         bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9
    …
```

An address is not an opaque string, and `keys public` is where one key gets
taken apart: a Base58 address is a version byte, a hash and a checksum; a Bech32
one is a prefix, a witness version, a program and a checksum.

### `hd` — BIP39 sentences and BIP32 derivation

```console
$ bitcoin-tools hd mnemonic --words 12
network              mainnet
passphraseUsed       no

phrase               draw fork excite seven plate relief soon purpose soccer armed siege dance
wordCount            12
entropy              426b6d3b625a636ab3d573cdc17b201b
entropyBits          128
checksum             0a
checksumBits         4
indices              531 731 630 1573 1329 1450 1658 1395 1646 94 1600 442

seed                 0748fbad13386e11e852c410739119fde146ac04…

masterKey
  path               m
  depth              0
  fingerprint        8671f0a8
  parentFingerprint  00000000
  chainCode          58d8b8fa5e99b82c572db2191038a80a0aa06fcfb9b0743ccab5967550205bbd
  xprv               xprv9s21ZrQH143K2wfKxDjtdrC9yfxAcMnr3ZKHX1Zm6YqJpzicpVtyBrRq…
  xpub               xpub661MyMwAqRbcFReo4FGu13yta7ng1pWhQnEtKPyNexNHhnck…

$ bitcoin-tools hd derive --seed-file seed.hex --path m/84h/0h/0h/0 --count 2
network              mainnet
purpose              bip84

branch
  path               m/84'/0'/0'/0
  depth              4
  fingerprint        b1cc03eb
  parentFingerprint  e889b6af
  chainCode          597354c4ef773a7f4657588e3b7d5400383cd12422f98f72b11348732236f1df
  xprv               xprvA2FgjeA3n5EwtdrdQMPjBLyX8ibH1eyXTcVNNH1CA2qGJYYjPiBiPz5d…
  xpub               xpub6FF399gwcSoF77w6WNvjYUvFgkRmR7hNpqQyAfQoiNNFBLsswFVxwnQ6…

m/84'/0'/0'/0/0
  index              0
  privateKey         8d98d2f794f9935b7fb57e18dfe8d9ae34149a58835c299f219ac5fa0bac739a
  wif                L1xxTDd4RJ9GG7jZQQR4WKHjYU7CvbNjjiWcPBPkowCj11BDPp4p
  publicKey          02ce3088b423b443a7dd03ffc917961c43df41b50a5627e1af31a2fd65c57be50a
  pubkeyHash         0f0d117a87e7e06468b90afbdb72c3ef66072da6
  address            bc1qpux3z758ulsxg69eptaakukraanqwtdxe5yy4c
  p2pkh              12NanssrThfNFiKJeqdvtVTEaAm5eXhXdc
  p2shP2wpkh         38BvBy1n6De475moHjsCibmcKDVjHoGA2W
  p2wpkh             bc1qpux3z758ulsxg69eptaakukraanqwtdxe5yy4c
  p2tr               bc1pt4cyn0ntnuvsck7htdy2za0t95snajcdpd4yvcks9d9s50ajsr9qna5pnv

m/84'/0'/0'/0/1
  …
```

An apostrophe or `h` marks a hardened step, and `h` is the one that does not need
quoting in a shell. `purpose` is inferred from the path's first step and decides
which of the four addresses is *the* address for that layout — BIP44, 49, 84 and
86 are four purpose numbers over one algorithm, not four code paths.

`--start-index` pages through an account: `--start-index 20 --count 20` is the
second twenty addresses of the same branch.

### `transactions` — scripts, raw transactions, building one

```console
$ bitcoin-tools transactions script 76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
kind            P2PKH
hex             76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
sizeBytes       25
asm             OP_DUP OP_HASH160 OP_PUSHBYTES_20 751e76e8… OP_EQUALVERIFY OP_CHECKSIG
disabledOpcode  no
  pubkeyHash    751e76e8199196d454941c45d1b3a323f1433bd6

offset  hex  opcode           category    data        description
0       76   OP_DUP           stack                   Duplicate the top item
1       a9   OP_HASH160       crypto                  RIPEMD-160 of the SHA-256 of the top item
2       14   OP_PUSHBYTES_20  push-bytes  751e76e8…   Push the next N bytes onto the stack
23      88   OP_EQUALVERIFY   logic                   OP_EQUAL then OP_VERIFY
24      ac   OP_CHECKSIG      crypto                  Verify a signature against a public key

$ bitcoin-tools transactions splitter --input tx.json
txid                  6d574d5c96bac5cbc1204adb43cb1de7485c9c3e8b80be3fa7580225d7afa9a5
wtxid                 f6b19a3dfb44291b6bf698f8df0857c2cdf800eece09dff0ed46bb35ea60ac23

version               01000000
marker                00
flag                  01
inputCount            01
  input 0
    txid              03171240f4a4e080333762611ac16dade8cfe9b09e12802541ca106a1b32dc38
    vout              01000000
    scriptSigSize     17
    scriptSig         160014a12cc1a4ca6d59139a7e06d833af09652fde5f87
    sequence          ffffffff
  …

$ bitcoin-tools transactions builder --type legacy \
      --spend aa52ef52f47e26a3e0bd0e8de4b7c0e3e2d2c1b0a9f8e7d6c5b4a39281706150:0 \
      --pay 100000:76a914751e76e8199196d454941c45d1b3a323f1433bd688ac
txid    284bd5daab2af3babc2400aa7c8e87905a2144b8850714a3f16628ec28dacac4
size    85
weight  340
vsize   85

rawTx   020000000150617081…88ac00000000
```

`splitter` shows every value as **the bytes it occupies**, not as a decoded
number — the version of a version 2 transaction is `02000000`, because showing
which bytes are which is the point.

A broken script is still an answer: everything that decoded, with the problem
beside it. A broken transaction is a failure, because once field boundaries stop
lining up there is no partial answer.

`builder` validates and does **not** sign. It refuses the set of transactions
that serialize cleanly and are still rejected by every node — no inputs, no
outputs, a duplicated outpoint, the coinbase outpoint, an amount above 21
million, both halves of BIP144's witness rule, and `bad-txns-oversize`. Its
flags build an unsigned skeleton; anything carrying a `scriptSig` or a witness
comes from `--input`.

### `blocks` — headers

```console
$ bitcoin-tools blocks hash 01000000…1dac2b7c
blockHash  000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
wireOrder  6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000

$ bitcoin-tools blocks header 01000000…1dac2b7c
blockHash    000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f
version      1 (00000001)
prevBlock    0000000000000000000000000000000000000000000000000000000000000000
merkleRoot   4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b
time         1231006505
bits         1d00ffff
nonce        2083236893

target       00000000ffff0000000000000000000000000000000000000000000000000000
difficulty   1.0
meetsTarget  yes
```

`meetsTarget` closes the loop: it checks the header's own hash against the target
its `bits` expand to, rather than asking you to trust either.

### `crypto` — ECDSA

```console
$ bitcoin-tools crypto sign --private-key-file key.hex --message-hash abab…abab
publicKey    0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
messageHash  abababababababababababababababababababababababababababababababab

signature
  der        3045022100a01fd9343bce99b2865d4f63e8ece20ca5b741772ead1069e28cc878…
  compact    a01fd9343bce99b2865d4f63e8ece20ca5b741772ead1069e28cc878bf52015f4b…
  r          a01fd9343bce99b2865d4f63e8ece20ca5b741772ead1069e28cc878bf52015f
  s          4b8b089c65f5f24b8ca8d3a987c2392a4ea7b379c457f85d7b91cab609d39c44
  lowS       yes

$ bitcoin-tools crypto verify --public-key 0279be66… --message-hash abab…abab \
      --signature 3045022100a01fd934…
valid      yes
encoding   der
publicKey  0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798

signature
  …
```

Neither command hashes anything. ECDSA signs a *digest*, and what a Bitcoin
signature commits to is a sighash — computed from the value and script of every
output being spent, which a raw transaction does not carry. A tool that quietly
hashed for you would produce a signature over the wrong thing and look like it
worked.

Signing is RFC 6979 deterministic: no RNG, and a repeated nonce — which hands an
attacker the private key outright — is impossible unless the digest repeats.
Output is always low-`s`.

`valid  no` exits **0**. That is the question the command exists to answer, and
there is no sub-reason a caller could act on; only bytes that are not a signature
at all are a failure.

### The notation is the flag

`--hex 0xab12`, not `0xab12 --base hex`. The notation and the value arrive as
one argument, which is how a person says it, and it makes the rule structural
rather than enforced: **there is no way to give a value without saying what it
is written in.** `10` is two, ten or sixteen; `1` is a satoshi or a hundred
million of them. A tool that guessed would return a confident wrong answer,
which is worse than an error.

Each flag's long form is the key its answer comes back under, so a key of the
output names the flag that would produce it. The short aliases are for typing:

| Long | Aliases |
|---|---|
| `--binary` `--decimal` `--hexadecimal` | `--bin` `--dec` `--hex` |
| `--satoshi` `--microbitcoin` `--millibitcoin` `--bitcoin` | `--sat` `--sats` `--ubtc` `--bits` `--mbtc` `--btc` |

Two other flags carry the same rule for the same reason. `transactions builder
--type` has no default, because the serialization changes the bytes, the txid
and whether a witness survives at all. `hd derive --path` has none, because `m`
and `m/84h/0h/0h/0` are different wallets.

`reverse-bytes`, `script`, `splitter`, `blocks hash` and `blocks header` take
their value positionally: one payload, no notation to name.

### Exactly one source

Every command takes its request from arguments *or* from `--input`, never a
mixture, and clap enforces it. Getting that wrong — both, or neither — is a
usage error and exits 2.

## Secrets never arrive as arguments

**There is no `--private-key`, no `--seed` and no `--passphrase`.** Arguments
are visible in `ps` to every user on the machine and land verbatim in shell
history, and neither is something you can take back. So the flag names a file:

```console
$ bitcoin-tools keys public --private-key-file key.hex
$ printf %s "$KEY" | bitcoin-tools keys public --private-key-file -
$ bitcoin-tools hd derive --seed-file seed.hex --path m/84h/0h/0h/0 --count 5
$ bitcoin-tools hd mnemonic --passphrase-file secret.txt
```

`-` is stdin, which is the scripting form and keeps the secret off disk
entirely. Surrounding whitespace is trimmed, so a file written by `echo` works.
A whole request file (`--input`) may also carry the secret, because a file is
not `argv`.

The rule is asserted against the *generated help* rather than against this
paragraph: `no_command_offers_a_flag_that_carries_a_secret` in the test suite
fails if such a flag is ever added.

**Three commands hand a secret back** — `keys generate`, `hd mnemonic` and
`hd derive` — because producing one is their purpose. They write it to stdout,
which is a place that gets redirected into scrollback, into `less`, and into
files nobody deletes. Redirect it somewhere you meant to. **A key generated here
uses this machine's RNG and is only as private as this machine**; a key meant to
hold value should be generated on the device that will keep it.

No command hands a secret back merely because one was given: `keys public` and
`crypto sign` take a private key and return only public data, and tests assert
the key is absent from both output modes.

An error never echoes a rejected secret either — the width and the reason are
what help, and stderr is redirected into logs far more often than `argv` is read.

## Output: two modes, one value

Every command prints formatted text, or the same values as JSON under `--json`.

They are not two code paths. A command returns one type whose `Serialize` *is*
the JSON contract and whose `render` is the terminal one, and a single function
decides which to write — so a field cannot exist in one mode and not the other.
`both_modes_carry_the_same_values` in each group's suite asserts it, by walking
the JSON and requiring every value to appear in the formatted output.

Three deliberate differences, each asserted rather than assumed:

- A boolean is `true`/`false` in JSON and `yes`/`no` in the terminal.
- A `null` is printed in JSON and **absent** from the terminal — a null is a fact
  a parser needs and a blank line is noise a reader does not.
- `hd derive` prints each key's addresses **as addresses**, not broken into
  version bytes and checksums. Four addresses fully taken apart times a hundred
  keys is not something anyone reads; `keys public` is where one key gets taken
  apart. `the_formatted_output_abbreviates_addresses_without_dropping_any`
  pins that it is only an abbreviation.

**The JSON carries the same keys, values and shapes as the HTTP API's response**
for the same request. Not the same bytes — this pretty-prints and the API emits
compact JSON — but `jq` cannot tell the two apart.

For the three `converter` commands the expected answers live in
`bitcoin-tools-vectors`, which holds the CLI argv, the HTTP request body and the
one response both must produce. **This crate's suite asserts against that file;
the server's does not yet.** Wiring `crates/server/tests/tools_api.rs` to it is
the other half, and it belongs to that crate's own review.

Until it lands, the asymmetry has a failure mode worth knowing: if the *server's*
output changes, the vectors go stale and the **CLI's** test is what fails. That
looks like a CLI bug and is not — check the file against both front ends before
changing anything here.

The other eleven commands are pinned against the same published vectors the
server and core use — BIP32's chains, BIP49/84/86's accounts, real mainnet
transactions, ten mainnet block headers — so both front ends are anchored to one
set of answers even where they are not compared to each other directly.

In `--json` mode **stdout carries nothing but JSON**. Diagnostics, including
every error, go to stderr — so a failing command still leaves stdout parseable,
or empty.

Colour is off automatically when stdout is not a terminal and when `NO_COLOR` is
set. `--color always|never|auto` overrides both. (clap's own help and error
output decides before `--color` is parsed, so it follows the automatic rules
only.)

## Input: arguments or a JSON file

Every command takes its request either as arguments or from a JSON file with
`--input <FILE>`, where `-` means stdin.

```console
$ echo '{"amount": "1", "denomination": "BTC"}' | bitcoin-tools converter unit --input -
$ bitcoin-tools transactions builder --input tx.json --json
```

The request shapes **are the HTTP API's request bodies**, field for field — so a
file written for one front end works with the other:

| Command | Request |
|---|---|
| `converter reverse-bytes` | `{"hex"}` |
| `converter base` | `{"value", "base"}` |
| `converter unit` | `{"amount", "denomination"}` |
| `keys generate` | `{"network"?, "compressed"?}` |
| `keys public` | `{"privateKey", "network"?, "compressed"?}` |
| `hd mnemonic` | `{"wordCount"?, "passphrase"?, "network"?}` |
| `hd derive` | `{"seed", "path", "count"?, "startIndex"?, "network"?}` |
| `transactions script` | `{"script"}` |
| `transactions splitter` | `{"tx"}` |
| `transactions builder` | `{"type", "version"?, "lockTime"?, "inputs", "outputs"}` |
| `blocks hash` / `blocks header` | `{"header"}` — one shape, shared |
| `crypto sign` | `{"privateKey", "messageHash", "compressed"?}` |
| `crypto verify` | `{"publicKey", "messageHash", "signature"}` |

The notation fields are a **superset** of what the API accepts: `base` and
`denomination` additionally take the short spellings above, which the API's
stricter serde contract refuses. A file written for the API always works with the
CLI; a file written here may not go the other way.

`transactions builder` is the one command whose flags cannot express everything
its request can. `--spend` and `--pay` build an unsigned skeleton; a `scriptSig`
or a witness stack is per-input, and a repeated flag carrying a nested list is
worse to type and to read than the JSON it would stand in for. That is a boundary
rather than a gap — this command does not sign, so the transactions it builds
from flags are exactly the unsigned ones.

Unknown fields are an error rather than silently ignored, so a typo is a
message. A request file is capped at 8,001,024 bytes — one hex payload at its
maximum, plus the envelope — so `--input -` on an endless pipe stops rather than
consuming the machine.

`--input` is also how to pass a payload too long for a shell argument: the hex
cap is 4 MB, which is `Tx::MAX_SIZE`, and a command line runs out long before
that.

## Values that must not be rounded are strings

Both directions, in both modes, including the satoshi count. A JSON number is a
double in most consumers and exact only below 2⁵³ — and `converter base` exists so
a 256-bit key can be read in decimal, while money is held in integer satoshis
precisely so `0.1 + 0.2` cannot lose one. `transactions builder --pay` takes
satoshis as a whole number for the same reason.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | The command answered. |
| 1 | It could not: bad input, an unreadable file, an unwritable stdout. |
| 2 | The arguments were wrong. clap owns this one and writes its own message. |

A **closed pipe is not a failure**. `bitcoin-tools … \| head` exits 0 and says
nothing, in both output modes and in every group.

Two answers that look like failures and are not:

- `crypto verify` exits **0** with `valid  no` for a signature that does not
  verify. That is the question the command exists to answer, and there is no
  sub-reason a caller could act on. Only bytes that are not a signature at all
  are a failure.
- `transactions script` exits **0** for a malformed script, printing everything
  that decoded with the problem beside it, because showing where it broke is the
  point. `transactions splitter` fails outright on a malformed transaction,
  because once field boundaries stop lining up there is no partial answer.

## Layout

| File | Holds |
|---|---|
| `src/main.rs` | The process boundary only: parse, run, report to stderr, exit code. |
| `src/cli.rs` | The clap `Parser`, the global flags, the six top-level groups. |
| `src/output.rs` | The `Output` trait, `Context::emit` — the only thing that writes to stdout — and the `Fields` and `Table` renderers. |
| `src/input.rs` | The hex input policy, the JSON source reader and its cap, the secret reader, the `from_str` serde helper. |
| `src/commands/` | One module per group. Each command holds `Args`, `Request`, an output type, and `run`, in that order. |
| `src/commands/address.rs` | Every address a public key produces, shared by `keys public` and `hd derive` — two places deciding which addresses exist is two places to forget BIP143. |

`src/commands/mod.rs` documents the shape a new command copies, the three ways a
command says "exactly one source", and the four rules a command touching a secret
inherits.

The two front ends' **surfaces** differ in `converter` and only there: the API
spells those `/tools/number` and `/tools/units` and takes the notation as a
required field, because a JSON body has no better option. Their **answers** do
not differ, and that is what the shared vectors pin.

**No Bitcoin logic lives here.** Hex, reversal, `Number`, `Amount`, address
derivation, BIP32 and the builder's rules are all core's. If a command needs to
hash, encode or convert something itself, the thing it needs belongs in core.

The one deliberate duplication is the hex input policy in `src/input.rs` — trim,
accept `0x`, refuse empty, cap the size — which restates the server's. The two
crates cannot share it without a fourth crate to put it in, and the part worth
not repeating, the codec, is already core's and is called from both. If a third
caller appears, it moves into core.

### Core's features

This crate declares core with `default-features = false` and turns on two:

- **`serde`**, because six of core's types cross this crate's serde boundary.
  `Category`, `ScriptFields` and `DecodeError` have no spelling this crate could
  reproduce by hand — `Category` has no `Display` at all, `ScriptFields` names
  each template's parts only in its serde attributes, and `DecodeError`'s wire
  form is a tagged object rather than the sentence its `Display` prints. Both
  front ends emit all three, so re-spelling them here is the drift the shared
  vectors exist to catch. `Network` and `TxKind` make the feature a compile
  error rather than a preference: they are fields of this crate's own request
  and response types, alongside `Purpose`.

  Not in that set: `ScriptKind`, which serializes through its own `Display`; and
  `BlockHeader`, `Tx`, `Input`, `Output` and `OutPoint`, which are only ever
  domain values on the way in — every response here is a view this crate owns,
  built from strings.
- **`rand`**, because `keys generate` and `hd mnemonic` mint a secret. Core keeps
  it off by default so a decoder cannot reach an RNG by accident, which is a
  statement about the library rather than about a tool whose job includes
  generating a key on request.

## Tests

`cargo test -p bitcoin-tools-cli`. The integration suites drive the **binary**
through `assert_cmd`, because a CLI's contract is its argument surface, its two
output modes, its streams and its exit codes — none of which are exercised by
calling `run` directly.

| Suite | Asserts |
|---|---|
| `tests/cli.rs` | The program-wide properties, across one command from every group: `--json` purity, a closed pipe, no escape codes when colour is refused, an empty stdout on failure, `--input -` everywhere. |
| `tests/blocks.rs`, `tests/hd.rs`, `tests/transactions.rs` | The published vectors — ten mainnet headers, BIP32's chains, BIP49/84/86's accounts, real mainnet transactions. |
| `tests/keys.rs`, `tests/crypto.rs` | Known keys and their addresses; sign and verify as each other's inverse; that a secret in is never a secret out. |
| `tests/converter.rs` | The shared `tools` vectors, which are the direct CLI-to-API comparison. |

`tests/cli.rs` derives its command list from the groups, so a group added without
being wired into those properties fails there rather than shipping.

## Review

Reviewed by the `rust-cli-reviewer` agent, which is forbidden from reviewing
`crates/core` and `crates/server` for critique. Run the loop with
`/cli-review`.

## License

MIT. See [LICENSE-MIT](../../LICENSE-MIT).
