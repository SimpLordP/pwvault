# pwvault

A command line password generator I built to learn Python. It generates
strong random passwords using the `secrets` module, guarantees at least
one character from every enabled character class, and can strip out look
alike characters like 0, O, 1, l, and I for passwords you have to type
by hand.

**Honest disclaimer up front:** this is a learning project. It does what
it says, and I can explain every line of it, but if you need to store
real secrets, use an established tool like KeePassXC or pass. This
project exists because building something real teaches you more than
exercises do.

## What it does

- Generates cryptographically secure passwords using `secrets`, never `random`
- Guarantees at least one lowercase, uppercase, and digit in every password
  (and a symbol, if you enable symbols)
- Optional exclusion of ambiguous characters for hand typed passwords
- Chunked output like `6hL4-Vk1m-Y0pQ` for readability
- Batch generation with `--count`
- Fails loudly with a clear error if you ask for something impossible,
  like a 2 character password that has to contain 4 character classes

## Setup

You will need Python 3.10 or newer.

    git clone https://github.com/YOURUSERNAME/pwvault.git
    cd pwvault
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## Usage

    python -m pwvault                        # one 20 character password
    python -m pwvault 30 --symbols           # longer, with symbols
    python -m pwvault 16 --no-ambiguous      # safe to read off paper
    python -m pwvault 16 --chunked           # grouped with dashes
    python -m pwvault --count 5              # five at once
    python -m pwvault --help                 # full options

## What I learned building this

The two bugs that taught me the most:

**The shuffle bias.** The `secrets` module has no shuffle function, so I
implemented Fisher-Yates myself with `secrets.randbelow`. The interesting
part is why the random range has to shrink each step. Three items have 6
possible orderings. If every step picks from the full range you get 27
equally likely paths, and 27 does not divide evenly by 6, so some
orderings come up more often than others. Shrinking the range gives
exactly one path per ordering. The bias is invisible in test output,
which is what makes it dangerous.

**The silent length failure.** Asking for a 2 character password with 4
guaranteed classes used to quietly return 4 characters, because
`range()` of a negative number runs zero times. No crash, just a wrong
answer. That is the worst kind of bug because it travels. The fix was a
`ValueError` guard that refuses impossible requests at the boundary.

There is also a working encrypted vault module in here (`vault.py`)
using scrypt and Fernet from the `cryptography` package. The current
tool does not use it, but I kept it because building it taught me the
key derivation chain, and it is the answer if I ever want encrypted
storage later.

## License

MIT. See the LICENSE file.
