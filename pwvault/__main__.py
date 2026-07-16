"""
CLI entry point. This runs on `python -m pwvault`, the same -m machinery as python -m venv. 
One design rule carried through the project is this is the only file allowed to print during normal operation.
"""

import argparse

from .generator import generate_password, chunked_password
# Relative import. The dot means "from this same package". This structure
# cannot produce the circular import crash we hit back when gen.py tried
# to import itself.

parser = argparse.ArgumentParser(
    prog="pwvault",
    description="Generate strong passwords offline. Output goes to your "
    "screen and nowhere else. Copy it into your own records.",
)
parser.add_argument("length", type=int, nargs="?", default=20,
                    help="password length (default: 20)")
parser.add_argument("--symbols", action="store_true",
                    help="include and guarantee punctuation")
parser.add_argument("--no-ambiguous", action="store_true",
                    help="exclude 0 O 1 l I for passwords typed by hand")
parser.add_argument("--chunked", action="store_true",
                    help="format as XXXX-XXXX-XXXX-XXXX for readability")
parser.add_argument("--count", type=int, default=1,
                    help="how many passwords to generate (default: 1)")

args = parser.parse_args()

for _ in range(args.count):     # underscore is the convention for an unused loop variable
    if args.chunked:
        # In chunked mode the length is reinterpreted as 4 character
        # groups, rounded down. Feel free to change the group size.
        print(chunked_password(max(args.length // 4, 2), 4,
                               args.symbols, args.no_ambiguous))
    else:
        print(generate_password(args.length, args.symbols, args.no_ambiguous))