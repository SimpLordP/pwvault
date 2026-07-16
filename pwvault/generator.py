"""Password generation for learning Python and for rotating my own
credentials. I built this bottom up. First a 6 line loop, then real
functions, then guaranteed character coverage, and finally a secure
shuffle I wrote myself.

One design rule for this file: it never prints (outside the demo block)
and never touches disk. Pure input to output. That is what makes it easy
to import and test from anywhere.
"""

import secrets   # cryptographic randomness. The random module is banned here.
import string    # prebuilt constants like ascii_lowercase, digits, punctuation

# Module constant. The ALL_CAPS naming is the Python convention for a value
# that never changes. These are the characters that look alike when you are
# reading a password off a screen or paper and typing it by hand.
AMBIGUOUS = "0O1lI"


def remove_ambiguous(text):
    """Return text with the look alike characters stripped out.

    Notice we loop with `for ch in text`. Python can walk the characters
    of a string directly, no indexes needed. The `in` operator handles
    the membership check.
    """
    kept = ""
    for ch in text:
        if ch not in AMBIGUOUS:
            kept = kept + ch
    return kept


def generate_password(length, use_symbols=False, exclude_ambiguous=False):
    """Generate a random password with at least one character from each
    enabled class.

    The guarantee matters. Independent random picks can produce an all
    letters password just by luck, and "usually has a digit" is not a spec.
    """
    lower = string.ascii_lowercase
    upper = string.ascii_uppercase
    digits = string.digits

    # The filtering has to happen here, before any picking. Same reasoning
    # as the ValueError guard placement further down: finish computing a
    # value before anyone consumes it. If we filtered after picking, an
    # ambiguous character could already be sitting in chars.
    if exclude_ambiguous:
        lower = remove_ambiguous(lower)
        upper = remove_ambiguous(upper)
        digits = remove_ambiguous(digits)

    # One guaranteed pick per class. Note that the first three positions
    # are now predictable: always lower, upper, digit in that order. The
    # shuffle at the end exists to destroy exactly that pattern.
    chars = [secrets.choice(lower), secrets.choice(upper), secrets.choice(digits)]
    pool = lower + upper + digits

    if use_symbols:
        # This branch does two jobs. Symbols become possible (the pool)
        # and guaranteed (the append).
        pool = pool + string.punctuation
        chars.append(secrets.choice(string.punctuation))

    # Fail fast and fail loud. Before this guard existed, asking for a
    # 2 character password with symbols silently returned 4 characters,
    # because range() of a negative number simply runs zero times. A crash
    # is honest. A wrong answer travels.
    # Placement matters: this sits after the symbols block because
    # len(chars) is not final until symbols have had their chance to add
    # a fourth guaranteed pick.
    if length < len(chars):
        raise ValueError(
            f"length {length} is too short: need at least {len(chars)} "
            "to guarantee every enabled class"
        )

    # Fill the remaining slots. Using len(chars) instead of a hardcoded
    # 3 or 4 means the math adjusts itself when the symbols branch runs.
    for i in range(length - len(chars)):
        chars.append(secrets.choice(pool))

    chars = secure_shuffle(chars)
    return "".join(chars)


def chunked_password(groups, group_size, use_symbols=False, exclude_ambiguous=False):
    """Format a password like 6hL4-Vk1m-Y0pQ for reading aloud or typing
    by hand.

    This is composition, not duplication. This function is a customer of
    generate_password. Fix a bug there and this gets the fix for free.
    Also note the dashes sit at fixed positions, so they add zero
    randomness. They are purely for readability.
    """
    pw = generate_password(groups * group_size, use_symbols, exclude_ambiguous)
    pieces = []
    for i in range(groups):
        # Half open slices tile perfectly: [0:4], [4:8], [8:12]. Each one
        # starts exactly where the last one stopped. I traced this by hand
        # before I trusted it, and I recommend you do the same.
        pieces.append(pw[i * group_size:(i + 1) * group_size])
    return "-".join(pieces)


def secure_shuffle(chars):
    """Fisher-Yates shuffle using secrets.randbelow. Takes a list and
    returns it shuffled in place.

    Why not random.shuffle? The random module is a deterministic formula.
    Observe enough outputs and the whole sequence can be reconstructed,
    including this shuffle order. The secrets module pulls from the OS
    entropy pool, so there is no sequence to reconstruct.

    Why a list and not a string? Strings in Python are immutable. Trying
    chars[i] = x on a string raises a TypeError. So we unlock with list(),
    swap in place, and seal back up with join().

    Why the range shrinks (the counting argument): 3 items have 6 possible
    orderings. If every step used randbelow(3) we would get 27 equally
    likely paths, and 27 does not divide evenly by 6, so some orderings
    would come up more often than others. Shrinking gives 3 times 2 equals
    6 paths across 6 orderings. Perfectly fair. Fairness comes first and
    security is the consequence.
    """
    for i in range(len(chars) - 1, 0, -1):
        # The +1 is load bearing. randbelow(n) excludes n, but position i
        # must be allowed to swap with itself, since staying put is a
        # legal shuffle outcome. Writing randbelow(i) instead creates a
        # bias you would never spot in test output.
        j = secrets.randbelow(i + 1)
        chars[i], chars[j] = chars[j], chars[i]   # the simultaneous swap idiom
    return chars


if __name__ == "__main__":
    # Demo block. This only runs via `python -m pwvault.generator` and
    # never on import. This guard is the fence between code that defines
    # things and code that demos things.
    print(generate_password(16))
    print(generate_password(16, use_symbols=True))
    print(generate_password(30, exclude_ambiguous=True))   # scan it: no 0 O 1 l I
    print(chunked_password(4, 5, exclude_ambiguous=True))
    try:
        generate_password(2, use_symbols=True)   # impossible: 2 < 4 guaranteed
    except ValueError as e:
        # try/except is the catching side of the exception machinery. We
        # raised the error ourselves, we catch it here, and the message
        # that prints is the one we wrote in the f-string.
        print("correctly refused:", e)