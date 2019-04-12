#!/usr/bin/env python3
# Try to generate statistics for various string comparisons similar to
# https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/
import argparse
import csv
from hashlib import md5
from hmac import compare_digest
import random
import time


def equals_operator(a, b):
    a == b


def andeq(a, b):
    if len(a) != len(b):
        return False

    result = True
    for i in range(len(a)):
        result &= (a[i] == b[i])
    return result


def xor_bytes(a, b):
    if len(a) != len(b):
        return False

    result = 0
    for i in range(len(a)):
        result |= (ord(a[i]) ^ ord(b[i]))
    return result == 0


def hash_compare(a, b):
    md5(a.encode("UTF-8")) == md5(b.encode("UTF-8")) and a == b


FUNCTIONS = {
    "compare_digest": compare_digest,
    "equals_operator": equals_operator,
    "andeq": andeq,
    "xor_bytes": xor_bytes,
    "hash_compare": hash_compare
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--length", "-l", default=16, type=int)
    parser.add_argument("--out", "-o", default="times.csv")
    parser.add_argument("--num-values", "-n", default=1000000, type=int)
    args = parser.parse_args()

    length = args.length
    out = args.out
    num_values = args.num_values

    password = "a" * length
    possible_functions = list(FUNCTIONS.items())
    with open(out, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["function", "password length",
                         "first difference", "time"])
        for i in range(1, num_values + 1):
            if i % 100000 == 0:
                print("Generated %d/%d values (%d%%)" %
                      (i, num_values, i // num_values * 100))
            name, function = random.choice(possible_functions)
            first_difference = random.randint(0, length - 1)
            attempt = "".join(["b" if i >= first_difference else "a"
                               for i in range(length)])
            assert (len(password) == len(attempt)
                    and password != attempt
                    and password[:first_difference]
                    == attempt[:first_difference])
            t0 = time.perf_counter()
            function(password, attempt)
            t1 = time.perf_counter()
            elapsed = t1 - t0
            row = [name, length, first_difference, elapsed]
            writer.writerow(row)


if __name__ == "__main__":
    main()
