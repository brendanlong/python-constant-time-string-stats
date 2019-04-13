#!/usr/bin/env python3
# Try to generate statistics for various string comparisons similar to
# https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/
import argparse
import csv
from hashlib import md5  # noqa
import hmac
import os
import random
import string


# Use xrange in Python 2 and range in Python 3
try:
    range = xrange  # type: ignore
except NameError:
    pass


try:
    from time import perf_counter
except ImportError:
    # perfcounter backport from https://gist.github.com/zed/5073409
    import ctypes
    import errno
    from ctypes.util import find_library

    CLOCK_MONOTONIC_RAW = 4

    clockid_t = ctypes.c_int
    time_t = ctypes.c_long

    class timespec(ctypes.Structure):
        _fields_ = [
            ('tv_sec', time_t),         # seconds
            ('tv_nsec', ctypes.c_long)  # nanoseconds
        ]

    _clock_gettime = (
        ctypes.CDLL(find_library('rt'), use_errno=True)  # type: ignore
        .clock_gettime)
    _clock_gettime.argtypes = [clockid_t, ctypes.POINTER(timespec)]

    def perf_counter():
        # type: () -> float
        tp = timespec()
        if _clock_gettime(CLOCK_MONOTONIC_RAW, ctypes.byref(tp)) < 0:
            err = ctypes.get_errno()
            msg = errno.errorcode[err]
            if err == errno.EINVAL:
                msg += (" The clk_id specified is not supported on this system"
                        " clk_id=%r") % (CLOCK_MONOTONIC_RAW,)
            raise OSError(err, msg)
        return tp.tv_sec + tp.tv_nsec * 1e-9


def random_string(length):
    # type: (int) -> str
    return "".join([random.choice(string.ascii_letters)
                    for _ in range(length)])


def equals_operator(a, b):
    # type: (str, str) -> bool
    return a == b


def andeq(a, b):
    # type: (str, str) -> bool
    if len(a) != len(b):
        return False

    result = True
    for i in range(len(a)):
        result &= (a[i] == b[i])
    return result


def xor_bytes(a, b):
    # type: (str, str) -> bool
    if len(a) != len(b):
        return False

    result = 0
    for i in range(len(a)):
        result |= (ord(a[i]) ^ ord(b[i]))
    return result == 0


def hash_compare(a, b):
    # type: (str, str) -> bool
    # This function works by preventing the attacker from controlling the
    # two strings we're comparing
    # Without a random salt, an attacker could still perform a timing attack
    # to leak the hash
    salt = os.urandom(8)
    return (hmac.new(salt, a.encode("UTF-8")).digest()
            == hmac.new(salt, b.encode("UTF-8")).digest()
            and a == b)


FUNCTIONS = {
    "equals_operator": equals_operator,
    "andeq": andeq,
    "xor_bytes": xor_bytes,
    "hash_compare": hash_compare
}

try:
    from hmac import compare_digest
    FUNCTIONS["compare_digest"] = compare_digest
except ImportError:
    pass


def main():
    # type: () -> None
    function_names = list(FUNCTIONS.keys())

    parser = argparse.ArgumentParser()
    parser.add_argument("--length", "-l", default=16, type=int,
                        help="The length of the 'password' to test with")
    parser.add_argument("--out", "-o", default="times.csv",
                        help="The CSV file to generate. Note that this file "
                        "will be overwritten if it exists.")
    parser.add_argument("--num-values", "-n", default=1000000, type=int,
                        help="The number of data points to generate")
    parser.add_argument("functions",
                        default=function_names,
                        nargs="*")
    args = parser.parse_args()

    length = args.length
    out = args.out
    num_values = args.num_values

    possible_functions = args.functions
    with open(out, "w") as f:
        writer = csv.writer(f)
        writer.writerow(["function", "password length",
                         "first difference", "time"])
        for i in range(1, num_values + 1):
            if i % 100000 == 0:
                print("Generated %d/%d values (%d%%)" %
                      (i, num_values, int(i * 100 / num_values)))

            name = random.choice(possible_functions)
            function = FUNCTIONS[name]
            a = random_string(length)
            first_difference = random.randint(0, length - 1)
            b = a[:first_difference] + random_string(length - first_difference)
            while b[first_difference] == a[first_difference]:
                b = "".join([
                    random.choice(string.ascii_letters)
                    if i == first_difference
                    else c
                    for i, c in enumerate(b)])
            assert (len(a) == len(b)
                    and a != b
                    and a[:first_difference]
                    == b[:first_difference]
                    and a[first_difference] != b[first_difference])
            t0 = perf_counter()
            function(a, b)
            t1 = perf_counter()
            elapsed = t1 - t0
            row = [name, length, first_difference, elapsed]
            writer.writerow(row)


if __name__ == "__main__":
    main()
