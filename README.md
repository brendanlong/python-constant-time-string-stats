# Python "constant time" string comparisons

This repo contains examples of supposedly constant-time string comparison
functions, and has code to time them and to plot the times.

The stats generation code should work on any version of Python >= 2.6, but the
plotting code has only been tested on Python >= 3.6.

## Why should you care?

Read this: https://codahale.com/a-lesson-in-timing-attacks/

And then read this: https://securitypitfalls.wordpress.com/2018/08/03/constant-time-compare-in-python/

In short, if you're ever comparing two strings where one string is secret and
the other is controlled by a potential attacker, you need to make your
string comparison not depend on how close the attack's string got to yours. If
you don't do this, the amount of time it takes for you to check if their
password/token/HMAC is correct tells them *whether each character* was correct,
which enables movie-style character-by-character password cracking.

If you're on Python 2.7 or Python >= 3.3, you can solve this by doing your
comparison using [`hmac.compare_digest`](https://docs.python.org/3/library/hmac.html#hmac.compare_digest),
which is a constant-time string comparison function written in C. If you're
curious, this project can help you confirm that it is-indeed constant time.

## Functions

The functions this code implements so far are:

- `equals_operator`: This is `==`
- `compare_digest`: This is [`hmac.compare_digest`](https://docs.python.org/3/library/hmac.html#hmac.compare_digest),
  if the version of Python you're running supports it.
- `xor_bytes`: This loops over the two strings, xor's the two characters at
  each position, and logical-or's the results.
- `andeq`: This loops over the two strings and logical-and's each character.
- `hash_compare`: This hashes each string (using MD5) and then compares the
  hash. This solves the vulnerability in a different way, by making it so the
  attacker no longer controls the string to be compared.

## Terminology

- "Password" is the string we want to keep secret
- "Attempt" is the string the attacker is sending us (hoping it's equal to
  "Password")
- "Index of first difference" is the first index in the attacker's string that
  doesn't match the "password". For example, if the first 3 characters of the
  password are correct (`"pasxxxxx" == "password"`), then the index of first
  difference is 3 (`password[3] != attempt[3]`).

## Generating stats

**It's very important to run this on the actual version of Python you plan to use**.
Python code has different performance in different versions, and in particular,
Python 2 and Python 3 get wildly different results. If you need to backport
`hmac.hmac_compare` to Python 2.6, *generate the stats in Python 2.6*.

To generate a CSV of timings by function and index of first difference, run:

```bash
./stats.py -o timings.csv
```

Run with `--help` for more options.

## Generating plots

Once you have a CSV, run:

```bash
./plots.py timings.csv
```

## Interpreting the results

What we're looking for us anything that lets us distinguish between the
distributions between one index and the next. For a properly-implemented
constant-time string comparison, every box plot for the given function should
be completely identical.

## Examples

These are from my desktop, using 16-character passwords, 16,000 data
points per function, and some system settings to reduce noise:

- Booted with `isocpus=2,3 rcu_nocbs=2,3 processor_max_cstate=1 idle=poll`
- Ran `python3 -m perf system tune`
- Turned off address space randomization with `echo 0 > /proc/sys/kernel/randomize_va_space`
- Ran the actual stats collection using taskset to run tasks on a single
  isolated CPU.
- Used auto-loop calculation and 10 warmups.
- Set `PYTHONHASHSEED=1` mainly for reproducability

Example:

```bash
PYTHONHASHSEED=1 taskset -a -c 2 python2.6 ./stats.py -n 16000 -l 16 -o py26.csv
```

Python 2.6.9:

![Boxplots for Python 2.6.9](static/python2.6.9.png?raw=true)

Python 3.6.8:

![Boxplots for Python 3.6.8](static/python3.6.8.png?raw=true)