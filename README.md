# Cracker

A password cracker built from scratch in C. No frameworks, no abstractions, no shortcuts — every line written and understood before it was committed.

This is not a Hashcat clone. It is a ground-up implementation of the mechanics behind tools like Hashcat, built as a learning exercise in systems programming and applied cryptography. The goal was never to compete with production tools. The goal was to understand exactly what they are doing and why.

---

## What this is

`cracker` performs offline password recovery against captured hash files. You give it a file of hashes and a wordlist. It hashes every candidate, compares the result against every target, and prints matches as it finds them.

V1 ships with a fully working dictionary attack, four hash algorithms, live progress output, and clean file-based result storage. It is single-threaded and deliberately minimal — a foundation with no moving parts I do not understand.

---

## Building

**Dependencies**

- GCC or Clang
- OpenSSL (`libssl`, `libcrypto`) — for MD5, SHA-256, SHA-512
- GNU Make

On Debian / Ubuntu:
```bash
sudo apt install build-essential libssl-dev
```

On Arch:
```bash
sudo pacman -S base-devel openssl
```

On macOS (Homebrew):
```bash
brew install openssl
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
```

**Compile**
```bash
make
```

**Debug build** (with AddressSanitizer and no optimization):
```bash
make debug
```

**Clean**
```bash
make clean
```

---

## Usage

```
./cracker [options] <hashfile>

Options:
  -m <type>     Hash algorithm (default: 0)
                  0 = MD5
                  1 = SHA-256
                  2 = SHA-512
                  3 = NTLM
  -w <path>     Path to wordlist (required for dictionary attack)
  -o <path>     Write cracked pairs to file
  -v            Verbose — show live progress counter
  -h            Print this help and exit
```

**Basic dictionary attack against MD5 hashes:**
```bash
./cracker -m 0 -w rockyou.txt hashes.txt
```

**With verbose output and results saved to file:**
```bash
./cracker -m 0 -w rockyou.txt -o cracked.txt -v hashes.txt
```

**SHA-256:**
```bash
./cracker -m 1 -w rockyou.txt -v hashes.txt
```

---

## Hash file format

Two formats are supported:

```
# Bare hash
5f4dcc3b5aa765d61d8327deb882cf99

# Username:hash
admin:5f4dcc3b5aa765d61d8327deb882cf99
```

Multiple hashes in the same file are all cracked in a single pass. The program exits early if all targets are solved before the wordlist is exhausted.

---

## Output format

Results are printed to stdout as they are found:

```
5f4dcc3b5aa765d61d8327deb882cf99:password
e10adc3949ba59abbe56e057f20f883e:123456
```

If a username was present in the hash file, it is included:

```
admin:5f4dcc3b5aa765d61d8327deb882cf99:password
```

---

## Architecture

Six files. Each one has a single responsibility.

```
cracker/
├── main.c          argument parsing, program entry point
├── config.h        the Config struct shared across all modules
├── hash.c / .h     hash computation via OpenSSL
├── hashfile.c / .h reads and parses the target hash file
├── attack.c / .h   the dictionary attack loop
└── output.c / .h   result printing and file writing
```

There are no threads. There is no GPU code. There is no mmap, no lock-free queue, no SIMD. All of that comes later. V1 is the thing you read when you want to understand what the later versions are doing.

The data flow is linear:

```
argv
  -> Config struct
  -> hashfile_load() -> Target array (raw digest bytes + metadata)
  -> run_dictionary() -> fgets loop -> hash_compute() -> memcmp()
  -> output_print_crack() -> stdout + optional file
```

One design decision worth noting: target hashes are stored as raw bytes (`unsigned char digest[64]`), not hex strings. Comparison uses `memcmp`, not `strcmp`. Hash digests are binary data and can contain null bytes — `strcmp` stops at the first null and would silently miss matches on real-world hash data.

---

## Testing

A small test hash file is included at `test/hashes.txt` with five MD5 hashes. A matching test wordlist is at `test/wordlist.txt`.

```bash
./cracker -m 0 -w test/wordlist.txt -v test/hashes.txt
```

Expected output:
```
[*] Loaded 5 target hash(es)
[*] Starting dictionary attack...
5f4dcc3b5aa765d61d8327deb882cf99:password
e10adc3949ba59abbe56e057f20f883e:123456
25f9e794323b453885f5181f1b624d0b:123456789
d8578edf8458ce06fbc5bb76a58c5ca4:qwerty
827ccb0eea8a706c4c34a16891f84e7b:12345
[*] Done. 5/5 cracked.
```

To verify your hash implementation independently before running a full attack:

```bash
make test_hash
./test_hash
```

This hashes the string "password" with each supported algorithm and compares the output against known-correct values. If all four print "Match: YES", the hash engine is correct.

---

## Wordlists

`cracker` works with any plaintext wordlist, one entry per line. The standard reference wordlist for testing is `rockyou.txt` — a 133MB file containing 14 million real passwords from a 2009 breach, used throughout security research and CTF competitions.

Where to get it:
- Kali Linux ships it at `/usr/share/wordlists/rockyou.txt.gz` — decompress with `gunzip`
- SecLists on GitHub: `https://github.com/danielmiessler/SecLists` under `Passwords/`

---

## What is coming

V1 is a working foundation. The next three versions are already designed.

**V2 — More attack modes and smarter internals**

The hash switch statement gets replaced with a function pointer table (vtable). Adding a new algorithm means adding one row to a table — nothing else in the codebase changes. Brute force attack mode arrives: a mixed-radix counter enumerates every combination of characters up to a given length without any string building overhead. A rule engine applies transformations to wordlist entries automatically — capitalize, reverse, leet substitution, append digits, append symbols — turning one base word into dozens of candidates without storing any of them. Binary search on sorted targets replaces the linear scan: 10,000 hashes goes from 10,000 `memcmp` calls per candidate to approximately 14.

**V3 — Real performance**

Pthreads. The wordlist is divided into equal byte-range slices and each thread processes its own slice independently. `mmap` replaces `fgets` — the file is mapped directly into the process's address space as a byte array and the OS handles page loading. Atomic counters replace the plain progress integer so multiple threads can update it concurrently without corrupting the count.

**V4 — Polish and completeness**

Session save and restore: a checkpoint file records the exact keyspace offset so an interrupted run can resume from where it stopped. Mask attack mode: specify the exact character-class structure of a password (`?u?l?l?l?d?d` for something shaped like `Pass12`) for targeted attacks against known password policies. Benchmark mode measures hash throughput on the current hardware across all supported algorithms.

---

## What I learned building this

The implementation was the straightforward part. What took real time:

**Why you cannot decrypt a hash.** A hash function is one-way by design. What a cracker does is not decryption — it is finding a collision. Hash the candidate, compare the output. If they match, you have the password. The algorithm never runs in reverse.

**Why algorithm choice defines crackability.** MD5 runs at roughly 60 billion hashes per second on a modern GPU. bcrypt runs at around 20,000. That factor-of-three-million difference is not a bug — bcrypt was designed to be expensive. The same eight-character password goes from recoverable in seconds to unrecoverable in practice depending solely on which function hashed it.

**Why `memcmp` and not `strcmp`.** Hash digests are raw binary data. A digest can contain a null byte at position 3. `strcmp` treats null bytes as string terminators and stops there, missing the rest of the comparison. `memcmp` compares a fixed number of bytes regardless of content. One wrong function call and the cracker silently fails on real data.

**What double pointers are actually for.** To return a dynamically allocated array from a function in C, the caller passes a pointer to their pointer: `Target **targets`. The function writes the address of the new array into `*targets`. This felt completely foreign until I had to write `hashfile_load()` and there was no other way to do it.

**Why `.o` files do not belong in version control.** Object files are intermediate build artifacts produced by the compiler. They are platform-specific, auto-generated, and reproducible by anyone with the source. Committing them adds binary noise to the repository and bloat to every clone. Only commit what a human wrote.

---

## Legal

This tool is for authorized security testing, CTF competitions, and educational use only. Running it against systems or credentials you do not own or have explicit written permission to test is illegal in most jurisdictions and is not what this project is for.

Made with love by The1Dali