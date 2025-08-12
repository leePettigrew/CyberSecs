#!/usr/bin/env python3
"""
Session 1 — Securing Data: Python demonstrations
Author: You :)
Warning: Educational code. Do NOT roll your own crypto in production.
Use battle-tested libraries (e.g., libsodium, pyca/cryptography) for real systems.

This script showcases:
  1) Hashing & salting (SHA-256, PBKDF2, scrypt) + verification
  2) Dictionary vs rainbow-table concept (toy)
  3) Brute-force keyspace math + visual estimates
  4) Key stretching cost demo (PBKDF2 iteration timing)
  5) Diffie–Hellman key exchange (real math) + HMAC for integrity
  6) Toy RSA (teeny primes) for encryption + digital signatures (for intuition ONLY)
  7) Challenge–response (passkey-style) using the toy RSA flow
  8) Secure delete demo (overwrite then remove) — *best-effort* on this filesystem

Dependencies: only Python stdlib + matplotlib (for charts).
"""

import base64
import hashlib
import hmac
import math
import os
import random
import secrets
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Tuple, Dict, List, Optional

# Matplotlib is used for simple visualizations
import matplotlib.pyplot as plt


# ------------------------------
# 1) HASHING & SALTING HELPERS
# ------------------------------

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def blake2b_hex(data: bytes, digest_size: int = 32) -> str:
    return hashlib.blake2b(data, digest_size=digest_size).hexdigest()

def pbkdf2_hash(password: str, salt: bytes, iterations: int = 200_000, dklen: int = 32) -> str:
    """PBKDF2-HMAC-SHA256. Returns base64-encoded derived key."""
    dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, iterations, dklen=dklen)
    return base64.b64encode(dk).decode('ascii')

def scrypt_hash(password: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1, dklen: int = 32) -> str:
    """hashlib.scrypt KDF. Returns base64-encoded derived key."""
    dk = hashlib.scrypt(password.encode('utf-8'), salt=salt, n=n, r=r, p=p, dklen=dklen)
    return base64.b64encode(dk).decode('ascii')

def make_salted_record(password: str, scheme: str = "pbkdf2", **params) -> str:
    """
    Produce a salted, parameterized password record string.
    Format examples:
      pbkdf2$iter=200000$<base64salt>$<base64dk>
      scrypt$n=16384$r=8$p=1$<base64salt>$<base64dk>
    """
    salt = secrets.token_bytes(16)
    b64salt = base64.b64encode(salt).decode('ascii')
    if scheme == "pbkdf2":
        iterations = params.get("iterations", 200_000)
        dk = pbkdf2_hash(password, salt, iterations=iterations)
        return f"pbkdf2$iter={iterations}${b64salt}${dk}"
    elif scheme == "scrypt":
        n = params.get("n", 2**14)
        r = params.get("r", 8)
        p = params.get("p", 1)
        dk = scrypt_hash(password, salt, n=n, r=r, p=p)
        return f"scrypt$n={n}$r={r}$p={p}${b64salt}${dk}"
    else:
        raise ValueError("Unknown scheme")

def verify_password(password: str, record: str) -> bool:
    try:
        parts = record.split('$')
        scheme = parts[0]
        if scheme == "pbkdf2":
            iter_part = parts[1]
            iterations = int(iter_part.split('=')[1])
            salt = base64.b64decode(parts[2])
            expected = parts[3]
            actual = pbkdf2_hash(password, salt, iterations=iterations)
            return secrets.compare_digest(actual, expected)
        elif scheme == "scrypt":
            n = int(parts[1].split('=')[1])
            r = int(parts[2].split('=')[1])
            p = int(parts[3].split('=')[1])
            salt = base64.b64decode(parts[4])
            expected = parts[5]
            actual = scrypt_hash(password, salt, n=n, r=r, p=p)
            return secrets.compare_digest(actual, expected)
        else:
            return False
    except Exception:
        return False


# ---------------------------------------------------
# 2) DICTIONARY / RAINBOW-TABLE TOY DEMONSTRATION
# ---------------------------------------------------

COMMON_PASSWORDS = [
    "123456", "password", "qwerty", "111111", "abc123",
    "letmein", "monkey", "dragon", "iloveyou", "sunshine",
    "trustno1", "football", "welcome", "ninja", "princess",
    "baseball", "password1", "admin", "login", "starwars"
]

def make_toy_rainbow_table(words: List[str]) -> Dict[str, str]:
    """Return dict {sha256_hex(password): password} (no salt)."""
    table = {}
    for w in words:
        table[sha256_hex(w.encode('utf-8'))] = w
    return table

def rainbow_lookup(hash_hex: str, table: Dict[str, str]) -> Optional[str]:
    return table.get(hash_hex)


# ------------------------------------------
# 3) BRUTE-FORCE KEYSPACE & TIME ESTIMATES
# ------------------------------------------

def keyspace_size(charset_size: int, length: int) -> int:
    return charset_size ** length

def estimate_crack_time_seconds(keyspace: int, guesses_per_second: float) -> float:
    """Expected time for uniform random guess = keyspace/2 / rate."""
    return (keyspace / 2.0) / guesses_per_second

def humanize_seconds(seconds: float) -> str:
    units = [("year", 365*24*3600), ("day", 24*3600), ("hour", 3600), ("minute", 60), ("second", 1)]
    parts = []
    s = int(seconds)
    for name, size in units:
        if s >= size:
            qty, s = divmod(s, size)
            parts.append(f"{qty} {name}{'' if qty == 1 else 's'}")
        if len(parts) >= 2:  # keep it concise
            break
    if not parts:
        return f"{seconds:.3f} seconds"
    return " ~ ".join(parts)

def plot_keyspace_vs_length(charset_size: int, max_len: int = 12, guesses_per_second: float = 1e9, outfile: Optional[Path] = None):
    lengths = list(range(1, max_len + 1))
    expected_seconds = [estimate_crack_time_seconds(keyspace_size(charset_size, L), guesses_per_second) for L in lengths]
    years = [s / (365*24*3600) for s in expected_seconds]

    plt.figure()
    plt.yscale('log')
    plt.xlabel("Password length")
    plt.ylabel("Expected crack time (years, log scale)")
    plt.title(f"Brute-force (charset size={charset_size}, {guesses_per_second:.0f} guesses/sec)")
    plt.plot(lengths, years, marker='o')
    plt.grid(True, which='both', ls='--', alpha=0.5)
    if outfile:
        plt.savefig(outfile, bbox_inches='tight')
    else:
        plt.show()
    plt.close()


# ------------------------------------------------
# 4) PBKDF2 COST CURVE (KEY STRETCHING TIMING)
# ------------------------------------------------

def time_pbkdf2_iterations(sample_password: str = "CorrectHorseBatteryStaple!", sample_salt: bytes = b"NaCl", iterations_list: List[int] = [50_000, 100_000, 200_000, 400_000, 800_000]) -> List[Tuple[int, float]]:
    results = []
    for iters in iterations_list:
        t0 = time.time()
        _ = hashlib.pbkdf2_hmac('sha256', sample_password.encode('utf-8'), sample_salt, iters, dklen=32)
        dt = time.time() - t0
        results.append((iters, dt))
    return results

def plot_pbkdf2_cost_curve(results: List[Tuple[int, float]], outfile: Optional[Path] = None):
    its = [r[0] for r in results]
    secs = [r[1] for r in results]
    plt.figure()
    plt.plot(its, secs, marker='o')
    plt.xlabel("PBKDF2 iterations")
    plt.ylabel("Time (seconds)")
    plt.title("Key stretching — PBKDF2 timing")
    plt.grid(True, ls='--', alpha=0.5)
    if outfile:
        plt.savefig(outfile, bbox_inches='tight')
    else:
        plt.show()
    plt.close()


# ----------------------------------------------
# 5) DIFFIE–HELLMAN + HMAC (AUTHENTICATION)
# ----------------------------------------------

# A small (educational) 2048-bit safe prime could be used, but that's large to display.
# We'll use a well-known 1536-bit MODP group from RFC 3526 for realism without huge cost.
RFC3526_GROUP_5_P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A36210000000000090563"
)
RFC3526_GROUP_5_P = int(RFC3526_GROUP_5_P_HEX, 16)
RFC3526_GROUP_5_G = 2

@dataclass
class DHParty:
    p: int
    g: int
    priv: int
    pub: int

def dh_generate(p: int = RFC3526_GROUP_5_P, g: int = RFC3526_GROUP_5_G) -> DHParty:
    priv = secrets.randbits(256)  # private exponent
    pub = pow(g, priv, p)
    return DHParty(p=p, g=g, priv=priv, pub=pub)

def dh_shared_key(a: DHParty, b_pub: int) -> bytes:
    shared = pow(b_pub, a.priv, a.p)
    # Derive a 256-bit key from the shared secret
    return hashlib.sha256(shared.to_bytes((shared.bit_length()+7)//8, 'big')).digest()

def demo_diffie_hellman_hmac():
    alice = dh_generate()
    bob = dh_generate()
    ak = dh_shared_key(alice, bob.pub)
    bk = dh_shared_key(bob, alice.pub)
    assert ak == bk, "Shared keys mismatch — something went wrong."

    message = "Hello from Alice to Bob — authenticated with HMAC.".encode("utf-8")
    tag = hmac.new(ak, message, hashlib.sha256).hexdigest()
    verified = hmac.compare_digest(tag, hmac.new(bk, message, hashlib.sha256).hexdigest())
    return {
        "alice_pub": alice.pub,
        "bob_pub": bob.pub,
        "shared_key_b64": base64.b64encode(ak).decode('ascii'),
        "message": message.decode('utf-8'),
        "hmac_sha256": tag,
        "verified": verified,
    }


# ----------------------------------------------
# 6) TOY RSA (FOR INTUITION ONLY)
# ----------------------------------------------

def is_prime(n: int) -> bool:
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    r = int(n**0.5) + 1
    for d in range(3, r, 2):
        if n % d == 0:
            return False
    return True

def gen_small_prime(start: int = 2000, end: int = 5000) -> int:
    while True:
        x = random.randrange(start, end)
        if is_prime(x):
            return x

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    if b == 0:
        return (a, 1, 0)
    g, x, y = egcd(b, a % b)
    return (g, y, x - (a // b) * y)

def modinv(a: int, m: int) -> int:
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

@dataclass
class RSAKeyPair:
    n: int
    e: int
    d: int

def toy_rsa_keygen() -> RSAKeyPair:
    # Tiny primes for speed. DO NOT use this for real security.
    p = gen_small_prime()
    q = gen_small_prime()
    while q == p:
        q = gen_small_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    if math.gcd(e, phi) != 1:
        # fall back to small e
        e = 3
        while math.gcd(e, phi) != 1:
            e += 2
    d = modinv(e, phi)
    return RSAKeyPair(n=n, e=e, d=d)

def rsa_encrypt(m: int, pub_n: int, pub_e: int) -> int:
    return pow(m, pub_e, pub_n)

def rsa_decrypt(c: int, priv_n: int, priv_d: int) -> int:
    return pow(c, priv_d, priv_n)

def rsa_sign(message: bytes, priv_n: int, priv_d: int) -> int:
    # Sign the SHA-256 hash integer
    h = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    return pow(h, priv_d, priv_n)

def rsa_verify(message: bytes, sig: int, pub_n: int, pub_e: int) -> bool:
    h = int.from_bytes(hashlib.sha256(message).digest(), 'big')
    return pow(sig, pub_e, pub_n) == h % pub_n

def demo_toy_rsa_flow():
    keys = toy_rsa_keygen()
    msg = b"hi gf <3 (toy RSA demo)"
    # Encrypt small integer form (NOT real padding, just for intuition)
    m_int = int.from_bytes(msg, 'big')
    if m_int >= keys.n:
        # If too big for our tiny n, just hash then encrypt hash to visualize
        m_int = int.from_bytes(hashlib.sha256(msg).digest(), 'big') % keys.n
    c = rsa_encrypt(m_int, keys.n, keys.e)
    m2 = rsa_decrypt(c, keys.n, keys.d)
    # Signature
    sig = rsa_sign(msg, keys.n, keys.d)
    verified = rsa_verify(msg, sig, keys.n, keys.e)
    return {
        "n": keys.n, "e": keys.e, "d": keys.d,
        "cipher_int": c, "plain_int_recovered": m2,
        "signature_int": sig, "signature_valid": verified
    }


# -------------------------------------------------------
# 7) PASSKEY-LIKE CHALLENGE–RESPONSE (TOY, USING RSA)
# -------------------------------------------------------

def demo_challenge_response():
    keys = toy_rsa_keygen()
    public = (keys.n, keys.e)
    private = (keys.n, keys.d)

    # Server issues a random challenge
    challenge = secrets.token_bytes(32)
    # "Device" signs challenge with private key
    sig = rsa_sign(challenge, private[0], private[1])
    # Server verifies with public key
    ok = rsa_verify(challenge, sig, public[0], public[1])

    return {
        "public_n": public[0], "public_e": public[1],
        "challenge_b64": base64.b64encode(challenge).decode('ascii'),
        "signature_int": sig,
        "verified": ok
    }


# ---------------------------------
# 8) SECURE DELETE (BEST-EFFORT)
# ---------------------------------

def secure_delete(path: Path, passes: int = 2):
    """
    Overwrite file contents with random bytes, fsync, then remove.
    Note: effectiveness varies by filesystem, SSD wear-leveling, etc.
    """
    if not path.exists() or not path.is_file():
        return False
    size = path.stat().st_size
    try:
        with open(path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
        # Truncate to 0 and remove
        with open(path, 'r+b') as f:
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())
        path.unlink()
        return True
    except Exception:
        return False


# ------------------------------
# HIGH-LEVEL DEMO RUNNER (CLI)
# ------------------------------

def demo_hashing_and_salts():
    print("\n=== Hashing & Salting Demo ===")
    pwd = "Puppy123!"
    # Two users with the same password get different records
    rec1 = make_salted_record(pwd, scheme="pbkdf2", iterations=200_000)
    rec2 = make_salted_record(pwd, scheme="pbkdf2", iterations=200_000)
    print("User A record:", rec1)
    print("User B record:", rec2)
    print("Verify correct password A:", verify_password(pwd, rec1))
    print("Verify wrong password A:", verify_password("Puppy124!", rec1))

def demo_rainbow_vs_salt():
    print("\n=== Rainbow Table Concept (Toy) ===")
    table = make_toy_rainbow_table(COMMON_PASSWORDS)
    target = "dragon"
    stolen_hash = sha256_hex(target.encode('utf-8'))
    recovered = rainbow_lookup(stolen_hash, table)
    print("Stolen sha256:", stolen_hash)
    print("Lookup result (no salt):", recovered)

    # With salt (toy): the hash becomes unpredictable to precomputation
    salt = b"XY"
    salted = sha256_hex(salt + target.encode('utf-8'))
    recovered2 = rainbow_lookup(salted, table)
    print("Salted sha256(salt||pwd):", salted)
    print("Lookup result with salt (should be None):", recovered2)

def demo_bruteforce_plot(outdir: Path):
    print("\n=== Brute-force keyspace & time (plot) ===")
    # Typical charsets
    # Digits: 10, lower:26, upper:26, symbols: ~32 (varies)
    charsets = {
        "digits(10)": 10,
        "lower(26)": 26,
        "lower+upper(52)": 52,
        "alnum(62)": 62,
        "alnum+symbols(~94)": 94
    }
    guesses_per_second = 1e9  # 1 billion guesses/s (aggressive attacker GPU rig)
    for name, size in charsets.items():
        outfile = outdir / f"bf_{size}.png"
        plot_keyspace_vs_length(size, max_len=14, guesses_per_second=guesses_per_second, outfile=outfile)
        print(f"Saved {name} curve to {outfile}")

def demo_pbkdf2_cost(outdir: Path):
    print("\n=== PBKDF2 key-stretching timing (plot) ===")
    results = time_pbkdf2_iterations()
    for iters, secs in results:
        print(f"Iterations={iters:,} -> {secs:.4f}s")
    outfile = outdir / "pbkdf2_cost.png"
    plot_pbkdf2_cost_curve(results, outfile=outfile)
    print(f"Saved PBKDF2 cost curve to {outfile}")

def demo_dh_hmac():
    print("\n=== Diffie–Hellman + HMAC Demo ===")
    info = demo_diffie_hellman_hmac()
    print("Alice public:", info["alice_pub"])
    print("Bob public  :", info["bob_pub"])
    print("Shared key (b64):", info["shared_key_b64"])
    print("Message:", info["message"])
    print("HMAC tag:", info["hmac_sha256"])
    print("Verified:", info["verified"])

def demo_rsa_and_signatures():
    print("\n=== Toy RSA (DO NOT USE FOR REAL SECURITY) ===")
    info = demo_toy_rsa_flow()
    print("n:", info["n"])
    print("e:", info["e"])
    print("d:", info["d"])
    print("cipher_int:", info["cipher_int"])
    print("plain_int_recovered:", info["plain_int_recovered"])
    print("signature_int:", info["signature_int"])
    print("signature_valid:", info["signature_valid"])

def demo_passkey_style():
    print("\n=== Challenge–Response (Passkey-style, toy RSA) ===")
    info = demo_challenge_response()
    print("Public (n,e):", (info["public_n"], info["public_e"]))
    print("Challenge (b64):", info["challenge_b64"])
    print("Signature (int):", info["signature_int"])
    print("Verified:", info["verified"])

def demo_secure_delete(outdir: Path):
    print("\n=== Secure Delete (best-effort) ===")
    secret_path = outdir / "secret_demo.bin"
    data = os.urandom(1024 * 64)  # 64 KB
    secret_path.write_bytes(data)
    print("Wrote secret file:", secret_path, "size:", secret_path.stat().st_size)
    ok = secure_delete(secret_path, passes=2)
    print("Secure delete ok:", ok, "| Exists after?:", secret_path.exists())

def main():
    outdir = Path("session1_outputs")
    outdir.mkdir(exist_ok=True)
    demo_hashing_and_salts()
    demo_rainbow_vs_salt()
    demo_bruteforce_plot(outdir)
    demo_pbkdf2_cost(outdir)
    demo_dh_hmac()
    demo_rsa_and_signatures()
    demo_passkey_style()
    demo_secure_delete(outdir)
    print("\nDone. Charts in:", outdir.resolve())

if __name__ == "__main__":
    main()
