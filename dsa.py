#!/usr/bin/env python3

"""
dsa.py
"""

from Crypto.Util.number import getPrime, isPrime
import secrets
import hashlib
import time
import csv
from typing import Tuple, Union, Optional, List

# ---------------------------
# Internal
# ---------------------------

# Convert a message to an integer in [0, q-1]:
# . int -> module q
# . bytes/str -> SHA-1 -> int -> module q
def _msg_to_int(message: Union[int, bytes, str], q: int) -> int:
    if isinstance(message, int):
        return message % q
    if isinstance(message, (bytes, bytearray)):
        h = hashlib.sha1(message).digest()
        return int.from_bytes(h, 'big') % q
    if isinstance(message, str):
        return _msg_to_int(message.encode('utf-8'), q)
    raise TypeError("message must be int, bytes or str")

# Extended Euclidean Algorithm: modular inverse a^{-1} mod m, used as a fallback if pow(..., -1, mod) is not available
def _modinv(a: int, m: int) -> int:
    a = a % m
    if a == 0:
        raise ValueError("Inverse does not exist")
    lm, hm = 1, 0
    low, high = a, m
    while low > 1:
        r = high // low
        nm = hm - lm * r
        new = high - low * r
        hm, lm = lm, nm
        high, low = low, new
    return lm % m

# ---------------------------
# 1. get_DSAparameters(n)
# ---------------------------

# Generate and return (p, q, g) for DSA:
# . q: n-bit prime
# . p: prime such that p-1 = k*q (k increasing)
# . g: generator of subgroup of order q: g = h^{(p-1)//q} mod p, with g > 1
def get_DSAparameters(n: int) -> Tuple[int, int, int]:
    assert isinstance(n, int) and n >= 2, "n must be integer >= 2 (bits for q)"

    q = getPrime(n)
    k = 1
    while True:
        p_candidate = k * q + 1
        if isPrime(p_candidate):
            p = p_candidate
            break
        k += 1

    g = 1
    while g == 1:
        h = secrets.randbelow(p - 3) + 2
        g = pow(h, (p - 1) // q, p)

    assert isPrime(q)
    assert isPrime(p)
    assert (p - 1) % q == 0
    assert g > 1

    return p, q, g

# ---------------------------
# 2. get_skeys(p, q, g)
# ---------------------------

# Generate and return (x, y):
# . x: private session key in [1, q-1] using secrets (secure)
# . y: public key = g^x mod p
def get_skeys(p: int, q: int, g: int) -> Tuple[int, int]:
    assert isPrime(q) and isPrime(p) and ((p - 1) % q == 0)
    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)
    return x, y

# ---------------------------
# 3. dsa_sign(message, p, q, g, x)
# ---------------------------

# Sign a message with DSA and return (r, s)
# k is generated internally with secrets; not returned
def dsa_sign(message: Union[int, bytes, str], p: int, q: int, g: int, x: int) -> Tuple[int, int]:
    assert 0 < x < q
    m_int = _msg_to_int(message, q)

    while True:
        k = secrets.randbelow(q - 1) + 1
        r = pow(g, k, p) % q
        if r == 0:
            continue
        try:
            k_inv = pow(k, -1, q)
        except TypeError:
            k_inv = _modinv(k, q)
        s = (k_inv * (m_int + x * r)) % q
        if s == 0:
            continue
        return r, s

# ---------------------------
# 4. dsa_verify(message, signature, p, q, g, y)
# ---------------------------

# Verify DSA signature: returns True if valid, False otherwise
# Signature must be a tuple (r, s)
def dsa_verify(message: Union[int, bytes, str], signature: Tuple[int, int],
               p: int, q: int, g: int, y: int) -> bool:

    r, s = signature
    if not (0 < r < q and 0 < s < q):
        return False
    m_int = _msg_to_int(message, q)
    try:
        w = pow(s, -1, q)
    except TypeError:
        w = _modinv(s, q)
    u1 = (m_int * w) % q
    u2 = (r * w) % q
    v = (pow(g, u1, p) * pow(y, u2, p) % p) % q
    return v == r

# ---------------------------
# 5. get_private_key(y, g, p)
# ---------------------------

# Recover x by brute force testing x = 1..p-1 until pow(g, x, p) == y
# Returns x if found, else None
def get_private_key(y: int, g: int, p: int) -> Optional[int]:
    for x in range(1, p):
        if pow(g, x, p) == y:
            return x
    return None

# Brute-force is limited to [1, q-1], useful to compare times and demonstrate why using q is preferable
def get_private_key_with_q(y: int, g: int, p: int, q: int) -> Optional[int]:
    for x in range(1, q):
        if pow(g, x, p) == y:
            return x
    return None

# ---------------------------
# 6.a. dsa_sign_with_k
# ---------------------------

# Sign a message using a provided k (forced reuse), useful to demonstrate the vulnerability of reused k
def dsa_sign_with_k(message: Union[int, bytes, str], p: int, q: int, g: int, x: int, k: int) -> Tuple[int, int]:
    assert 0 < k < q
    m_int = _msg_to_int(message, q)
    r = pow(g, k, p) % q
    if r == 0:
        raise ValueError("Invalid r (0)")
    try:
        k_inv = pow(k, -1, q)
    except TypeError:
        k_inv = _modinv(k, q)
    s = (k_inv * (m_int + x * r)) % q
    if s == 0:
        raise ValueError("Invalid s (0)")
    return r, s

# ---------------------------
# 6.b. recover_private_key_from_reused_k
# ---------------------------

# Recover x when two signatures use the same k for messages m1 and m2
# Formula: x = (s2*m1 - s1*m2) * inv(r*(s1 - s2), q) mod q
def recover_private_key_from_reused_k(m1: int, m2: int, s1: int, s2: int, r: int, q: int) -> int:
    numerator = (s2 * m1 - s1 * m2) % q
    denominator = (r * (s1 - s2)) % q
    try:
        denom_inv = pow(denominator, -1, q)
    except TypeError:
        denom_inv = _modinv(denominator, q)
    x = (numerator * denom_inv) % q
    return x

# ---------------------------
# Helpers
# ---------------------------

# Measure brute-force time using get_private_key (1..p-1)
def brute_force_time_to_recover(y: int, g: int, p: int) -> float:
    start = time.perf_counter()
    _ = get_private_key(y, g, p)
    end = time.perf_counter()
    return end - start

# Measure brute-force time limited to [1..q-1]
def brute_force_time_with_q(y: int, g: int, p: int, q: int) -> float:
    start = time.perf_counter()
    _ = get_private_key_with_q(y, g, p, q)
    end = time.perf_counter()
    return end - start

# ---------------------------
# Tests and output
# ---------------------------

# Run tests for each q size in 'sizes'
def run_tests_and_save(sizes: List[int], csv_filename: str) -> List[Tuple[int,int,int,int,float,float,bool]]:
    results = []
    with open(csv_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['n_bits_q','p_bits','q_bits','p','q','time_bruteforce_p_s','time_bruteforce_q_s','recovered_ok'])
        for n in sizes:
            p, q, g = get_DSAparameters(n)
            x, y = get_skeys(p, q, g)

            k = secrets.randbelow(q - 1) + 1
            m1 = 1001
            m2 = 2002
            r1, s1 = dsa_sign_with_k(m1, p, q, g, x, k)
            r2, s2 = dsa_sign_with_k(m2, p, q, g, x, k)
            assert r1 == r2
            recovered_x = recover_private_key_from_reused_k(m1, m2, s1, s2, r1, q)
            recovered_ok = (recovered_x == x)

            time_p = brute_force_time_to_recover(y, g, p)
            time_q = brute_force_time_with_q(y, g, p, q)

            writer.writerow([n, p.bit_length(), q.bit_length(), p, q, f"{time_p:.6f}", f"{time_q:.6f}", recovered_ok])
            results.append((n, p, q, p.bit_length(), time_p, time_q, recovered_ok))
    return results

# ---------------------------
# Example
# ---------------------------

# Quick demo to check functionality
def demo_small():
    print("Demo small run:")
    n = 12
    p, q, g = get_DSAparameters(n)
    print("p,q,g:", p, q, g)
    x, y = get_skeys(p, q, g)
    print("x,y:", x, y)
    message = "DSA Test"
    sig = dsa_sign(message, p, q, g, x)
    print("signature:", sig)
    ok = dsa_verify(message, sig, p, q, g, y)
    print("verify:", ok)

if __name__ == "__main__":
    sizes = [12, 14, 16]
    csv_file = "dsa_test_results.csv"
    print(f"Running tests for sizes {sizes} - results will be saved to {csv_file}")
    results = run_tests_and_save(sizes, csv_file)
    print("Done. Results (n, p_bits, time_p, time_q, recovered_ok):")
    for r in results:
        print(r)