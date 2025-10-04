#!/usr/bin/env python3

from math import ceil, sqrt
from Crypto.Util.number import getPrime, isPrime
import random
import time
import plotly.express as px
import hashlib
from typing import Tuple, Union, Optional

def main():
    choice = ''
    while choice != 'q':
        print("Select the test to run:")
        print("1. Basic DSA test with a user-specified size of p (in bits)")
        print("2. Basic DSA test with private key recovery with a user-specified size of p (in bits). Comparison of time taken between brute force and baby-step giant-step")
        print("3. Get x from k, when two messages are signed with the same k for a user-specified size of p (in bits)")
        print("4. Time taken to get x for a range of n and plot time taken")
        print("0. All tests")
        print("q. Quit")
        choice = input("Enter the identifier of the test to run: ")
        if choice not in ['0', '1', '2', '3', '4', 'q']:
            print("Invalid choice. Running test 1.")
            choice = '1'
        tests(choice)

# Auxiliary functions

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


# ---------------------------
# 1. get_DSAparameters(n)
# ---------------------------

# Generate and return (p, q, g) for DSA:
# q: n-bit prime
# p: prime such that p-1 = k*q (k increasing)
# g: generator of subgroup of order q: g = h^{(p-1)//q} mod p, with g > 1
def get_DSAparameters(n : int) -> Tuple[int, int, int]:
    q = getPrime(n)
    p = get_p(q)
    g = 1  # Initialize g to 1 so that the loop returns a value for g != 1 
    while(g == 1):
        h = random.randint(2, p-2)
        g = pow(h, (p-1)//q, p) # pow(base, exp, mod)
    
    return(p, q, g)

# Given a prime number q, returns a prime number p such that p-1 is a multiple of q.
def get_p(q: int) -> int:
    k = 0
    while True:
        k = k + 1
        p = k * q + 1
        if isPrime(p):
            return p

# ---------------------------
# 2. get_skeys(p, q, g)
# ---------------------------

# Generate and return (x, y):
# . x: private session key in [1, q-1] using secrets (secure)
# . y: public key = g^x mod p
def get_skeys(p: int, q: int, g: int) -> Tuple[int, int]:
    x = random.randint(2, q-2)  # Private key
    y = pow(g, x, p)            # Public key
    return (x, y) 

# ---------------------------
# 3. dsa_sign(message, p, q, g, x)
# ---------------------------

# Sign a message with DSA and return (r, s)
# k is generated internally with secrets; not returned
def dsa_sign(message: Union[int, bytes, str], p: int, q: int, g: int, x: int) -> Tuple[int, int]:
    r = 0
    s = 0
    message_int = _msg_to_int(message, q)
    while (s == 0 or r == 0):
        k = random.randint(2, q-2)
        r = pow(g, k, p) % q
        k_inv = pow(k, -1, q)  # Modular inverse of k mod q
        s = (k_inv * (message_int + x * r)) % q
    
    return (r, s)

# ---------------------------
# 4. dsa_verify(message, signature, p, q, g, y)
# ---------------------------

# Verify DSA signature: returns True if valid, False otherwise
# Signature must be a tuple (r, s)
def dsa_verify(message: Union[int, bytes, str], signature: Tuple[int, int], p: int, q: int, g: int, y: int) -> bool:
    r, s = signature
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    
    message_int = _msg_to_int(message, q)
    w = pow(s, -1, q)  # Modular inverse of s mod q
    u1 = (message_int * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# ---------------------------
# 5. get_private_key(y, g, p)
# ---------------------------

# Recover x by brute force testing x = 1..p-1 until pow(g, x, p) == y
# Returns x if found, else None
def get_private_key(y: int, g: int, p: int) -> Tuple[Optional[int], float]:
    start_cpu = time.process_time()  # Record start CPU time
    for x in range(1, p):
        if pow(g, x, p) == y:
            end_cpu = time.process_time()  # Record end CPU time
            print(f"CPU time: {end_cpu - start_cpu} seconds with brute force")
            return (x, end_cpu - start_cpu)
        
    end_cpu = time.process_time()  # Record end CPU time 
    print(f"Hasnt found x after testing all values up to p-1")       
    return (None, end_cpu - start_cpu)

# ---------------------------
# 5.b. get_private_key(y, g, p) using baby-step giant-step
# ---------------------------

# Recover x by brute force testing using baby-step giant-step algorithm
# Returns x if found, else None
def get_private_key_bsgs(y: int, g: int, p: int) -> Tuple[Optional[int], float]:
    start_cpu = time.process_time()  # Record start CPU time
    m = ceil(sqrt(p - 1)) 
    
    # Baby step
    baby_steps = {}
    for i in range(m):
        value = pow(g, i, p)
        baby_steps[value] = i # Store the value and its corresponding i

    # Precompute g^(-m) mod p
    g_m_inv = pow(g, p - m - 1, p)

    # Giant step
    current = y
    for j in range(m):
        if current in baby_steps:
            end_cpu = time.process_time()  # Record end CPU time
            print(f"CPU time: {end_cpu - start_cpu} seconds with baby-step giant-step")
            return (j * m + baby_steps[current], end_cpu - start_cpu)
        current = (current * g_m_inv) % p

    end_cpu = time.process_time()  # Record end CPU time
    return (None, end_cpu - start_cpu)  # Logarithm not found

# ---------------------------
# 6.a. dsa_sign_with_k
# ---------------------------

# Sign a message using a provided k (forced reuse), useful to demonstrate the vulnerability of reused k
def dsa_sign_with_same_k(message1: Union[int, bytes, str], message2: Union[int, bytes, str], p: int, q: int, g: int, x: int, k: int) -> Tuple[int, int, int]:
    message1_int = _msg_to_int(message1, q)
    message2_int = _msg_to_int(message2, q)

    r = pow(g, k, p) % q
    k_inv = pow(k, -1, q)  # Modular inverse of k mod q
    s1= (k_inv * (message1_int + x * r)) % q
    s2 = (k_inv * (message2_int + x * r)) % q
    return (r, s1, s2)

# ---------------------------
# 6.b. recover_private_key_from_reused_k
# ---------------------------

# Recover x when two signatures use the same k for messages m1 and m2
# Formula: x = (s2*m1 - s1*m2) * inv(r*(s1 - s2), q) mod q
def get_private_key_from_k(message1: Union[int, bytes, str], message2: Union[int, bytes, str], p: int, q: int, g: int, x: int, k: int) -> Optional[int]:
    message1_int = _msg_to_int(message1, q)
    message2_int = _msg_to_int(message2, q)

    (r, s1, s2) = dsa_sign_with_same_k(message1, message2, p, q, g, x, k)
    return ((s2 * message1_int - s1 * message2_int) * pow(r * (s1 - s2), -1, q)) % q


def tests(test_to_run):
    if(test_to_run == '1' or test_to_run == '0'):
        # Basic test of DSA functions with a user-specified n
        try: 
            n = int(input("Enter a value for n: "))
        except ValueError:
            print("Invalid input. Using default value of 16.")
            n = 16

        print(f"Testing DSA implementation with n = {n} bits:\n")
        (p, q, g) = get_DSAparameters(n)
        print(f"Generated DSA parameters:\np = {p}\nq = {q}\ng = {g}\n")
        (x, y) = get_skeys(p, q, g)
        print(f"Generated key pair:\nPrivate key (x) = {x}\nPublic key (y) = {y}\n")
        m = random.randint(0, 999999999)  # Random integer from 0 to 999,999,999 (up to 9 digits)
        (r, s) = dsa_sign(m, p, q, g, x)
        print(f"Signature for message {m}:\nr = {r}\ns = {s}\n")
        is_valid = dsa_verify(m, (r, s), p, q, g, y)
        print(f"Signature verification for message {m}. Expected True, got: {is_valid}\n")

    if(test_to_run == '2' or test_to_run == '0'):
        # Basic test of DSA functions with a brute force recovery of the private key at the end, for n = 8 to 15
        try: 
            n = int(input("Enter a value for n: "))
        except ValueError:
            print("Invalid input. Using default value of 16.")
            n = 16

        print(f"Testing DSA implementation with n = {n} bits:\n")
        (p, q, g) = get_DSAparameters(n)
        print(f"Generated DSA parameters:\np = {p}\nq = {q}\ng = {g}\n")
        (x, y) = get_skeys(p, q, g)
        print(f"Generated key pair:\nPrivate key (x) = {x}\nPublic key (y) = {y}\n")
        m = random.randint(0, 999999999)  # Random integer from 0 to 999,999,999 (up to 9 digits)
        (r, s) = dsa_sign(m, p, q, g, x)
        print(f"Signature for message {m}:\nr = {r}\ns = {s}\n")
        is_valid = dsa_verify(m, (r, s), p, q, g, y)
        print(f"Signature verification for message {m}. Expected True, got: {is_valid}\n")
        is_valid = dsa_verify(m, (r + 1, s), p, q, g, y)
        print(f"Signature verification for message {m} with incorrect signature parameters. Expected False, got: {is_valid}\n")
        
        print(f"Attempting to recover private key by brute force:")
        (x_recovered, cpu_time) = get_private_key(y, g, p)
        print(f"Recovered private key by brute force: x = {x_recovered}\n")
        
        print(f"Attempting to recover private key by baby-step giant-step:")
        (x_recovered_bsgs, cpu_time_bsgs) = get_private_key_bsgs(y, g, p)
        print(f"Recovered private key by baby-step giant-step: x = {x_recovered_bsgs}\n")

    if(test_to_run == '3' or test_to_run == '0'):
        # Test for getting x from k, when two messages are signed with the same k
        try: 
            n = int(input("Enter a value for n: "))
        except ValueError:
            print("Invalid input. Using default value of 16.")
            n = 16

        print(f"Testing recovery of private key x from two signatures with the same k with n = {n}:\n")
        (p, q, g) = get_DSAparameters(n)
        print(f"Generated new DSA parameters for repeated k test:\np = {p}\nq = {q}\ng = {g}\n")
        (x, y) = get_skeys(p, q, g)
        m1 = random.randint(0, 999999999)  # Random integer from 0 to 999,999,999 (up to 9 digits)
        m2 = random.randint(0, 999999999)  # Random integer from 0 to 999,999,999 (up to 9 digits)
        print(f"Generated key pair for repeated k test:\nPrivate key (x) = {x}\nPublic key (y) = {y}\n")
        x_from_k = get_private_key_from_k(m1, m2, p, q, g, x, (p-1 // q))  # Using k = (p-1)/q for the test
        print(f"Recovered private key from two signatures with same k: x = {x_from_k}\n")

    if(test_to_run == '4' or test_to_run == '0'):
        print("\nThis test allows for a creation of a table plotting the values of n against the time taken to recover the private key, however it requires Plotly/Pandas to be installed.\n")
        draw_table = int(input("Do you wish to see the results as graphs? (0 for No, else Yes): "))
        # Test time taken to get x for a range of n and plot CPU time taken
        try :
            n_lower_bound = int(input("Enter the lower bound for n: "))
            n_upper_bound = int(input("Enter the upper bound for n: "))
        except ValueError:
            print("Invalid input. Using default values of 8 and 30.")
            n_lower_bound = 8
            n_upper_bound = 30
        times_cpu = []
        times_cpu_bsgs = []
        ns = []
        for i in range(0, 4, 1): # Repeat the whole test 3 times to get more data points
            for n in range(n_lower_bound, n_upper_bound, 1):
                print(f"Testing time taken to recover private key for n = {n} bits:")
                (p, q, g) = get_DSAparameters(n)
                (x, y) = get_skeys(p, q, g)
                (x_recovered, cpu_time) = get_private_key(y, g, p)
                ns.append(n)  
                times_cpu.append(cpu_time)
                (x_recovered, cpu_time_bsgs) = get_private_key_bsgs(y, g, p)
                times_cpu_bsgs.append(cpu_time_bsgs)
        
        if(draw_table != 0):
            # Plotting the results using Plotly
            fig_brute_force = px.scatter(x=ns, y=times_cpu, labels={'x': 'n (bits)', 'y': 'Time (seconds)'}, title='Real Time to Recover Private Key vs n')        
            fig_bsgs = px.scatter(x=ns, y=times_cpu_bsgs, labels={'x': 'n (bits)', 'y': 'Time (seconds)'}, title='Real Time to Recover Private Key vs n using Baby-step Giant-step')
            fig_brute_force.show()
            fig_bsgs.show()


if __name__ == "__main__":
    main()