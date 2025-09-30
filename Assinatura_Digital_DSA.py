from math import ceil, sqrt
from Crypto.Util.number import getPrime, isPrime
import random
import time
import plotly.express as px

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
        choice = input("Enter the number of the test to run: ")
        if choice not in ['0', '1', '2', '3', '4', 'q']:
            print("Invalid choice. Running test 1.")
            choice = '1'
        tests(choice)


# Gets the size of the key "n" as an input and returns a triplet (p, q, g) of DSA parameters
# p is such that p-1 is a multiple of q
# q will be a prime number with n bits 
# g will be pow(h, (p-1)//q, p)
def get_DSAparameters(n):
    q = getPrime(n)
    p = get_p(q)
    g = 1  # Initialize g to 1 so that the loop returns a value for g != 1 
    while(g == 1):
        h = random.randint(2, p-2)
        g = pow(h, (p-1)//q, p) # pow(base, exp, mod)
    
    return(p, q, g)

# Given a prime number q, returns a prime number p such that p-1 is a multiple of q.
def get_p(q):
    k = 0
    while True:
        k = k + 1
        p = k * q + 1
        if isPrime(p):
            return p

# Given the DSA parameters (p, q, g), returns a pair (x, y) of keys
# x is the private key  
# y is the public key        
def get_skeys(p,q,g):
    x = random.randint(2, q-2)  # Private key
    y = pow(g, x, p)            # Public key
    return (x, y) 

# Given a message "message" and the DSA parameters (p, q, g) and the private key x,
# returns the signature (r, s) of the message
def dsa_sign(message, p, q, g, x):
    r = 0
    s = 0
    while (s == 0 or r == 0):
        k = random.randint(2, q-2)
        r = pow(g, k, p) % q
        k_inv = pow(k, -1, q)  # Modular inverse of k mod q
        s = (k_inv * (message + x * r)) % q
    
    return (r, s)

# Given a message "message", a signature (r, s), the DSA parameters (p, q, g) and the public key y,
# returns True if the signature is valid, False otherwise
def dsa_verify(message, r, s, p, q, g, y):
    if r <= 0 or r >= q or s <= 0 or s >= q:
        return False
    w = pow(s, -1, q)  # Modular inverse of s mod q
    u1 = (message * w) % q
    u2 = (r * w) % q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q
    return v == r

# Given the public key y, the DSA parameters (p, g), returns the private key x through brute force
def get_private_key(y, g, p):
    start_cpu = time.process_time()  # Record start CPU time
    x = 0
    while True:
        x = x + 1
        if pow(g, x, p) == y:
            end_cpu = time.process_time()  # Record end CPU time
            print(f"CPU time: {end_cpu - start_cpu} seconds with brute force")
            return (x, end_cpu - start_cpu)

# Given two messages signed with the same k, returns their signatures (r, s1, s2)
def dsa_sign_with_same_k(message1, message2, p, q, g, x, k):
    r = pow(g, k, p) % q
    k_inv = pow(k, -1, q)  # Modular inverse of k mod q
    s1= (k_inv * (message1 + x * r)) % q
    s2 = (k_inv * (message2 + x * r)) % q
    return (r, s1, s2)

# Given two messages signed with the same k, returns the private key x
def get_private_key_from_k(message1, message2, p, q, g, x, k):
    (r, s1, s2) = dsa_sign_with_same_k(message1, message2, p, q, g, x, k)
    return ((s2 * message1 - s1 * message2) * pow(r * (s1 - s2), -1, q)) % q

def get_private_key_bsgs(y, g, p):
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

    return (None, end_cpu - start_cpu)  # Logarithm not found


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
        is_valid = dsa_verify(m, r, s, p, q, g, y)
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
        is_valid = dsa_verify(m, r, s, p, q, g, y)
        print(f"Signature verification for message {m}. Expected True, got: {is_valid}\n")
        is_valid = dsa_verify(m, r + 1, s, p, q, g, y)
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
        # Test time taken to get x for a range of n and plot CPU and actual time taken
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

        fig_brute_force = px.scatter(x=ns, y=times_cpu, labels={'x': 'n (bits)', 'y': 'Time (seconds)'}, title='Real Time to Recover Private Key vs n')        
        fig_bsgs = px.scatter(x=ns, y=times_cpu_bsgs, labels={'x': 'n (bits)', 'y': 'Time (seconds)'}, title='Real Time to Recover Private Key vs n using Baby-step Giant-step')
        fig_brute_force.show()
        fig_bsgs.show()

if __name__ == "__main__":
    main()