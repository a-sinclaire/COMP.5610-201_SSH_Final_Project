import math  # For isqrt
import random  # For very-large random number generation
import numpy as np  # For base36 encoding and logs
import CNSec_Utils as util

MIN_PRIME = 2**500  # Lower bound of p and q (for RSA key generation)
MAX_PRIME = 2**540  # Upper bound of p and q (for RSA key generation)
CHUNK_SIZE = 64  # Number of BYTES in a single message. Longer messages will be chunked into this size, using back-padding.

"""
Usage:
generate_key() to generate a (d, e, n) RSA key combination.
encode(M, K, n) to encode a message using key (K, n).
    Output is an array of encrypted chunks; each chunk is an integer in modulus n.
    M must be a string, but any arbitrary Bytes object can be represented as a string: e.g. '\x0f' is a valid 1-byte string to encode (in ASCII, it correponds to the carriage return code).
decode(C, K, n) to decode a set of ciphertext chunks C using key (K, n).
    C must be an array of integers in modulus n (that is, output from encode()).

Padding scheme for plaintext:
    For a message chunk m with length l < CHUNK_SIZE,
    a padded message m' will be created using:
    m' = m + b'x\01' + b'x\00'*(CHUNK_SIZE - len(m) - 1)
    
    e.g. CHUNK_SIZE = 8, m = b'abcd'
    -> m' = b'abcd\x01\x00\x00\x00'
    
    (note that b'1' corresponds to the byte encoding of the ASCII character 1... not the value 1. b'\x01' is the actual value 1.)

Padding scheme for encrypted chunks:
Encrypted chunks are ASCII strings representing base-36 values, prepended with 0 such that they are f(n) bytes long.
"""

def chunklen(n):
    """
    For an RSA key with public parameter n, calculates the padded length of an encrypted chunk.
    """
    return len(np.base_repr(n, 36))

def generate_key():
    """
    Generates an RSA key.
    :return: Tuple containing private key, public key, and modulus, respectively.
    """
    while True:  # Generate a random large prime number p
        if util.is_prime(p := random.randint(MIN_PRIME, MAX_PRIME)):
            break
    while True:  # Generate a random large prime number q
        if util.is_prime(q := random.randint(MIN_PRIME, MAX_PRIME)):
            if q != p:
                break
    n = p*q

    l = (p-1)*(q-1) // util.gcd((p-1), (q-1))  # Carmichael Totient Function of n. (Integer division // is only used to enforce the Python type to be integral; by construction, the value must be an integer regardless)
    print("p = {}, q = {}, l = {}".format(p, q, l))

    while True:  # Generate public key e. e < sqrt(l) and gcd(e, l) == 1 (e and l are coprime). (Nominally, e < l; however, to ensure relatively small e for efficient encryption, I choose e < sqrt(l))
       if util.gcd(l, e := random.randint(2**16, math.isqrt(l))) == 1:
           break

    d = util.mmi(e, l)

    return d, e, n

def _encrypt_chunk(m, k, n):
    """
    Encrypts a message chunk.
    :param m: Bytes (plaintext)
    :param k: Key parameter
    :param n: Key parameter
    :return: Bytes object
    """
    assert type(m) == bytes, "RSA encrypt_chunk() passed a {}; expected a Bytes object".format(type(m))
    assert len(m) <= CHUNK_SIZE, "RSA encrypt_chunk() passed a message of length {}; but CHUNK_SIZE is {}".format(len(m), CHUNK_SIZE)

    if len(m) < CHUNK_SIZE:
        m = m + b'\x01' + (b'\x00' * (CHUNK_SIZE - len(m) - 1))

    val = util.fme(int.from_bytes(m, 'big', signed=False), k, n)
    out = np.base_repr(val, 36)
    out = '0'*(chunklen(n) - len(out)) + out

    return out

def _decrypt_chunk(c, k, n, unpad=False):
    """
    Decrypts a message chunk.
    :param c: String (base 36 ciphertext)
    :param k: Key parameter
    :param n: Key parameter
    :param unpad: If True, we expect this message to be padded; unpad the deciphered message
    :return: Bytes object
    """
    assert type(c) == str, "RSA decrypt_chunk() passed a {}; expected a str".format(type(c))
    
    c = int(c, 36)
    out = util.fme(c, k, n)

    if unpad:  # Unpad the message
        out = int.from_bytes(out.to_bytes(CHUNK_SIZE, 'big', signed=False).rstrip(b'\x00')[:-1], 'big', signed=False)  # Remove all trailing 0's and the padded 1

    return out

def encrypt(M, k, n):
    """
    Encrypts an arbitrary string M using key (k, n).
    1. Converts string to ASCII
    2. Breaks string into CHUNK_SIZE-sized plaintext blocks (the last block will be post-padded with 1||0000...)
    3. Encrypts each block individually
    :param M:
    :param k:
    :param n:
    :return: An array of encrypted chunks (Base 36 string prepended with 0's). 
    """
    A = M.encode('ascii')
    chunks = list([A[i * CHUNK_SIZE:(i+1) * CHUNK_SIZE] for i in range(len(A) // CHUNK_SIZE + 1)])
    out = []
    for chunk in chunks:
        out.append(_encrypt_chunk(chunk, k, n))
    return out

def decrypt(C, k, n):
    """
    Decrypts an array of encrypted chunks (integers).
    :param C: Array of encrypted chunks (integers)
    :param k: Key parameter
    :param n: Key parameter
    :return: String
    """
    out = []
    for chunk in C[:-1]:
        out.append(_decrypt_chunk(chunk, k, n, unpad=False))
    out.append(_decrypt_chunk(C[-1], k, n, unpad=True))
    out = ''.join(map(lambda x: x.to_bytes(CHUNK_SIZE, 'big', signed=False).strip(b'\x00').decode('ascii'), out))
    return out


if __name__ == '__main__':
    print("--- RSA Module Unit Tests ---\n")
    # RSA tests: key generation, encryption, and decryption
    print("Performing RSA tests")
    print("  Generating key")
    (d, e, n) = generate_key()
    print("    Key generated:\n      d = {}\n      e = {}\n      n = {}".format(d, e, n))

    # M = "Hello, World!"
    M = "Hello, world! This is a test of a long message to be encrypted and decrypted using our implementation of the RSA public-key cryptosystem."
    print("  Encrypting message '{}' using public key, and decrypting using private key:".format(M))
    plaintext = int.from_bytes(M.encode('ascii'), byteorder='big', signed=False)
    print("    Plaintext: {:x}".format(plaintext))
    public_encrypted = encrypt(M, e, n)
    print("    Encrypted chunks:")
    for i, m in enumerate(public_encrypted):
        print(f"      {i:>3}: {m}")
    private_decrypted = decrypt(public_encrypted, d, n)
    print("    Decrypted: {}".format(private_decrypted))

    print("  Encrypting message '{}' using private key, and decrypting using public key:".format(M))
    plaintext = int.from_bytes(M.encode('ascii'), byteorder='big', signed=False)
    print("    Plaintext: {}".format(plaintext))
    private_encrypted = encrypt(M, d, n)
    print("    Encrypted chunks:")
    for i, m in enumerate(private_encrypted):
        print(f"      {i:>3}: {m}")
    public_decrypted = decrypt(private_encrypted, e, n)
    print("    Decrypted: {}".format(public_decrypted))
    del d, e, n, i, m, plaintext, private_decrypted, public_encrypted, private_encrypted, public_decrypted, M
