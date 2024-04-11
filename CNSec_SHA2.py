k = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
)  # Round constants

def _pb(B):
    # Pretty-print binary from Bytes objects. Helpful for debugging but not used in code
    out = bin(int(B.hex(), 16))[2:]
    out = '0'*(-len(out) % 8) + out
    out = ' '.join([out[i*8:(i+1)*8] for i in range(len(out) // 8 + 1)])
    out = '\n'.join([out[i*36:(i+1)*36] for i in range(len(out) // 36 + 1)])
    print(out)

def _pad(M):
    # SHA-256 padding
    # Input: bytes object with length L (in bits)
    # Output: bytes object with length L' > L s.t. L' % 512 = 0, L' - L < 512

    L = len(M)*8

    M = M + b'\x80'
    M = M + b'\x00' * (62 - len(M) % 64)
    M = M + L.to_bytes(2, 'big')

    return M

def _compress_chunk(chunk, init):
    """
    :param chunk: Bytes object of 16-word chunk to hash
    :param init: Current hash value [h0..h7] (list of 8 ints)
    :return: New hash value [h'0..h'7] (list of 8 ints)
    """
    # Input: 512-bit (64-byte, 16-word) chunk (Bytes object)
    # Output: Compressed chunk

    w = [
        chunk[0:4],     chunk[4:8],     chunk[8:12],    chunk[12:16],   chunk[16:20],   chunk[20:24],   chunk[24:28],   chunk[28:32],
        chunk[32:36],   chunk[36:40],   chunk[40:44],   chunk[44:48],   chunk[48:52],   chunk[52:56],   chunk[56:60],   chunk[60:64],
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',        b'0000',
    ]  # 64-word array with first 16 words initialized to chunk

    for i in range(16, 64):  # Populate the rest of the words
        s0 = int.from_bytes(_byterotate(w[i-15], 7), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(w[i-15], 18), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(w[i-15], 3, wrap=False), 'big', signed=False)  # (w[i-15] ror 7) ^ (w[i-15] ror 18) ^ (w[i-15] rsh 3)
        s1 = int.from_bytes(_byterotate(w[i-2], 17), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(w[i-2], 19), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(w[i-2], 10, wrap=False), 'big', signed=False)  # (w[i-2] ror 17) ^ (w[i-2] ror 19) ^ (w[i-2] rsh 10)

        temp = (int.from_bytes(w[i-16], 'big', signed=False) + s0 + int.from_bytes(w[i-7], 'big', signed=False) + s1) % 2**32  # w[i-16] + s0 + w[i-7] + s1
        w[i] = temp.to_bytes(4, 'big', signed=False)

    # Init working variables to current hash value, and prepare our output hash value
    (a, b, c, d, e, f, g, h) = map(lambda x: x.to_bytes(4, 'big', signed=False), init)
    out = init.copy()

    for i in range(64):
        s1 = int.from_bytes(_byterotate(e, 6), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(e, 11), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(e, 25), 'big', signed=False)  # (e ror 6) ^ (e ror 11) ^ (e ror 25)
        ch = (int.from_bytes(e, 'big', signed=False) & int.from_bytes(f, 'big', signed=False))\
            ^ (~(int.from_bytes(e, 'big', signed=False)) & int.from_bytes(g, 'big', signed=False))  # (e & f) ^ (~e & g)
        t1 = (int.from_bytes(h, 'big', signed=False) + s1 + ch + k[i] + int.from_bytes(w[i], 'big', signed=False)) % 2**32
        s0 = int.from_bytes(_byterotate(a, 2), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(a, 13), 'big', signed=False)\
            ^ int.from_bytes(_byterotate(a, 22), 'big', signed=False)  # (a ror 2) ^ (a ror 13) ^ (a ror 22)
        maj = (int.from_bytes(a, 'big', signed=False) & int.from_bytes(b, 'big', signed=False))\
            ^ (int.from_bytes(a, 'big', signed=False) & int.from_bytes(c, 'big', signed=False))\
            ^ (int.from_bytes(b, 'big', signed=False) & int.from_bytes(c, 'big', signed=False))  # (a & b) ^ (a & c) ^ (b & c)
        t2 = (s0 + maj) % 2**32

        (a, b, c, d, e, f, g, h) = (
            ((t1+t2) % 2**32).to_bytes(4, 'big', signed=False),
            a, b, c,
            ((int.from_bytes(d, 'big', signed=False)+t1) % 2**32).to_bytes(4, 'big', signed=False),
            e, f, g
        )  # Update working variables

    out = [sum(pair) % 2**32 for pair in zip(out, map(lambda x: int.from_bytes(x, 'big', signed=False), (a, b, c, d, e, f, g, h)))]  # Update output hash (h'0 = h0 + a, h'1 = h1 + b, etc.)

    return out


def _byterotate(M, n, wrap=True):
    """
    Rotates a Bytes object.
    :param M: Bytes object
    :param n: Rotation degree in BITS (positive for right rotation (>>), negative for left rotation (<<))
    :param wrap: If true, perform a rotate; if False, perform a shift, truncating to original length of M
    :return:
    """

    if n == 0: return M
    L = len(M)

    # Right-rotating an L-bit message n times is equivalent to rotating it (n % L) times.
    #   Take advantage of this, but also hold onto the original n.
    #   Note also that this handles negative/left-rotations eloquently:
    #       a left-rotation by n is equivalent to a right-rotation by ((L - n) % L) == (-n % L)
    n1 = n % (L * 8)

    v = int.from_bytes(M, 'big', signed=False)  # In Python, bitshifts can only be performed on ints

    # Shifting by n bits will lose information on the least- or most-significant n bits (depending on if it's a right-or-left shift).
    # Copy these bits using a bitmask so that we can "wrap" them to the other side.
    #   (Even if the 'wrap' parameter is False; we will handle that in a moment)
    addend = (v & (2**n1 - 1)) << (L*8-n1)

    # Perform the bitshift, and re-add the lost bits.
    v = addend + (v >> n1)

    # If the 'wrap' parameter is False, zero out the addend bits.
    #   (I think this may be doable by simply not re-adding the addend, but I got distracted and this works just as well, so...)
    if not wrap:
        mask = (1 << (L*8 - abs(n))) - 1
        if n < 0: mask <<= abs(n)
        v = v & mask

    # Re-convert back to a Bytes object; truncate off any extra bytes which may have been added
    v = v.to_bytes(L+abs(n1), 'big', signed=False)[abs(n1):]

    return v

def sha256(M):
    """
    SHA2-256 hashing algorithm.
    :param M: Input string to be hashed
    :return: SHA2-256 hash string (in lowercase hex with no preceding '0x')
    """

    # Encode message and pad
    M = _pad(M.encode('ascii'))

    # Break into 512-bit chunks
    chunks = list([M[i * 64:(i+1) * 64] for i in range(len(M) // 64)])

    out = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]  # Initial hash

    for chunk in chunks:
        out = _compress_chunk(chunk, out)

    out = (b''.join(map(lambda x: x.to_bytes(4, 'big', signed=False), out))).hex()

    return out


if __name__ == '__main__':

    M = "Hello, World!"
    Mb = M.encode('ascii')
    Mp = _pad(Mb)
    print(M, Mb, Mp, sep="|")

    print("Test of bit rotation:")
    for i in range(-19, 20):
        print("   {:>3}: {:0104b}".format(i, int.from_bytes(_byterotate(Mb, i), 'big', signed=False)))

    print("Test of bit rotation (no wrapping):")
    for i in range(-9, 10):
        print("   {:>3}: {:0104b}".format(i, int.from_bytes(_byterotate(Mb, i, wrap=False), 'big', signed=False)))

    test_vectors = ("", "hello world", "Hello, world!", "TEST", "This is a test of a long string with more than 64 characters. ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    for test in test_vectors:
        print("{:>30} | {}".format("'" + test + "'", sha256(test)))
