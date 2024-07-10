import uhashlib as hashlib
import ubinascii

# Message schedule indexes for the left path.
ML = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
      7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
      3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
      1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
      4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]

# Message schedule indexes for the right path.
MR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
      6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
      15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
      8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
      12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]

# Rotation counts for the left path.
RL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
      7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
      11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
      11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
      9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]

# Rotation counts for the right path.
RR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
      9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
      9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
      15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
      8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]

# K constants for the left path.
KL = [0, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]

# K constants for the right path.
KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0]

# RIPEMD-160 auxiliary functions
def fi(x, y, z, i):
    if i == 0:
        return x ^ y ^ z
    elif i == 1:
        return (x & y) | (~x & z)
    elif i == 2:
        return (x | ~y) ^ z
    elif i == 3:
        return (x & z) | (y & ~z)
    elif i == 4:
        return x ^ (y | ~z)
    else:
        assert False

def rol(x, i):
    return ((x << i) | ((x & 0xFFFFFFFF) >> (32 - i))) & 0xFFFFFFFF

# RIPEMD-160 compression function
def compress(h0, h1, h2, h3, h4, block):
    # Left path variables.
    al, bl, cl, dl, el = h0, h1, h2, h3, h4
    # Right path variables.
    ar, br, cr, dr, er = h0, h1, h2, h3, h4
    # Message variables.
    x = [int.from_bytes(block[4 * i: 4 * (i + 1)], "little") for i in range(16)]

    # Iterate over the 80 rounds of the compression.
    for j in range(80):
        rnd = j >> 4
        # Perform left side of the transformation.
        al = rol(al + fi(bl, cl, dl, rnd) + x[ML[j]] + KL[rnd], RL[j]) + el
        al, bl, cl, dl, el = el, al, bl, rol(cl, 10), dl
        # Perform right side of the transformation.
        ar = rol(ar + fi(br, cr, dr, 4 - rnd) + x[MR[j]] + KR[rnd], RR[j]) + er
        ar, br, cr, dr, er = er, ar, br, rol(cr, 10), dr

    # Compose old state, left transform, and right transform into new state.
    return h1 + cl + dr, h2 + dl + er, h3 + el + ar, h4 + al + br, h0 + bl + cr

# RIPEMD-160 hash function
def ripemd160(data):
    state = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)
    for b in range(len(data) >> 6):
        s1, s2, s3, s4, s5 = state
        state = compress(s1, s2, s3, s4, s5, data[64 * b: 64 * (b + 1)])
    pad = b"\x80" + b"\x00" * ((119 - len(data)) & 63)
    fin = data[len(data) & ~63:] + pad + (8 * len(data)).to_bytes(8, "little")
    for b in range(len(fin) >> 6):
        s1, s2, s3, s4, s5 = state
        state = compress(s1, s2, s3, s4, s5, fin[64 * b: 64 * (b + 1)])
    return b"".join((h & 0xFFFFFFFF).to_bytes(4, "little") for h in state)

# Constants related to the elliptic curve (secp256k1)
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0
b = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (Gx, Gy)

# Elliptic curve point addition
def point_addition(P, Q, a, p):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    if P[0] == Q[0] and P[1] != Q[1]:
        return (0, 0)
    if P != Q:
        lam = ((Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p)) % p  # Modular inverse using Fermat's Little Theorem
    else:
        lam = ((3 * P[0] ** 2 + a) * pow(2 * P[1], p - 2, p)) % p
    x = (lam ** 2 - P[0] - Q[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (x, y)

# Elliptic curve point doubling
def point_doubling(P, a, p):
    if P == (0, 0):
        return (0, 0)
    lam = ((3 * P[0] ** 2 + a) * pow(2 * P[1], p - 2, p)) % p
    x = (lam ** 2 - 2 * P[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (x, y)

# Elliptic curve point multiplication
def point_multiplication(n, P, a, p):
    Q = (0, 0)
    while n:
        if n & 1:
            Q = point_addition(Q, P, a, p)
        P = point_doubling(P, a, p)
        n >>= 1
    return Q

# Convert public key to compressed form
def compress_public_key(Q):
    x_hex = f"{Q[0]:064x}"
    prefix = '02' if Q[1] % 2 == 0 else '03'
    return bytes.fromhex(prefix + x_hex)

# Base58 encoding function
def base58_encode(b):
    b58_digits = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    value = int.from_bytes(b, 'big')
    result = ''
    while value > 0:
        value, remainder = divmod(value, 58)
        result = b58_digits[remainder] + result
    for byte in b:
        if byte == 0:
            result = '1' + result
        else:
            break
    return result

# Define the function to convert the public key to a Bitcoin address
def public_key_to_address(public_key):
    sha256_hash = hashlib.sha256(public_key).digest()
    ripemd160_hash = ripemd160(sha256_hash)
    return ripemd160_hash

# Generate Bitcoin addresses from a range of private keys
def generate_bitcoin_addresses(start, end, target_addresses):
    for private_key in range(start, end + 1):
        print(f"Processing private key: {private_key}")
        # Generate the public key
        Q = point_multiplication(private_key, G, a, p)
        compressed_public_key = compress_public_key(Q)
        print(f"Compressed Public Key: {ubinascii.hexlify(compressed_public_key).decode()}")

        # Generate the Bitcoin address
        ripemd160_hash = public_key_to_address(compressed_public_key)
        print(f"RIPEMD-160 Hash: {ubinascii.hexlify(ripemd160_hash).decode()}")

        # Add network byte
        network_byte = b'\x00' + ripemd160_hash
        print(f"With Network Byte: {ubinascii.hexlify(network_byte).decode()}")

        # Checksum
        checksum = hashlib.sha256(hashlib.sha256(network_byte).digest()).digest()[:4]
        print(f"Checksum: {ubinascii.hexlify(checksum).decode()}")

        # Address
        address_bytes = network_byte + checksum
        print(f"Address Bytes: {ubinascii.hexlify(address_bytes).decode()}")

        bitcoin_address = base58_encode(address_bytes)
        print(f"Generated Bitcoin Address: {bitcoin_address}")

        # Check if the generated address matches any in the target list
        if bitcoin_address in target_addresses:
            print(f"Matched address: {bitcoin_address}, Private Key: {private_key}")
            #break  # Exit loop if a match is found

# Main execution
if __name__ == "__main__":
    # Put your bitcoin address list here.
    addresses_to_find = ['1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH']
    start_range = 1  # starting private key in hex
    end_range = 10  # ending private key in hex
    print(f"Processing range: {start_range} to {end_range}")
    generate_bitcoin_addresses(start_range, end_range, addresses_to_find)
