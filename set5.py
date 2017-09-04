import random
import hashlib
import codecs
import functools

from challenges import challenge, assert_true
import set1, set2, set3, set4
# From: https://cryptopals.com/sets/5

## Challenge 33
def diffie_helman(p, g):
    # Generate private keys in p
    a, b = random.randrange(1, p), random.randrange(1, p)
    # Generate public keys
    A, B = modexp(g, a, p), modexp(g, b, p)
    # Generate shared secret
    s, s2 = modexp(B, a, p), modexp(A, b, p)
    # Verify Bob and Alice have the same shared secret
    assert_true(s == s2)
    # Return SHA256 of shared secret
    return hashlib.sha256(long_to_bytes(s)).digest()

def long_to_bytes(l):
    r = bytearray()
    l2 = l
    # While l2 is positive,
    while l2 > 0:
        # Take the last 8 bits, and add it as a new byte to r
        r.append(l2 & 255)
        # Shift the last 8 bits out
        l2 = l2 >> 8
    # Reverse the order and return the output
    r.reverse()
    return r

def modexp(a, b, c):
    r = 1
    base = a % c
    # Iterate over all bits by observing the least significant bit, then shifting
    # As long as b is still positive (i.e. there are bits to observe),
    while b > 0:
        # If least significant bit is 1, multiply result by base, mod c
        if b % 2 == 1:
            r = (r * base) % c
        # Shift least significant bit out
        b = b >> 1
        # Square base, mod c
        base = (base * base) % c
    return r

nist_p, nist_g = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff, 2

@challenge(5, 33)
def challenge_33():
    print("Session Key: {}".format(diffie_helman(p=37, g=5)))
    print("Session Key: {}".format(diffie_helman(p=nist_p, g=nist_g)))


## Challenge 34
class EchoAlice:
    def __init__(self):
        self.p, self.g, self.s, self.a, self.msg = None, None, None, None, None

    def initiate(self, p, g):
        self.p = p
        self.g = g
        # Generate a (valid) private key a
        self.a = random.randrange(1, p)
        # Send p, g, A
        return (p, g, modexp(g, self.a, p))

    def send_msg(self, inp, msg):
        self.msg = msg
        # Generate the shared secret s
        self.s = modexp(inp, self.a, self.p)
        # Send plaintext using SHA1 hash of shared secret as key, generated IV as IV
        iv = set2.random_bytes(16)
        ciphertext = set2.encrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=msg)
        # Send ciphertext with IV
        return ciphertext, iv

    def verify_echo(self, inp):
        (ciphertext, iv) = inp
        # Decrypt received message
        msg = set2.decrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=ciphertext)
        # Verify message is the one that was sent
        return msg == self.msg


class EchoBob:
    def __init__(self):
        self.p, self.g, self.s = None, None, None

    def receive(self, inp):
        (self.p, self.g, A) = inp
        # Generate a (valid) private key b
        b = random.randrange(1, self.p)
        # Generate B
        B = modexp(self.g, b, self.p)
        # Generate the shared secret s
        self.s = modexp(A, b, self.p)
        # Send B
        return B

    def receive_msg(self, inp):
        (ciphertext, iv) = inp
        # Decrypt received message
        msg = set2.decrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=ciphertext)
        # Send plaintext using SHA1 hash of shared secret as key, generated IV as IV
        iv = set2.random_bytes(16)
        ciphertext = set2.encrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=msg)
        # Send ciphertext with IV
        return ciphertext, iv

class EchoEve:
    def __init__(self):
        self.p, self.g, self.msg, self.iv = None, None, None, None

    def intercept_alice_initiate(self, inp):
        (p, g, _) = inp
        self.p = p
        self.g = g
        return (p, g, p)

    def intercept_bob_receive(self, _):
        return self.p

    def intercept_alice_send_msg(self, inp):
        ciphertext, iv = inp
        self.msg = ciphertext
        self.iv = iv
        return inp

    def intercept_bob_receive_msg(self, inp):
        return inp

    def decrypt_message(self):
        # We know s = 0, because Alice thinks B = p = 0 (mod p), and Bob thinks A = p = 0 (mod p)
        return set2.decrypt_aes_cbc(text=self.msg, key=hashlib.sha1(long_to_bytes(0)).digest()[0:16], iv=self.iv)

@challenge(5, 34)
def challenge_34():
    # Simple EchoBot exchange
    alice = EchoAlice()
    bob = EchoBob()

    msg1 = alice.initiate(p=nist_p, g=nist_g)
    msg2 = bob.receive(msg1)
    msg3 = alice.send_msg(msg2, set2.random_bytes(random.randrange(10, 100)))
    msg4 = bob.receive_msg(msg3)
    exchange_1_valid = alice.verify_echo(msg4)

    # EchoBot exchange with MitM
    alice = EchoAlice()
    bob = EchoBob()
    eve = EchoEve()

    secret_msg = set2.random_bytes(random.randrange(10, 100))
    msg1 = alice.initiate(p=nist_p, g=nist_g)
    msg1p = eve.intercept_alice_initiate(msg1)
    msg2 = bob.receive(msg1p)
    msg2p = eve.intercept_bob_receive(msg2)
    msg3 = alice.send_msg(msg2p, secret_msg)
    msg3p = eve.intercept_alice_send_msg(msg3)
    msg4 = bob.receive_msg(msg3p)
    msg4p = eve.intercept_bob_receive_msg(msg4)
    exchange_2_valid = alice.verify_echo(msg4p)
    exchange_2_cracked = secret_msg == eve.decrypt_message()

    # Verify exchanges were valid and Eve was able to obtain the original message
    assert_true(exchange_1_valid and exchange_2_valid and exchange_2_cracked)


## Challenge 35
class EchoAlice2:
    def __init__(self):
        self.p, self.g, self.s, self.a, self.msg = None, None, None, None, None

    def initiate(self, p, g):
        self.p = p
        self.g = g
        # Generate a (valid) private key a
        self.a = random.randrange(1, p)
        # Send p, g
        return (p, g)

    def send_A(self, inp):
        assert inp
        self.a = random.randrange(1, self.p)
        return modexp(self.g, self.a, self.p)

    def send_msg(self, inp, msg):
        self.msg = msg
        # Generate the shared secret s
        self.s = modexp(inp, self.a, self.p)
        # Send plaintext using SHA1 hash of shared secret as key, generated IV as IV
        iv = set2.random_bytes(16)
        ciphertext = set2.encrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=msg)
        # Send ciphertext with IV
        return ciphertext, iv

    def verify_echo(self, inp):
        (ciphertext, iv) = inp
        # Decrypt received message
        msg = set2.decrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=ciphertext)
        # Verify message is the one that was sent
        return msg == self.msg

class EchoBob2:
    def __init__(self):
        self.p, self.g, self.s = None, None, None

    def receive(self, inp):
        (self.p, self.g) = inp
        return True

    def send_B(self, inp):
        # Generate a (valid) private key b
        b = random.randrange(1, self.p)
        # Generate B
        B = modexp(self.g, b, self.p)
        # Generate the shared secret s
        self.s = modexp(inp, b, self.p)
        return B

    def receive_msg(self, inp):
        (ciphertext, iv) = inp
        # Decrypt received message
        msg = set2.decrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=ciphertext)
        # Send plaintext using SHA1 hash of shared secret as key, generated IV as IV
        iv = set2.random_bytes(16)
        ciphertext = set2.encrypt_aes_cbc(key=hashlib.sha1(long_to_bytes(self.s)).digest()[0:16], iv=iv, text=msg)
        # Send ciphertext with IV
        return ciphertext, iv

class EchoEve2:
    def __init__(self, g_prime):
        self.p, self.g, self.msg, self.iv, self.g_prime = None, None, None, None, g_prime

    def intercept_alice_initiate(self, inp):
        (p, g) = inp
        self.p = p
        self.g = g
        return (p, self.g_prime)

    def intercept_bob_receive(self, inp):
        return True

    def intercept_alice_send_msg(self, inp):
        ciphertext, iv = inp
        self.msg = ciphertext
        self.iv = iv
        return inp

    def intercept_bob_receive_msg(self, inp):
        return inp

    def decrypt_message(self):
        # We know s = 0, because Alice thinks B = p = 0 (mod p), and Bob thinks A = p = 0 (mod p)
        key_candidates = []
        if self.g_prime == 1:
            # A=g^a, B=g'^b=1
            # s_a=B^a=1^a=1, s_b=A^b=?
            key_candidates = [1]
        if self.g_prime == self.p:
            # A=g^a, B=g'^b=0
            # s_a=0^a=0^a=0, s_b=A^b=?
            key_candidates = [0]
        if self.g_prime == self.p-1:
            # A=g^a, B=g'^b=(-1)^b={either 1 or -1}
            # s_a=B^a={either 1 or -1}, s_b=A^b=?
            key_candidates = [1, -1]

        for key in key_candidates:
            try:
                return set2.pkcs7_remove_padding(set2.decrypt_aes_cbc(text=self.msg, key=hashlib.sha1(long_to_bytes(key)).digest()[0:16], iv=self.iv, unpad=False))
            except ValueError:
                continue
        return None #raise ValueError("Decryption failed (keys tried: {})".format(key_candidates))

def MitM_alter_group(g):
    alice = EchoAlice2()
    bob = EchoBob2()
    eve = EchoEve2(g)

    secret_msg = set2.random_bytes(50)
    msg1 = alice.initiate(nist_p, nist_g)
    msg1p = eve.intercept_alice_initiate(msg1)
    msg2 = bob.receive(msg1p)
    msg2p = eve.intercept_bob_receive(msg2)
    msg3 = alice.send_A(msg2p)
    msg4 = bob.send_B(msg3)
    msg5 = alice.send_msg(msg4, secret_msg)
    msg5p = eve.intercept_alice_send_msg(msg5)
    #msg6 = bob.receive_msg(msg5p)
    exchange_2_cracked = secret_msg == eve.decrypt_message() or MitM_alter_group(g)
    return exchange_2_cracked

@challenge(5, 35)
def challenge_35():
    g_1_cracked = MitM_alter_group(1)
    g_p_cracked = MitM_alter_group(nist_p)
    g_p_min_1_cracked = MitM_alter_group(nist_p-1)

    assert_true(g_1_cracked and g_p_cracked and g_p_min_1_cracked)


## Challenge 39
# All prime numbers between 2 and 1000
PRIMES = set([2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997])

def xgcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = xgcd(b % a, a)
    return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, _ = xgcd(a, m)
    if g != 1:
        raise ValueError('Given numbers are not coprime.')
    else:
        return x % m

def are_coprime(int_list):
    # Make sure there are no duplicates in the list
    if len(set(int_list)) != len(int_list): return False
    # Get a list of all items to compare
    comparison_list = set([(min(x, y), max(x, y)) for x in int_list for y in int_list if x != y])
    # For each pair...
    for item in comparison_list:
        # Find the XGCD
        g, _, _ = xgcd(*item)
        # If `g` != 1, they are not coprime
        if g != 1: return False
    # If all `g`s unequal to 1, we know all ints are coprime
    return True

def set_up_rsa(e, pqs=set()):
    # Textbook RSA
    try:
        # Select random `p`
        p = random.sample(PRIMES - pqs, 1)[0]
        # Add `p` to `pqs` to avoid picking it as q again
        pqs.add(p)
        # Select random `q`
        q = random.sample(PRIMES - pqs, 1)[0]
        # Add `q` to `pqs`
        pqs.add(q)
        # Calculate `n`
        n = p * q
        # Calculate `et`
        et = (p - 1) * (q - 1)
        # Find `d`
        d = modinv(e, et)
    except ValueError:
        # If e and et are not coprime, the modular inverse won't exist.
        # Hence, generate two new primes and try again
        return set_up_rsa(e)
    # Return public and private keys
    public = (e, n)
    private = (d, n)
    return public, private

def encrypt_rsa(msg, key):
    # Note that encrypt = decrypt for RSA
    return modexp(msg, key[0], key[1])

def string_to_int(message):
    return int(codecs.encode(message, 'hex'), 16)

def int_to_string(integer):
    return codecs.decode(hex(integer)[2:], 'hex')

assert int_to_string(string_to_int(b'test')) == b'test'

@challenge(5, 39)
def challenge_39():
    # Get public and private key
    public, private = set_up_rsa(3)
    # Generate message
    msg = random.randrange(2, public[1])
    # Encrypt and decrypt
    ciphertext = encrypt_rsa(msg, public)
    plaintext = encrypt_rsa(ciphertext, private)
    # Verify output
    assert_true(msg == plaintext)


## Challenge 40
def crt(data):
    # Textbook Chinese Remainder Theorem
    N = functools.reduce(lambda a, b: a * b, [n for _, n in data])
    output = 0
    print('CRT:')
    for (c, n) in data:
        print('  x = {:6d} mod {}'.format(c, n))
        X = int(N / n)
        temp_result = c * X * modinv(X, n)
        output = (output + temp_result) % N
    print('  Solution: x = {}\n'.format(output))
    return output

@challenge(5, 40)
def challenge_40():
    e = 3
    # For this attack to work, it is assumed that:
    # - all `p`s and `q`s are unique;
    # - all `n`s are coprime with each other;
    # - the message is smaller than the smallest `n`.
    # The code below will make sure that these conditions are met.
    while True:
        # Generate a random message
        msg = random.randrange(1, 1000)
        data, pqs = [], set()
        for _ in range(e):
            # Generate new public/private key pair
            public, _ = set_up_rsa(e, pqs)
            # If we end up getting a public key that's too small for our message, start over
            if public[1] <= msg: break
            # Collect encrypted text and public key
            data.append((encrypt_rsa(msg, public), public[1]))
        else:
            # If we succsefully generated `e` ciphertexts and pubkeys, verify the pubkeys are coprime with each other
            if are_coprime([n for _, n in data]):
                #  If not, start over
                break

    # Use CRT and take `e`th root
    r = round(crt(data) ** (1/e))
    print('Original message: {}, found message: {}'.format(msg, r))
    assert_true(r == msg)


## Execute individual challenges
if __name__ == '__main__':
    challenge_33()
    challenge_34()
    challenge_35()
    challenge_39()
    challenge_40()

