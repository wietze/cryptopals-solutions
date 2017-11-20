import os
import random
import hashlib
import re
import base64
from tqdm import tqdm
import colorama

from challenges import challenge, assert_true
import set1, set2, set3, set4, set5
# From: https://cryptopals.com/sets/6
colorama.init()

## Challenge 41
class RsaOracle:
    seen_hashes = []

    def __init__(self):
        # Generate public, private key pair
        self.public, self.__private__ = set5.set_up_rsa(e=3)

    def query(self, msg):
        # Generate hash of given message
        msg_hash = set4.hmac_sha1(b'', bytes(msg)).hexdigest()
        # If hash was seen before, ignore request
        if msg_hash in self.seen_hashes: return None
        # Add hash to list of seen hashes
        self.seen_hashes.append(msg_hash)
        # Return decrypted message
        return set5.encrypt_rsa(msg, self.__private__)

@challenge(6, 41)
def challenge_41():
    # Initate a new RSA Oracle
    oracle = RsaOracle()
    # Generate a secret
    secret = random.randrange(2, oracle.public[1] // 2)
    # Generate a message to send to the RSA oracle
    msg = set5.encrypt_rsa(secret, oracle.public)

    # Query 1: try the generated encrypted secret
    r = oracle.query(msg)
    # Expected output: the original secret
    assert r == secret
    # Query 2: try the generated encrypted secret again
    r = oracle.query(msg)
    # Expected output: a None
    assert r is None

    e, n = oracle.public
    s = 2
    # Query 3: the attack - try our manipulated value
    msgp = (set5.modexp(s, e, n) * msg) % n
    # Expected output: the original secret
    r = (oracle.query(msgp) // s) % n
    assert_true(r == secret)


## Challenge 42
class RsaSignVerify:
    def __init__(self):
        # Generate public, private key pair
        self.public, self.__private__ = set5.set_up_rsa(e=3, keysize=1024)

    def sign(self, msg):
        digest = hashlib.sha1(msg).digest()
        sgn = set5.bytes_to_int(b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3)) + b'\x00' + digest)
        if sgn > self.public[1]:
            raise ValueError("Message to big for public key")
        return set5.encrypt_rsa(sgn, self.__private__)

    def verify(self, msg, signature):
        print('Message to verify: {}'.format(msg))
        decrypted_sig = set5.int_to_bytes(int(set5.encrypt_rsa(signature, self.public)))
        match = re.search(b'\x01\xff*\x00(.{20})', decrypted_sig, re.DOTALL)
        if match is None:
            raise ValueError("Invalid padding.")
        expected_digest = hashlib.sha1(msg).digest()
        print('Digest expected: {}'.format(expected_digest))
        obtained_digest = match.group(1)
        print('Digest obtained: {}'.format(obtained_digest))
        return expected_digest == obtained_digest


def cuberoot(n):
    # Using Binary Search
    lo = 0
    hi = n

    while lo < hi:
        mid = (lo + hi) // 2
        if mid**3 < n:
            lo = mid + 1
        else:
            hi = mid
    return lo


@challenge(6, 42)
def challenge_42():
    # Create new RSA Sign/Verify instance
    m = RsaSignVerify()
    print('> Signed message')
    # Part 1: try to verify a valid signature
    signature = m.sign(b'Hello world')
    assert m.verify(b'Hello world', signature)

    # Part 2: forge a signature
    print('\n> Forged message')
    # Find digest for message to forge
    forged_message = b'hi mom'
    digest = hashlib.sha1(forged_message).digest()
    # Set the contents of the (fake) message to forge
    fake_message = b'\x00\x01\xff\x00' +  digest
    fake_message = set5.bytes_to_int(fake_message + (b'\x00' * (128 - len(fake_message))))
    # The actual trick: find the cube root
    fake_signed_message = cuberoot(fake_message)
    # Check that the forged message passes verification
    assert_true(m.verify(forged_message, fake_signed_message))


## Challenge 43
class DSA:
    # Based on https://en.wikipedia.org/wiki/Digital_Signature_Algorithm
    def __init__(self, p, q, g):
        self.p, self.q, self.g = p, q, g

    def __get_hash__(self, msg):
        return int(hashlib.sha1(msg).hexdigest(), 16)

    def generate_keypair(self):
        x = random.randrange(0, self.q)
        p = set5.modexp(self.g, x, self.p)
        return (x, p)

    def sign(self, msg, x):
        k = random.randrange(2, self.q)
        r = set5.modexp(self.g, k, self.p) % self.q
        if k == 0: return self.sign(msg, x)
        s = (set5.modinv(k, self.q) * (self.__get_hash__(msg) + (x*r))) % self.q
        if s == 0: return self.sign(msg, x)
        return (r, s), k

    def verify(self, msg, sig, y):
        r, s = sig
        if not(0 < r and r < self.q): raise ValueError('r not between 0 and q (r={})'.format(r))
        if not(0 < s and s < self.q): raise ValueError('s not between 0 and q (s={})'.format(s))
        w = set5.modinv(s, self.q)
        u1 = (self.__get_hash__(msg) * w) % self.q
        u2 = (r * w) % self.q
        v = ((set5.modexp(self.g, u1, self.p) * set5.modexp(y, u2, self.p)) % self.p) % self.q
        return v == r

    def crack_x(self, k, msg, sig):
        r, s = sig
        return (((s * k) - self.__get_hash__(msg)) * set5.modinv(r, self.q)) % self.q

@challenge(6, 43)
def challenge_43():
    # Set parameters p, q, g
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

    message = b'Who is the king of the jungle?'

    # Set up new DSA instance and keypair
    dsa = DSA(p, q, g)
    x, y = dsa.generate_keypair()

    # Part 1: try to verify a valid signature
    sig, k = dsa.sign(message, x)
    assert dsa.verify(message, sig, y)

    # Part 2: try and obtain x
    assert dsa.crack_x(k, message, sig) == x

    # Part 3: try and brute force private key based on signature and message#
    message = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
    sig = 548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940

    # Try all `k`s in given range
    for k in range(0, 2 ** 16):
        # Try k, get private key `x`
        x = dsa.crack_x(k, message, sig)
        # Verify hash of found private key `x`
        if hashlib.sha1(hex(x)[2:].encode()).hexdigest() == '0954edd5e0afe5542a4adf012611a91912a3ec16':
            print("The private key is x={}".format(x))
            assert_true(True)
            break
    else:
        print('Unable to find x')
        assert_true(False)


## Challenge 44
def get_challenge_44_messages():
    # Open file, read to string
    with open("inputs/44.txt") as file:
        lines = file.read()
    result = []
    # Parse input file into desired format
    for (msg, s, r, m) in re.findall(r'msg: (.*?)\ns: ([a-z0-9]+)\nr: ([a-z0-9]+)\nm: ([a-z0-9]+)', lines, re.MULTILINE):
        result.append({'msg':str.encode(msg), 's':int(s), 'r':int(r), 'm':int(m, 16)})
    # Return the list of messages with their signatures and hashes
    return result

@challenge(6, 44)
def challenge_44():
    # Set up `p`, `q` and `g` parameters
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    # Create new DSA instance
    dsa = DSA(p, q, g)
    # Read inputs for this challenge from file
    messages = get_challenge_44_messages()
    # Iterate over messages
    for i, msg1 in enumerate(messages):
        for msg2 in messages[(i+1):]:
            # Check if the same `k` was used (implies `r` values are equal)
            if msg1['r'] == msg2['r']:
                # Use '9th grade math' to recover `k`
                a = (msg1['m'] - msg2['m']) % q
                b1 = (msg1['s'] - msg2['s']) % q
                b2 = set5.modinv(b1, q)
                k = (a * b2) % q
                print('Recovered k: {}'.format(k))
                # Recover `x`
                x = dsa.crack_x(k, msg=msg1['msg'], sig=(msg1['r'], msg1['s']))
                print('Recovered x: {}'.format(hashlib.sha1(hex(x)[2:].encode()).hexdigest()))
                # Verify the found private key `x` is the one we are looking for
                assert_true(hashlib.sha1(hex(x)[2:].encode()).hexdigest() == 'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
                return


## Challenge 45
@challenge(6, 45)
def challenge_45():
    # Set up `p` and `q` parameters
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

    # Create new DSA instance with `g` = `p` + 1
    dsa = DSA(p, q, g=p+1)
    x, y = dsa.generate_keypair()

    # Part 1: try to verify a valid signature
    message = b"Hello world!"
    sig, _ = dsa.sign(message, x)
    assert dsa.verify(message, sig, y)

    # Part 2: Try to obtain the magic signature that will verify every message
    # Let's pick z=1 to keep things simple
    r2 = (y % p) % q
    s2 = r2 % q
    sig2 = (r2, s2)

    # Verify two arbitrary strings against the same signature
    assert_true(dsa.verify(b"Hello, world", sig2, y) and dsa.verify(b"Goodbye, world", sig2, y))


## Challenge 46
def rsa_oracle_plaintext_even(ciphertext, priv):
    return set5.encrypt_rsa(ciphertext, priv) % 2 == 0

@challenge(6, 46)
def challenge_46():
    print()
    # Get message, create RSA keypair, generate ciphertext
    message = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
    pub, priv = set5.set_up_rsa(e=3, keysize=1024)
    ciphertext = set5.encrypt_rsa(set5.bytes_to_int(message), pub)
    # Set up our Oracle
    oracle = lambda x: rsa_oracle_plaintext_even(x, priv)
    # Verify the keypair works
    assert set5.int_to_bytes(set5.encrypt_rsa(ciphertext, priv)) == message
    # Set initial lower and upper bound, as well as intermediate ciphertext
    lower_bound, upper_bound = 0, pub[1]
    ciphertext_ = ciphertext

    # Perform the below until the lower and upper bound converge
    while upper_bound != lower_bound:
        # Multiply plaintext by multiplying ciphertext by 2**`e` mod `N`
        ciphertext_ = (ciphertext_ * set5.modexp(2, pub[0], pub[1])) % pub[1]
        # If the oracle says True, update the upper bound; if False, update the lower bound
        if oracle(ciphertext_):
            upper_bound = floor(upper_bound + lower_bound, 2)
        else:
            lower_bound = floor(upper_bound + lower_bound, 2)
        # Create 'Holywood style' output
        intermediate_result = str(set5.int_to_bytes(upper_bound))[:os.get_terminal_size().columns - 1]
        fill = " " * (os.get_terminal_size().columns - 1 - len(intermediate_result))
        print(colorama.Cursor.UP(1) + intermediate_result + fill)

    # Print final outputs
    print(colorama.Cursor.UP(1) + "Result:   {}".format(set5.int_to_bytes(upper_bound)))
    print("Original: {}".format(message))

## Challenge 47
# PKCS oracle: check if given ciphertext results in PKCS conforming plaintext
def rsa_oracle_02(ciphertext, priv):
    plaintext = set5.int_to_bytes(set5.encrypt_rsa(ciphertext, priv)).rjust((priv[1].bit_length() + 7) // 8, b'\x00')
    return plaintext[0:2] == b'\x00\x02'

# Create a PKCS conformant message
def pad_PKCS(plaintext, k):
    return b'\x00\x02' + (b'\xff' * (k - len(plaintext) - 3)) + b'\x00' + plaintext

# Custom ceil/floor functions to ensure desired behaviour
def ceil(x, y):
    r = x // y
    if x % y:
        r += 1
    return r

def floor(x, y):
    return x // y

class bleichenbacher98:
    def __init__(self, ciphertext, pub, oracle):
        # Set up initial parameters for bleichenbacher98 attack
        self.e, self.N = pub[0], pub[1]
        k = (self.N.bit_length() + 7) // 8
        self.B = 2 ** (8 * (k - 2))
        self.M = [(2*self.B, 3*self.B - 1)]
        self.c = ciphertext
        self.oracle = oracle
        self.s = -1

    # Step 2a
    def Step2a(self):
        pbar = tqdm(desc='Step 2A')
        # Start at (N // 3B)
        s = ceil(self.N, 3*self.B)
        while True:
            pbar.update(1)
            # Generate `c_1`
            c1 = (self.c * set5.modexp(s, self.e, self.N)) % self.N
            # See if `c(s)^e mod N` is PKCS conforming
            if self.oracle(c1):
                pbar.set_description('Step 2A: Initial s found ({})'.format(s))
                pbar.close()
                # Return found value `s`
                return s % self.N
            s += 1

    # Step 2c
    def Step2c(self, M, s, pbar2):
        # For all (a, b) pairs:
        for (a, b) in M:
            # Compute `r`
            r = ceil(2 * (b*s - 2*self.B), self.N)
            t = True
            while t:
                pbar2.update(1)
                # Compute `S_{min}`, `S_{max}`
                Smin, Smax = ceil(2*self.B + r*self.N, b), ceil(3*self.B + r*self.N, a) + 1
                # If `S_{min}` exceeds `S_{max}`, go to the next (a, b) pair
                if Smin >= Smax: t = False
                # For all integers in range `(S_{min}, S_{max})`:
                for s in range (Smin, Smax):
                    # Generate `ci`
                    ci = (self.c * set5.modexp(s, self.e, self.N)) % self.N
                    # See if `c(s)^e mod N` is PKCS conforming
                    if self.oracle(ci):
                        pbar2.set_description(('Step 2C: Intermediate s found ({})'.format(s))[:os.get_terminal_size().columns - 33])
                        # Return found value `s`
                        return s
                # If no `s` was found, try next `r`
                r += 1
        # If all pairs in `M` are exhausted and yet no `s` was found, raise an exception
        raise Exception("No values found")

    # Step 3
    def Step3(self, M, s):
        # Initialise result set
        R = []
        # For all pairs (a, b) in M:
        for (a, b) in M:
            # Compute `R_{min}` and `R_{max}`
            Rmin, Rmax = ceil(a*s - 3*self.B + 1, self.N), floor(b*s - 2*self.B, self.N) + 1
            # Make sure `R_{min}` is smaller than `R_{max}`
            assert Rmin <= Rmax
            # For all values in range `(R_{min}, R_{max})`:
            for r in range(Rmin, Rmax):
                # Compute values `x` and `y`
                x = max(a, ceil(2*self.B + r*self.N, s))
                y = min(b, floor(3*self.B - 1 + r*self.N, s))
                # If `x` is bigger than `y`, try the next value for `r`
                if x > y: continue
                # Append the found `(x, y)` to the result set
                R.append((x, y))
        # Return the result set
        return R

    def solve(self):
        # Perform step 2A, followed by step 3
        self.s = self.Step2a()
        self.M = self.Step3(self.M, self.s)
        pbar2 = tqdm(desc='Step 2C')
        while True:
            # Step 4: If `M` contains only one interval of length 1, then we found our solution
            if self.M[0][0] == self.M[0][1]:
                pbar2.set_description(('Step 2C: Final s found ({})'.format(self.M[0][0]))[:os.get_terminal_size().columns - 33])
                pbar2.close()
                return b'\x00' + set5.int_to_bytes(self.M[0][0])
            # If not, perform step 2C followed by step 3, and try again
            self.s = self.Step2c(self.M, self.s, pbar2)
            self.M = self.Step3(self.M, self.s)


@challenge(6, 47)
def challenge_47():
    # Set up new RSA instance
    pub, priv = set5.set_up_rsa(e=3, keysize=256)
    # Prepare message
    message = pad_PKCS(b'kick it, CC', k=(pub[1].bit_length() + 7) // 8)
    # Get ciphertext using generated RSA instance
    ciphertext = set5.encrypt_rsa(set5.bytes_to_int(message), pub)
    # Set up our Oracle
    oracle = lambda x: rsa_oracle_02(x, priv)
    assert oracle(ciphertext)

    # Perform the actual attack: set up bleichenbacher98 instance
    bb98 = bleichenbacher98(ciphertext, pub, oracle)
    # Run the attack
    found_message = bb98.solve()
    print("Found message:", found_message)

    # Verify the found message equals our original plaintext
    assert_true(found_message == message)

## Challenge 48
@challenge(6, 48)
def challenge_48():
    # Set up new RSA instance, this time with bigger key length
    pub, priv = set5.set_up_rsa(e=3, keysize=768)
    # Prepare message
    message = pad_PKCS(b'I don\'t know, Marge. Trying is the first step towards failure - Homer Simpson', k=(pub[1].bit_length() + 7) // 8)
    # Get ciphertext using generated RSA instance
    ciphertext = set5.encrypt_rsa(set5.bytes_to_int(message), pub)
    # Set up our Oracle
    oracle = lambda x: rsa_oracle_02(x, priv)
    assert oracle(ciphertext)

    # Perform the actual attack: set up bleichenbacher98 instance
    bb98 = bleichenbacher98(ciphertext, pub, oracle)
    # Run the attack
    found_message = bb98.solve()
    print("Found message:", found_message)

    # Verify the found message equals our original plaintext
    assert_true(found_message == message)

## Execute individual challenges
if __name__ == '__main__':
    challenge_41()
    challenge_42()
    challenge_43()
    challenge_44()
    challenge_45()
    challenge_46()
    challenge_47()
    challenge_48()
