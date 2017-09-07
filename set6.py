import random
import hashlib
import re

from challenges import challenge, assert_true
import set1, set2, set3, set4, set5
# From: https://cryptopals.com/sets/6

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

## Execute individual challenges
if __name__ == '__main__':
    challenge_41()
    challenge_42()
