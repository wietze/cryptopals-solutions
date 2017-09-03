import random

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
    assert r == secret


## Execute individual challenges
if __name__ == '__main__':
    challenge_41()
