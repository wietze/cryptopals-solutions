import random
import hashlib

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

    def intercept_bob_receive(self, inp):
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

## Execute individual challenges
if __name__ == '__main__':
    challenge_33()
    challenge_34()
