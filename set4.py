import random
import base64
import math
from challenges import challenge, assert_true
import set1, set2, set3


# From: https://cryptopals.com/sets/4

## Challenge 25
def edit_ctr_stream(ciphertext, key, nonce, offset, newtext):
    # Verify given parameters are within the allowed bounds
    assert 0 <= offset and offset + len(newtext) <= len(ciphertext)
    # Generate  the ciphertext for {offset} dummy byes appended with {newtext}
    fake_data = b'\x00' * offset + newtext
    new_ciphertext = set3.encrypt_aes_ctr(fake_data, key, nonce)
    # Return the original {offset} bytes of {ciphertext}, plus the relevant bytes of {new_ciphertext}, plus the remainder of {ciphertext}
    return ciphertext[:offset] + new_ciphertext[offset:offset+len(newtext)] + ciphertext[offset+len(newtext):]

def find_ctr_plaintext(ciphertext, replace_function):
    # Simply replace all bytes with zero bytes, giving us the full key stream
    new_ciphertext = replace_function(ciphertext, 0, b'\x00' * len(ciphertext))
    # XOR with the ciphertext to get the corresponding plaintext
    return bytes([x ^ y for x, y in zip(ciphertext, new_ciphertext)])

@challenge(4, 25)
def challenge_25():
    key = set2.random_bytes(16)
    nonce = random.randrange(1,10**10)
    # Get plaintext
    with open('inputs/25.txt') as file:
        contents = base64.b64decode(file.read())
    plaintext = set2.pkcs7_remove_padding(set1.decrypt_aes_ecb(contents, 'YELLOW SUBMARINE'))
    # Generate ciphertext
    ciphertext = set3.encrypt_aes_ctr(plaintext, key, nonce)
    # Create vulnerable function
    def vulnerable_ctr_stream_edit_function(ciphertext, offset, newtext):
        return edit_ctr_stream(ciphertext, key, nonce, offset, newtext)
    # Find the plaintext using the above function
    obtained_plaintext = find_ctr_plaintext(ciphertext, vulnerable_ctr_stream_edit_function)
    # Verify found plaintext matches with the original plaintext
    assert_true(obtained_plaintext == plaintext)


## Challenge 26
def challenge_26_encryption(plaintext, key, nonce):
    # Initialise prefix and suffix
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    # Generate the full plaintext, which is about to be encrypted
    text = set2.pkcs7_add_padding(prefix + bytes(plaintext.replace(';','').replace('&', ''), 'utf-8') + suffix, 16)
    # Return ciphertext
    return set3.encrypt_aes_ctr(text, key, nonce)

def challenge_26_admin_check(ciphertext, key, nonce):
    # Obtain plaintexzt
    plaintext = set2.pkcs7_remove_padding(set3.decrypt_aes_ctr(ciphertext, key, nonce))
    # Parse text as object
    items = {x:y for x, y in [z.split(b'=') for z in plaintext.split(b';')]}
    # Check whether 'admin' property is in object, and is set to 'true'
    return b'admin' in items and items[b'admin'] == b'true'

@challenge(4, 26)
def challenge_26():
    # Intialise the encryption parameters
    nonce = random.randrange(1, 10**10)
    key = set2.random_bytes(16)

    # Generate ciphertext for our string
    ciphertext = bytearray(challenge_26_encryption('-admin-true', key, nonce))

    # Replace the 32th character with the XOR of itself with '-' and ';'
    # Note that AES CTR will XOR this again with the key stream,
    # hence resulting in ';'. Same strategy for the 38th character.
    ciphertext[32] = ciphertext[32] ^ ord('-') ^ ord(';')
    ciphertext[38] = ciphertext[38] ^ ord('-') ^ ord('=')

    assert_true(challenge_26_admin_check(bytes(ciphertext), key, nonce))

## Execute individual challenges
if __name__ == '__main__':
    challenge_25()
    challenge_26()
