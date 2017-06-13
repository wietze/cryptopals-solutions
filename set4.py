import random
import base64
import math
import external.slowsha
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


## Challenge 27
def challenge_27_encryption(plaintext, key):
    iv = key
    # Initialise prefix and suffix
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    # Generate the full plaintext, which is about to be encrypted
    text = set2.pkcs7_add_padding(prefix + bytes(plaintext.replace(';','').replace('&', ''), 'utf-8') + suffix, 16)
    # Return ciphertext
    return set2.encrypt_aes_cbc(text, key, iv)

def challenge_27_check_decrypt(ciphertext, key):
    # Obtain plaintext
    deciphered = set2.decrypt_aes_cbc(ciphertext, key, iv=key, unpad=False)
    #plaintext = set2.pkcs7_remove_padding(deciphered)
    for byte in deciphered:
        if byte > 128: raise ValueError("Invalid ASCII obtained in text", deciphered)
    return True

@challenge(4, 27)
def challenge_27():
    # Intialise the encryption parameters
    key = set2.random_bytes(16)
    # Generate ciphertext for our string
    ciphertext = challenge_27_encryption('whatevah', key)
    # Modify the ciphertext such that it is equal to c_1 + 0 + c_2
    ciphertext = ciphertext[0:16] + b'\x00'*16 + ciphertext[0:16]
    try:
        # Verify this modified ciphertext will now parse 'admin':'true'
        assert_true(challenge_27_check_decrypt(ciphertext, key))
    except ValueError as error:
        # Extract the deciphered text from the exception
        plaintext = error.args[1]
        # XOR p_1 with p_3
        derived_key = bytes([x ^ y for x, y in zip(plaintext[0:16], plaintext[32:48])])
        # Verify the derived key equals the original key
        assert_true(derived_key == key)


## Challenge 28
def simple_mac(key, message, digest=True):
    # Using SHA-1 implementation from 'slowsha' (https://github.com/sfstpala/SlowSHA)
    sha_hash = external.slowsha.SHA1(key + message)
    return sha_hash.digest() if digest else sha_hash

def mac_tamper(key, original_message, original_mac):
    # Iterate over all characters in the original message
    for i, _ in enumerate(original_message):
        # Copy the original message
        altered_message = bytearray(original_message)
        # Try to find a new, pseudo-random value for the selected byte
        while altered_message[i] == original_message[i]:
            altered_message[i] = random.randrange(1, 256)
        # Compute hamming distance between the original mac and the mac of the altered message
        hdistance = set1.hamming_distance(simple_mac(key, bytes(altered_message)), original_mac)
        # Verify the hamming distance is not too small
        if hdistance < 10: raise Exception("Small hamming distance! ({})".format(hdistance))
    return True

@challenge(4, 28)
def challenge_28():
    # Generate random key, message
    key = set2.random_bytes(16)
    message = set2.random_bytes(random.randrange(128, 1024))
    # Compute mac for the generated key and message
    original_mac = simple_mac(key, message)
    # Verify changing a byte will change the mac significantly
    assert_true(mac_tamper(key, message, original_mac))
    # (note 1: it is not trivial to prove you cannot tamper with the message without breaking the MAC)
    # (note 2: you can't prove it isn't possible to produce a new MAC without knowing the secret key,
    #          since we're mapping strings of arbitrary lengths to a string of a finite length)


## Challenge 29
def bits_to_bytes(result):
    assert len(result) % 8 == 0
    return bytes([int(result[x * 8:(x + 1) * 8], 2) for x in list(range(0, len(result) // 8))])

def get_sha1_padding(message):
    # Copied from the original SHA-1 function, with the _handle() calls removed
    length = bin(len(message) * 8)[2:].rjust(64, "0")
    while len(message) > 64:
        message = message[64:]
    result = "1" + "0" * ((447 - (len(message)*8) % 512) % 512) + length
    return bits_to_bytes(result)

@challenge(4, 29)
def challenge_29():
    # Generate random key of random number of bytes
    key = set2.random_bytes(random.randrange(4, 40))
    # Prepare validation function
    def validate_mac(message, digest):
        return simple_mac(key, message, False).hexdigest() == digest.hexdigest()
    # Prepare message to sign
    msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    # Generate genuine mac of the message
    original_mac = simple_mac(key, msg, False)
    # Obtain a, b, c, d and e
    abcde = original_mac._digest()
    # Prepare string to inject
    string_to_inject = b";admin=true"
    # Create a forged mac:
    # - The forged length is {msg} and it's padding (hence a multiple of 64), plus the length of our injected string
    # - We feed the SHA-1 instance the [a-e] parameters obtained from the original MAC
    forged_mac = external.slowsha.SHA1(string_to_inject, math.ceil(len(msg) / 64) * 64 + len(string_to_inject), abcde)
    # To figure out what message we actually signed, we need to figure out what the padding was of the original HMAC
    # Because we don't know the key, we have to guess the key length
    for key_length_guess in range(4, 41):
        # Compose the candidate message based on the key length guess
        signed_msg_guess = msg + get_sha1_padding(b'\x00'*key_length_guess + msg) + string_to_inject
        # Verify the validity of the guessed message with the forged mac
        if validate_mac(signed_msg_guess, forged_mac):
            print("Successfully forged message - key used had length {}".format(key_length_guess))
            assert_true(True)
            return
    raise Exception("Could not fake HMAC")


## Execute individual challenges
if __name__ == '__main__':
    challenge_25()
    challenge_26()
    challenge_27()
    challenge_28()
    challenge_29()
