from challenges import challenge
import random
import base64
import set1
# From: https://cryptopals.com/sets/2

# Challenge 9
def pkcs7_add_padding(input, length):
    # If {length} is smaller than the length of {input}, multiply it until it is big enough
    if length < len(input): length = len(input) + (length - (len(input) % length))
    # Find the difference between the input length and the wanted length
    difference = length - len(input)
    # Return the input plus the padding in PKCS7 format
    return input + bytes([difference for i in range(difference)])

@challenge(2, 9)
def challenge_9():
    pkcs7_add_padding(bytes("YELLOW SUBMARINE", 'utf-8'), 20) == bytes("YELLOW SUBMARINE\x04\x04\x04\x04", 'utf-8')
    print("Pass")


## Challenge 10
def encrypt_aes_ecb(text, key, padding = True):
    from Crypto.Cipher import AES
    # Create new AES object with the given key in ECB mode
    obj = AES.new(key, AES.MODE_ECB)
    if padding:
        # Compute the padding necessary to make the length of the input text a multiple of len(key)
        padding = len(key) - len(text) % len(key)
        # Apply padding
        text = pkcs7_add_padding(text, len(text) + padding)
    # Encrypt given text
    return obj.encrypt(text)

assert set1.unpad(set1.decrypt_aes_ecb(encrypt_aes_ecb(bytes("O Brave New World", 'utf-8'), "YELLOW SUBMARINE"), "YELLOW SUBMARINE")) == bytes("O Brave New World", 'utf-8')

def decrypt_aes_cbc(text, key, iv):
    # Create blocks of the key's length each
    blocks = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
    results = []
    for i, block in enumerate(blocks):
        # Decrypt the current block with the given key
        deciphered_block = set1.decrypt_aes_ecb(block, key)
        # XOR the deciphered block with the IV
        xored_deciphered_block = set1.XOR(deciphered_block, iv)
        # Decode the result as a string, and add it to the result set
        results.extend(xored_deciphered_block)
        # Set the IV of the next block as the current block's ciphertext
        iv = block
    # Return the unpadded result
    return set1.unpad(bytes(results))

@challenge(2, 10)
def challenge_10():
    # Open file, read to string
    with open("inputs/10.txt") as file:
        lines = file.read()
    # Obtain plaintext by deciphering given text under the known key with the known IV
    plaintext = decrypt_aes_cbc(base64.b64decode(lines), "YELLOW SUBMARINE", bytes('\x00','utf-8') * 16)
    # Print the result
    print(str(plaintext, 'utf-8'))


## Challenge 11
def random_bytes(length):
    return bytes([random.randrange(0, 256) for i in range(length)])

def encrypt_aes_cbc(text, key, iv):
    # Add padding, if neccessary
    text = pkcs7_add_padding(text, len(text) + (len(key) - len(text) % len(key)))
    # Create blocks of the key's length each
    blocks = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
    results = []
    for i, block in enumerate(blocks):
        # XOR the plaintext block with the IV
        xored_block = set1.XOR(block, iv).zfill(len(iv))
        # Encrypt the output with the given key
        xored_ciphered_block = encrypt_aes_ecb(xored_block, key, False)
        # Decode the result as a string, and add it to the result set
        results.extend(xored_ciphered_block)
        # Set the IV of the next block as the current block's ciphertext
        iv = xored_ciphered_block

    return bytes(results)

iv = bytes([0 for i in range(16)])
assert decrypt_aes_cbc(encrypt_aes_cbc(bytes('Be thine my vision, O Lord of my heart', 'utf-8'), 'YELLOW SUBMARINE', iv), 'YELLOW SUBMARINE', iv) == bytes('Be thine my vision, O Lord of my heart', 'utf-8')

def encrypt_aes_ecb_keyless(text, key = random_bytes(16)):
    # Create random prefix, suffix and iv (in case cbc is chosen)
    prefix = random_bytes(random.randrange(5, 10))
    suffix = random_bytes(random.randrange(5, 10))
    iv = random_bytes(16)
    # Construct text to be encrypted
    text = prefix + text + suffix
    # With a probability of 0.5, pick ECB or CBC
    if random.randrange(0,2) == 0:
        print('Encrypted with: ECB')
        return encrypt_aes_ecb(text, key)
    else:
        print('Encrypted with: CBC')
        return encrypt_aes_cbc(text, key, iv)

def encryption_oracle(encryption_function):
    # Strategy: we control the input string. If we now make the input long enough, we will get duplicate blocks if ECB is chosen (see challenge 8, set 1).

    # Create plaintext of 16 * 4 = 64 bytes long, all with the same characters
    plaintext = bytes('X' * (16 * 4), 'utf-8')
    # Call the given function with the created plaintext to obtain ciphertext
    cipher_text = encryption_function(plaintext)
    # Test for number of duplicate chunks, if not zero then probably ECB was used
    return "ECB" if set1.duplicate_chunks(cipher_text) != 0 else "CBC"

@challenge(2, 11)
def challenge_11():
    for i in range(3):
        print("Guess: {}".format(encryption_oracle(encrypt_aes_ecb_keyless)))


## Challenge 12
magic_string = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

def special_encryption(plaintext, key):
    return encrypt_aes_ecb(plaintext + magic_string, key)

def bruteforce_ecb_key(key, start = b''):
    # Assumptions:
    # - The length of the magic string is known.

    # Stop when we have found all characters in the magic string
    if len(start) >= len(magic_string): return start

    # Find the nearest multiple of len(key) after len(magic_string)
    block_size = len(magic_string) + (len(key) - len(magic_string) % len(key))
    # Construct our new 'known plaintext'
    new_plaintext = (b'X' * (block_size - len(start) - 1))
    # Encrypt our known plaintext using the special encryption function
    ciphertext = special_encryption(new_plaintext, key)
    # Create a list with all possible plaintexts for the first {block_size} bytes. We already know the first {block_size}-1 bytes, so we only have to guess the last one
    possible_plaintexts = [(special_encryption(new_plaintext + start + bytes([x]), key),x) for x in range(0, 256)]
    # Now filter all possible plaintext to find the entry of which the first {block_size} bytes match the first {block_size} bytes of the output of {cipher_text}
    matches = list(filter(lambda x: x[0][0:block_size] == ciphertext[0:block_size], possible_plaintexts))
    assert(len(matches) == 1)

    # Using the new information (i.e. the new byte found), start looking for the next byte
    return bruteforce_ecb_key(key, start + bytes([matches[0][1]]))

@challenge(2, 12)
def challenge_12():
    key = random_bytes(16)
    assert bruteforce_ecb_key(key) == magic_string
    print("Pass")


## Challenge 13
def query_parser(input):
    result = {}
    for pair in input.split('&'):
        k, v = pair.split('=')
        assert k not in result
        result[k] = v
    return result

def obj_to_query(input):
    return '&'.join([k +'='+str(v) for (k,v) in input.items()])

def profile_for(input):
    new_obj = {'email': input.replace('&', '').replace('=', ''), 'uid': 10, 'role': 'user'}
    return obj_to_query(new_obj)

def get_oracles():
    key = random_bytes(16)
    return lambda x: encrypt_aes_ecb(x, key), lambda x: set1.unpad(set1.decrypt_aes_ecb(x, key))

@challenge(2, 13)
def challenge_13():
    # Get the encryption and decryption oracles
    enc_oracle, dec_oracle = get_oracles()

    # Using the encryption oracle, generate two valid blocks containing email, uid in full and role header
    profile = bytes(profile_for('x' * 13), 'utf-8')
    ciphertext = enc_oracle(profile)
    part_1 = ciphertext[:32] # represents: email=xxxxxxxxxxxxx&uid=10&role=

    # Using the encryption oracle, generate a block that only contains 'admin' and padding characters
    profile = bytes(profile_for('x' * 10 + "admin" + (chr(11) * 11)), 'utf-8')
    ciphertext = enc_oracle(profile)
    part_2 = ciphertext[16:32] # represents: admin\x0B*11

    # Concatenate the two parts to get ciphertext for:
    # email=xxxxxxxxxxxxx&uid=10&role=admin\x0B*11
    constructed_ciphertext = part_1 + part_2

    # Using the decryption oracle and the constructed ciphertext, get the parsed profile
    plaintext = str(dec_oracle(constructed_ciphertext), 'utf-8')
    created_profile = query_parser(plaintext)

    # Make sure the role was spoofed successfully
    assert created_profile['role'] == 'admin'
    print('Pass')


## Challenge 14
def bruteforce_ecb_key_2(encrypt, found_bytes = b''):
    # Assumptions:
    # - The prefix is random, but constant.
    # - The length of the magic string is known.

    # Stop when all characters in the magic string were found
    if len(found_bytes) >= len(magic_string): return found_bytes

    # Determine the output length when an empty input was given
    length = len(encrypt(b''))
    # Determine the block size by incrementing the input by one and observing if the output size changes
    for i in range(1, 64):
        new_length = len(encrypt(b'X' * i))
        if length < new_length:
            block_size = new_length - length
            break

    # Given we know the size of the magic string, we now also know the size of the prefix
    random_bytes_length = length - len(magic_string) - i

    # To fill the prefix block, we append {block_size} - {random_bytes_length} characters
    prefix = b'X' * (block_size - random_bytes_length)

    # Fill the magic string block, append an extra character to push the byte we're interested in into the first position of a new block, and add the length of the bytes we already know
    suffix = b'X' * (block_size - (len(magic_string) % block_size) + 1 + len(found_bytes))

    # Determine the number of padding bytes (= {block_size} - number of bytes we know - the one we're guessing)
    k = block_size - (len(found_bytes) % block_size) - 1

    # Now construct the inputs as {prefix} + guessed character + {found_bytes} + padding + {suffix}
    # For each of these inputs, determine the number of duplicate blocks
    options = [(c, set1.duplicate_chunks(encrypt(prefix + bytes([c]) + found_bytes + (bytes([k]) * k) + suffix))) for c in range(0, 256)]

    # Find the byte candidate with the highest number of duplicate blocks
    match = max(options, key=lambda x: x[1])[0]

    # Using the new information (i.e. the new byte found), start looking for the next byte
    return bruteforce_ecb_key_2(encrypt, bytes([match]) + found_bytes)

@challenge(2, 14)
def challenge_14():
    # Intialise the encryption function that will be used
    key = random_bytes(16)
    prefix = random_bytes(random.randrange(1,16))
    encrypt = lambda x: encrypt_aes_ecb(prefix + x + magic_string, key)

    # Brute force the magic string
    assert bruteforce_ecb_key_2(encrypt) == magic_string
    print("Pass")


## Challenge 15
def pkcs7_remove_padding(text, block_size = 16):
    # Check if text is multiple of given {block_size}
    if len(text) % block_size != 0: raise ValueError("Invalid length")
    # Get the length by obtaining the ordinal value of the last character in the given text
    length = ord(text[len(text) - 1:])
    # Check if the last {length} characters are equal to \x{length}
    for i in range(1, length + 1):
        if text[-i] != length: raise ValueError("Invalid padding")
    # Return the input, bar the padding
    return text[:-length]

@challenge(2, 15)
def challenge_15():
    try:
        print(pkcs7_remove_padding(b'ICE ICE BABY\x04\x04\x04\x04'))
    except Exception as error: print("Caught: " + repr(error))
    try:
        print(pkcs7_remove_padding(b"ICE ICE BABY\x05\x05\x05\x05"))
    except Exception as error: print("Caught: " + repr(error))
    try:
        print(pkcs7_remove_padding(b"ICE ICE BABY\x01\x02\x03\x04"))
    except Exception as error: print("Caught: " + repr(error))


## Challenge 16
def challenge_16_encryption(plaintext, key, iv):
    # Initialise prefix and suffix
    prefix = b"comment1=cooking%20MCs;userdata="
    suffix = b";comment2=%20like%20a%20pound%20of%20bacon"
    # Generate the full plaintext, which is about to be encrypted
    text = pkcs7_add_padding(prefix + bytes(plaintext.replace(';','').replace('&', ''), 'utf-8') + suffix, 16)
    # Return ciphertext
    return encrypt_aes_cbc(text, key, iv)

def challenge_16_admin_check(ciphertext, key, iv):
    # Obtain plaintexzt
    deciphered = decrypt_aes_cbc(ciphertext, key, iv)
    plaintext = pkcs7_remove_padding(deciphered)
    # Parse text as object
    items = {x:y for x, y in [z.split(b'=') for z in plaintext.split(b';')]}
    # Check whether 'admin' property is in object, and is set to 'true'
    return b'admin' in items and items[b'admin'] == b'true'

@challenge(2, 16)
def challenge_16():
    # Intialise the encryption parameters
    iv = random_bytes(16)
    key = random_bytes(16)

    # Generate ciphertext for our string
    ciphertext = bytearray(challenge_16_encryption('-admin-true', key, iv))

    # Replace the 16th character with the XOR of itself with '-' and ';'
    # Note that AES CBC will XOR this again with the 16th character and '-',
    # hence resulting in ';'. Same strategy for the 22nd character.
    ciphertext[16] = set1.XOR(set1.XOR(bytes([ciphertext[16]]), b'-'), b';')[0]
    ciphertext[22] = set1.XOR(set1.XOR(bytes([ciphertext[22]]), b'-'), b'=')[0]

    try:
        # Verify this modified ciphertext will now parse 'admin':'true'
        assert challenge_16_admin_check(bytes(ciphertext), key, iv)
    except ValueError as error:
        # This may happen if the second block outputs an '=' or '&' by accident
        print('Invalid string formed, trying again')
        challenge_16()

    print('Pass')


## Execute individual challenges
if __name__ == '__main__':
    challenge_9()
    challenge_10()
    challenge_11()
    challenge_12()
    challenge_13()
    challenge_14()
    challenge_15()
    challenge_16()
