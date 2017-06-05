import random
import base64
import struct
import time
import math
from challenges import challenge, assert_true
import set1, set2


# From: https://cryptopals.com/sets/3

## Challenge 17
def function_1(key):
    string_set = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=", "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=", "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==", "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==", "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl", "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==", "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==", "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=", "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=", "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]
    selected_string = base64.b64decode(random.choice(string_set))
    iv = set2.random_bytes(16)
    ciphertext = set2.encrypt_aes_cbc(selected_string, key, iv)
    return ciphertext, iv

def function_2(ciphertext, key, iv):
    try:
        decrypt_aes_cbc_2(ciphertext, key, iv)
        return True
    except ValueError:
        return False

def decrypt_aes_cbc_2(text, key, iv):
    # Create blocks of the key's length each
    blocks = [text[i:i+len(key)] for i in range(0, len(text), len(key))]
    results = []
    for _, block in enumerate(blocks):
        # Decrypt the current block with the given key
        deciphered_block = set1.decrypt_aes_ecb(block, key)
        # XOR the deciphered block with the IV
        xored_deciphered_block = set1.XOR(deciphered_block, iv)
        # Decode the result as a string, and add it to the result set
        results.extend(xored_deciphered_block)
        # Set the IV of the next block as the current block's ciphertext
        iv = block
    return set2.pkcs7_remove_padding(bytes(results))

def aes_oracle_attack(oracle, ciphertext, iv):
    # Determine number of blocks
    number_of_blocks = len(ciphertext)//16
    # Prepend IV to given ciphertext (as it is the 'previous' block for the first cipher text block)
    ciphertext = bytearray(iv) + bytearray(ciphertext)
    #Initialise result byte array
    result = bytearray()
    # Iterate over ciphertext blocks
    for block in range(number_of_blocks):
        block_result = bytearray()
        for padding_value in range(1, 17):
            # Select window, i.e. block being investigated plus the previous block
            ct = ciphertext[block * 16:(block + 2) * 16]
            # Set the bytes that have been recovered already
            # by XORing the ciphertext value with the found plaintext and the padding value for this round
            for i, plaintext in enumerate(block_result, start=1):
                ct[16 - i] = padding_value ^ ct[16 - i] ^ plaintext
            for guessed_value in range(256):
                # Modify the ciphertext of the previous block to the guesesed value
                ct[16 - padding_value] = guessed_value
                # Test if padding is correct
                if oracle(bytes(ct)):
                    # If so, find plaintext character by XORing the guessed value with the value it must have resulted in (=`padding_value`) XORed with the original ciphertext character
                    found_plaintext = padding_value ^ ciphertext[(block * 16) + (16 - padding_value)] ^ guessed_value
                    if len(block_result) != padding_value:
                        # Append found plaintext character to block_result
                        block_result.append(found_plaintext)
                        if found_plaintext != 1: break
                    else:
                        if found_plaintext > block_result[-1]: block_result[-1] = found_plaintext
        # Prepend our block result to the overall result
        result = block_result + result
    # Reverse the byte order, unpad it and return it as the found plaintext
    result.reverse()
    result = set2.pkcs7_remove_padding(result)
    return result

@challenge(3, 17)
def challenge_17():
    # Initialise key
    key = set2.random_bytes(16)
    # Call function_1 to get random ciphertext with IV used
    ciphertext, iv = function_1(key)
    # For verification purposes, decrypt given ciphertext with key
    expected = set2.decrypt_aes_cbc(ciphertext, key, iv)
    print('Expected: {}'.format(expected))
    # Initialise oracle function
    oracle = lambda x: function_2(x, key, iv)
    # Run oracle attack
    result = aes_oracle_attack(oracle, ciphertext, iv)
    print('Found:    {}'.format(bytes(result)))
    # Verify found answer equals what we're expecting
    assert_true(result == expected)
    print("")


## Challenge 18
def encrypt_aes_ctr(data, key, nonce, block_size=16):
    # Turn nonce into Little Endian, unsigned 8 byte int
    nonce_le = struct.pack('<Q', nonce)
    # Get number of blocks required
    blocks = math.ceil(len(data) / block_size)
    output = b''
    # Iterate over blocks in {data}
    for block in range(blocks):
        # Construct plaintext for AES encryption by taking {nonce_le} and appending the block number in Little Endian, unsigned 8 byte int format
        plaintext = nonce_le + struct.pack('<Q', block)
        # Obtain ciphertext by encrypting the above under the given key (without applying padding)
        ciphertext = set2.encrypt_aes_ecb(plaintext, key, False)
        # XOR the obtained ciphertext with the current block of {data} being processed, and append it to {output}
        output += bytes([x ^ y for x, y in zip(ciphertext, data[block * 16:(block + 1) * 16])])
    return output

# CTR decryption is the same as CTR encryption
decrypt_aes_ctr = encrypt_aes_ctr

@challenge(3, 18)
def challenge_18():
    # Test given string
    test_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
    assert_true(decrypt_aes_ctr(base64.b64decode(test_string), "YELLOW SUBMARINE", 0) == b'Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ')

    # Generate random data, nonce and key, test if decrypting after encrypting results in the generated data again.
    data = set2.random_bytes(64)
    nonce = random.randint(128, 65536)
    key = set2.random_bytes(16)
    assert_true(data == decrypt_aes_ctr(encrypt_aes_ctr(data, key, nonce), key, nonce))


## Challenge 19
def frequency_score(data):
    frequencies = {'a':0.0651738, 'b':0.0124248, 'c':0.0217339, 'd':0.0349835, 'e':0.1041442, 'f':0.0197881, 'g':0.0158610, 'h':0.0492888, 'i':0.0558094, 'j':0.0009033, 'k':0.0050529, 'l':0.0331490, 'm':0.0202124, 'n':0.0564513, 'o':0.0596302, 'p':0.0137645, 'q':0.0008606, 'r':0.0497563, 's':0.0515760, 't':0.0729357, 'u':0.0225134, 'v':0.0082903, 'w':0.0171272, 'x':0.0013692, 'y':0.0145984, 'z':0.0007836, ' ':0.1918182}
    # Source: http://www.data-compression.com/english.html
    return sum([frequencies[x] for x in data.lower() if x in frequencies])

def crack_aes_ctr(ciphertexts):
    guessed_key = []
    # Iterate over the number of positions in the given ciphertexts
    for position in range(max([len(x) for x in ciphertexts])):
        # Get all {position}th bytes for all ciphertexts, if the string is long enough
        xth_bytes = [ciphertext[position] for ciphertext in ciphertexts if position < len(ciphertext)]
        outcomes = []
        # XOR each byte in {xth_bytes} with {guess}, our guessed key stream byte
        for guess in range(256):
            outcomes.append((''.join([chr(y ^ z) for y, z in zip(xth_bytes, [guess] * len(xth_bytes))]), guess))
        # Sort the obtained outputs by their frequency score
        sorted_outcomes = sorted(outcomes, key=lambda x: frequency_score(x[0]), reverse=True)
        # Assume the guess with the heigest letter frequency score is part of the key stream
        guessed_key.append(sorted_outcomes[0][1])

    guessed_plaintexts = []
    # 'Decrypt' the ciphertexts by decrypting them byte-by-byte using our {guessed_key}
    for text in ciphertexts:
        guessed_plaintexts.append(bytes([x ^ y for x, y in zip(text, guessed_key[:len(text)])]))
    return guessed_plaintexts

@challenge(3, 19)
def challenge_19():
    # Set fixed once, random key, and initialise plaintexts and ciphertexts
    nonce = 0
    key = set2.random_bytes(16)
    plaintexts = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==', 'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=', 'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==', 'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=', 'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk', 'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=', 'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==', 'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=', 'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl', 'VG8gcGxlYXNlIGEgY29tcGFuaW9u', 'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==', 'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=', 'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==', 'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=', 'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==', 'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==', 'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==', 'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==', 'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==', 'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==', 'U2hlIHJvZGUgdG8gaGFycmllcnM/', 'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=', 'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=', 'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=', 'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=', 'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==', 'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==', 'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=', 'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==', 'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu', 'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=', 'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs', 'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=', 'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0', 'SW4gdGhlIGNhc3VhbCBjb21lZHk7', 'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=', 'VHJhbnNmb3JtZWQgdXR0ZXJseTo=', 'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=']
    ciphertexts = []

    # Create ciphertexts using set key and nonce
    for plaintext in plaintexts:
        ciphertexts.append(encrypt_aes_ctr(base64.b64decode(plaintext), key, nonce))

    # Obtain guessed plaintexts
    guessed_plaintexts = crack_aes_ctr(ciphertexts)

    distance = lambda x, y: sum([1 if x != y else 0 for x, y in zip(x, y)])
    incorrect_byte_count = sum([distance(base64.b64decode(x), y) for x, y in zip(plaintexts, guessed_plaintexts)])
    total_byte_count = sum([len(x) for x in plaintexts])

    # Determine the accuracy of this approach by dividing the number of incorrect guessed plaintext bytes by the total number of bytes
    accuracy = 1 - (incorrect_byte_count / total_byte_count)
    print('Accuracy: {:.2%}'.format(accuracy))
    # Not perfect, but enough to manually debug and find the full original text

    assert_true(accuracy > 0.95)


## Challenge 20
@challenge(3, 20)
def challenge_20():
    # Open file, read to string
    with open("inputs/20.txt") as file:
        lines = file.read().splitlines()
    # Get the ciphertexts
    ciphertexts = [base64.b64decode(line) for line in lines if line.strip() != '']
    # Print the guessed plaintext
    print(crack_aes_ctr(ciphertexts))


## Challenge 21
# Based on https://en.wikipedia.org/wiki/Mersenne_Twister
class MT19937:
    N = 624
    F = 1812433253
    U = 11
    D = 0
    S = 7
    B = 2636928640
    T = 15
    C = 4022730752
    L = 18

    @staticmethod
    def int32(x): return int(0xFFFFFFFF & x)

    def __init__(self, seed):
        self.index = self.N
        self.mt = [seed] + ([0] * (self.N - 1))
        for i in range(1, self.N):
            self.mt[i] = self.int32(self.F * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def generate(self):
        if self.index >= len(self.mt):
            for i in range(self.N):
                y = self.int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % self.N] & 0x7fffffff))
                self.mt[i] = self.mt[(i + 397) % self.N] ^ y >> 1
                if y % 2 != 0:
                    self.mt[i] = self.mt[i] ^ 0x9908b0df
            self.index = 0
        y0 = self.mt[self.index]
        y1 = y0 ^ (y0 >> self.U)
        y2 = y1 ^ ((y1 << self.S) & self.B)
        y3 = y2 ^ ((y2 << self.T) & self.C)
        y = y3 ^ (y3 >> self.L)
        self.index = self.index + 1
        return self.int32(y)

@challenge(3, 21)
def challenge_21():
    prng_instance = MT19937(1234)
    print(prng_instance.generate(), prng_instance.generate(), prng_instance.generate())


## Challenge 22
def generate_prn_with_delay(timestamp):
    # Add a random 40 - 1000 seconds to given timestamp
    timestamp += random.randrange(40, 1000)
    # Seed MT19937 instance
    prng_instance = MT19937(timestamp)
    # Return first number plus the used timestamp (for verification later on)
    return prng_instance.generate(), timestamp

def bruteforce_seed(output, start_timestamp):
    possible_seeds = []
    # Try all possible timestamps between {start_timestamp} + 40 and {start_timestamp} + 1000
    for tested_seed in range(start_timestamp + 40, start_timestamp + 1000):
        # Create new MT19937 instance with guessed seed
        prng_instance = MT19937(tested_seed)
        # If the same as the tested value ({output}), a possible seed was found
        if prng_instance.generate() == output:
            possible_seeds.append(tested_seed)
    # Return list of seeds found
    return possible_seeds

@challenge(3, 22)
def challenge_22():
    # Get UNIX timestamp
    timestamp = int(time.time())
    # Generate a pseudo-random number using a given timestamp, with delay
    output, secret_seed = generate_prn_with_delay(int(time.time()))
    # Now bruteforce the obtained output based on the given timestamp
    found_seeds = bruteforce_seed(output, timestamp)
    # Display number of possible seeds found
    print("{} possible seed{} found".format(len(found_seeds), 's' if len(found_seeds) != 1 else ''))
    # Verify the used seed is in the list of found (possible) seeds
    assert_true(secret_seed in found_seeds)


## Challenge 23
def untemper(y):
    # [1] Because of the bit shift, the first L bits haven't changed;
    # [2] We can recover the remaining 32-L=14 bits by shifting the found bits and XORing it with y, the given value
    #     (because we know y = y3^(y3>>L), thus to recover y3 we have y3 = y^(y3>>L)).
    y3 = most_significant(y, MT19937.L)
    y3 |= get_bits((y3 >> MT19937.L) ^ y, 0, 14)

    # C = 0xEFC60000 = 11101111110001100000000000000000, i.e. the last 17 bits aren't touched by C; therefore:
    # [1] Because of the bit shift, the last T bits haven't changed;
    # [2] We can recover the next T bits by shifting the last 15 bits and XORing it with y3, the given value;
    # [3] Using the found 30 bits, repeat the above to recover the first two bits.
    y2 = least_significant(y3, MT19937.T)
    y2 |= get_bits(((y2 << MT19937.T) & MT19937.C) ^ y3, 15, 15)
    y2 |= get_bits(((y2 << MT19937.T) & MT19937.C) ^ y3, 30, 2)

    # B = 0x9D2C5680 = 10011101001011000101011010000000, i.e. the last 7 bits aren't touched by B; therefore:
    # [1] Because of the bit shift, the last S bits haven't changed;
    # [2] We can recover the next S bits by shifting the last 15 bits and XORing it with y2, the given value;
    # [3] Using the found 14 bits, repeat the above to recover the next 7 bits;
    # [4] Using the found 21 bits, repeat the above to recover the next 7 bits;
    # [5] Using the found 28 bits, repeat the above to recover the first 4 bits.
    y1 = least_significant(y2, MT19937.S)
    y1 |= get_bits(((y1 << MT19937.S) & MT19937.B) ^ y2, 7, 7)
    y1 |= get_bits(((y1 << MT19937.S) & MT19937.B) ^ y2, 14, 7)
    y1 |= get_bits(((y1 << MT19937.S) & MT19937.B) ^ y2, 21, 7)
    y1 |= get_bits(((y1 << MT19937.S) & MT19937.B) ^ y2, 28, 4)

    # [1] Because of the bit shift, the first U bits haven't changed;
    # [2] We can recover the next U bits by shifting the last 10 bits and XORing it with y1, the given value;
    # [3] Using the found 22 bits, repeat the above to recover the last 10 bits.
    y0 = most_significant(y1, MT19937.U)
    y0 |= get_bits((y0 >> MT19937.U) ^ y1, 10, 11)
    y0 |= get_bits((y0 >> MT19937.U) ^ y1, 0, 10)
    return y0

def most_significant(number, bits):
    # Returns the most significant {bits} bits from the given {number} using a mask
    return number & int('1'*bits + '0'*(32-bits), 2)

def least_significant(number, bits):
    # Returns the least significant {bits} bits from the given {number} using a mask
    return number & int('0'*(32-bits) + '1'*bits, 2)

def get_bits(number, _from, length):
    # Returns bits {_from}, {_from}+1, ..., {_from}+length from a given {number} using a mask
    return number & int('0'*(32-_from-length) + '1'*length + '0'*_from, 2)

@challenge(3, 23)
def challenge_23():
    # Create prng instance to clone
    prng_instance = MT19937(13371337)
    generated_values = []
    found_mt_values = []
    # Generate the first N numbers, and try to find the underlying values in the internal MT array using our untemper function
    for _ in range(prng_instance.N):
        generated_values.append(prng_instance.generate())
        found_mt_values.append(untemper(generated_values[-1]))
    # Create a dummy MT19937 instance
    clone_prng_instance = MT19937(0)
    # Set the internal MT array, reset index value to 0
    clone_prng_instance.mt = found_mt_values
    clone_prng_instance.index = 0
    # Using this cloned MT19937 instance, generate the first N values again
    clone_generated_numbers = [clone_prng_instance.generate() for _ in range(MT19937.N)]
    # Verify the results
    assert_true(generated_values == clone_generated_numbers)

## Challenge 24
class MT19937Cipher:
    def __init__(self, seed):
        self.__seed__ = seed
        self.__bytes__ = []

    def __get_stream_byte__(self, prng):
        # If no more bytes are available, let the prng generate a new number and save the individual bytes in {__bytes__}
        if len(self.__bytes__) == 0:
            g = prng.generate()
            self.__bytes__ = [g >> 24 & 0xff, g >> 16 & 0xff, g >> 8 & 0xff, g & 0xff]
        # Return and remove the last element in the list
        return self.__bytes__.pop()

    def encrypt(self, text):
        # Create a new PRNG based on the seed, and (re)initialise {__bytes__}
        prng, self.__bytes__ = MT19937(self.__seed__), []
        # XOR each input byte with the next stream byte
        return bytes([self.__get_stream_byte__(prng) ^ x for x in text])

    def decrypt(self, ciphertext):
        # Because we're using XOR, encrypt = decrypt
        return self.encrypt(ciphertext)

@challenge(3, 24)
def challenge_24():
    # Initialise our new stream cipher
    stream_cipher_instance = MT19937Cipher(424242)
    # Generate a random plaintext
    plaintext = set2.random_bytes(1024)
    # Encrypt the plaintext, decrypt is
    ciphertext = stream_cipher_instance.encrypt(plaintext)
    obtained_plaintext = stream_cipher_instance.decrypt(ciphertext)
    # Verify the decrypted ciphertext equals our original plaintext
    assert_true(obtained_plaintext == plaintext)

## Execute individual challenges
if __name__ == '__main__':
    challenge_17()
    challenge_18()
    challenge_19()
    challenge_20()
    challenge_21()
    challenge_22()
    challenge_23()
    challenge_24()
