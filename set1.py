from challenges import challenge
# From: https://cryptopals.com/sets/1

## Challenge 2
def XOR(str1, str2):
    # Convert given hex string to binary representation
    str1_bin = ''.join([bin(x)[2:].zfill(8) for x in str1])
    str2_bin = ''.join([bin(x)[2:].zfill(8) for x in str2])
    # XOR the individual bits
    result = ''.join([str(int(bool(int(x[0])) ^ bool(int(x[1])))) for x in zip(str1_bin, str2_bin)])
    # Convert binary output back to hex
    h = hex(int(result, 2))[2:]
    # Append leading zero if the number of digits is odd
    if len(h) % 2 != 0: h = '0' + h
    # Return outcome as bytearray
    return bytearray.fromhex(h)

@challenge(1, 2)
def challenge_2():
    assert XOR(bytearray.fromhex('1c0111001f010100061a024b53535009181c'), bytearray.fromhex('686974207468652062756c6c277320657965')) == bytearray.fromhex('746865206b696420646f6e277420706c6179')
    print("Pass")

## Challenge 3
def hex_to_text(text): return ''.join([chr(y) for y in text])
def frequency_of_common_letters(text): return len(list(filter(lambda x: x in 'ETAOIN SHRDLU', text.upper()))) / len(text)

def find_key(encrypted):
    results = []
    for i in range(32, 126):
        # Create key with equal length
        key = bytes([i]) * len(encrypted)
        # Obtain the text when XORing the above with the encrypted text
        xored = XOR(encrypted, key)
        #if len(xored) % 2 == 1: continue
        decrypted_text = hex_to_text(xored)
        # Add the key, the output and the frequency of common letters to list
        results.append((i, decrypted_text, frequency_of_common_letters(decrypted_text)))
    # Return best scorer in terms o
    return sorted(results, key=lambda x: x[2], reverse=True)[0]

@challenge(1, 3)
def challenge_3():
    print('{0}\t{2:.2f}\t{1}'.format(*find_key(bytearray.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'))))

## Challenge 4
def find_key_from_file(file):
    # Open file, read lines to list
    with open(file) as file:
        lines = file.read().splitlines()
    # Find the number one scoring key for each of the lines
    results = [find_key(bytearray.fromhex(l.strip())) for l in lines]
    # Obtain the top 5 results
    top_5 = sorted(results, key=lambda x: x[2], reverse=True)[0:5]
    return top_5[0]

@challenge(1, 4)
def challenge_4():
    print('{0}\t{2:.2f}\t{1}'.format(*find_key_from_file('inputs/4.txt')))

## Challenge 5
to_encrypt = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
def text_to_hex(text): return bytearray([ord(x) for x in text])

def encrypt_repeat(string, key):
    x = [XOR([x], [key[i % len(key)]]) for (i, x) in enumerate(string)]
    return bytearray.fromhex(''.join([y.hex() for y in x]))

@challenge(1, 5)
def challenge_5():
    assert encrypt_repeat(text_to_hex(to_encrypt), text_to_hex("ICE")) == bytearray.fromhex('0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    print("Pass")

## Challenge 6
def hamming_distance(str1, str2):
    # Convert given hex strings to binary representation
    str1_bin = ' '.join([bin(x)[2:].zfill(8) for x in str1])
    str2_bin = ' '.join([bin(x)[2:].zfill(8) for x in str2])
    # Count the number of ones in each string
    return sum([1 if x[0] != x[1] else 0 for x in zip(str1_bin, str2_bin)])

def base64_file_to_hex(file):
    import binascii
    # Open the file
    with open(file) as file:
        contents = file.read()
    # Get cipher text as byte array
    cipher_text = binascii.a2b_base64(contents)
    return bytearray(cipher_text)

def guess_key_length(ciphertext, min_length, max_length):
    results = []
    # For all possible key lengths in the given range...
    for keysize_guess in range(min_length, max_length):
        hamming_dists = []
        i = 0
        # While the ith and (i+1)th chunk of keysize_guess bytes can be selected...
        while len(ciphertext) > keysize_guess * (i+2):
            # Compute the Hamming distance between chunk i and chunk (i+1)
            hamming_dists.append(hamming_distance(ciphertext[keysize_guess * i:keysize_guess * (i + 1)], ciphertext[keysize_guess * (i + 1):keysize_guess * (i + 2)]) / keysize_guess)
            i += 1
        # Compute the average Hamming Distance
        results.append((keysize_guess, sum(hamming_dists)/len(hamming_dists)))

    # Find the keysize_guess value for which the average Hamming Distance was the smallest
    KEYLENGTH, DISTANCE = sorted(results, key=lambda x: x[1])[0]
    return KEYLENGTH, DISTANCE

def vigenere_file_bruteforce(ciphertext_hex, min_length, max_length):
    # Based on the given ciphertext, guess the most likely keylength (assuming a Vegenere cipher was used)
    keylength, _ = guess_key_length(ciphertext_hex, min_length, max_length)
    # Group every ith byte together in blocks
    blocks = [ciphertext_hex[i::keylength] for i in range(keylength)]
    composed_key = bytearray()
    # For each block, apply one-char XOR bruteforce, concatenate all key chars to find the 'master key'
    for block in blocks:
        char, _, _ = find_key(block)
        composed_key.append(char)

    return str(composed_key, 'utf-8'), str(encrypt_repeat(ciphertext_hex, composed_key), 'utf-8')

@challenge(1, 6)
def challenge_6():
    assert hamming_distance(text_to_hex('this is a test'), text_to_hex('wokka wokka!!!')) == 37
    ciphertext_hex = base64_file_to_hex('inputs/6.txt')
    key, text = vigenere_file_bruteforce(ciphertext_hex, 2, 40)
    print("Found key: {}".format(key))
    print("Found text: {}".format(text))


## Challenge 7
def decrypt_aes_ecb(file, key):
    from Crypto.Cipher import AES
    import base64
    unpad = lambda s: s[:-ord(s[len(s) - 1:])]
    # Create new AES object with the given key in ECB mode
    obj = AES.new(key, AES.MODE_ECB)
    # Open file, decode
    with open(file) as file:
        contents = base64.b64decode(file.read())
    # Decrypt file, remove padding, display as UTF-8
    return str(unpad(obj.decrypt(contents)), 'utf-8')

@challenge(1, 7)
def challenge_7():
    print('Found text: {}'.format(decrypt_aes_ecb('inputs/7.txt', 'YELLOW SUBMARINE')))

## Challenge 8
def find_ecb(file):
    # Open file, read lines to list
    with open(file) as file:
        lines = file.read().splitlines()
    # Iterate over lines
    for i, line in enumerate(lines):
        # Create list with 16 byte (=128 bit) chunks
        results = [line[i:i+16] for i in range(0, len(line), 16)]
        # Check whether the number of unique chunks is equal to the overall number of chunks
        difference = len(results) - len(set(results))
        # Report if the difference is not equal to 0
        if difference != 0:
            print('FOUND: line {} has {} non-unique blocks'.format(i, difference))

@challenge(1, 8)
def challenge_8():
    find_ecb('inputs/8.txt')

## Execute individual challenges
challenge_2()
challenge_3()
challenge_4()
challenge_5()
challenge_6()
challenge_7()
challenge_8()
