import re
import zlib
import string
import random

from challenges import challenge, assert_true
import set1, set2, set3, set4, set5, set6
# From: https://cryptopals.com/sets/7

## Challenge 49
def generate_cmac(text, iv):
    key = b'SECRET_MASTERKEY'
    ciphertext = set2.encrypt_aes_cbc(text, key, iv)
    return text + iv + ciphertext[-16:]

def generate_transaction(from_id, iv, transactions):
    template = '{to_id}:{amount}'
    message = 'from={}&tx_list='.format(from_id) + ';'.join([template.format(**transaction) for transaction in transactions])
    return generate_cmac(message.encode(), iv=iv)

def validate_transaction(received_message):
    plaintext, iv, mac = received_message[:-32], received_message[-32:-16], received_message[-16:]
    expected_message = generate_cmac(plaintext, iv)
    transaction = re.search(r"^from=(\d+)&tx_list=([0-9;:]+)$", plaintext.decode())
    if not transaction:
        raise Exception("Invalid transaction")
    tx_list = re.findall(r"(\d+):(\d+);?", transaction.group(2))
    if not tx_list:
        raise Exception("Invalid transaction")
    for (receiver, amount) in tx_list:
        print('> Transferring £{:,} from {} to {}'.format(int(amount), transaction.group(1), receiver))
    return received_message == expected_message

def xor_string(a, b):
    return bytearray([int(x) ^ int(y) for x, y in zip(a, b)])

@challenge(7, 49)
def challenge_49():
    # Define User IDs
    Alice, Bob, Carol, Eve = 100, 101, 102, 600
    # Define fixed IV
    fixed_iv = b'\x00'*16

    # Sample for Alice
    print('Sample for Alice')
    valid_message_alice = generate_transaction(Alice, fixed_iv, [{'to_id':Bob, 'amount':100}, {'to_id':Carol, 'amount':500}])
    assert(validate_transaction(valid_message_alice))

    # Generate transaction based on own account (transferring 1M from own account to own account)
    valid_message_eve = generate_transaction(Eve, fixed_iv, [{'to_id':Eve, 'amount':1000000}])
    print('\nValid message (not sent to server): {}'.format(valid_message_eve))

    # Forge transaction by changing the 'from' account to Alice's
    forged_first_block = 'from={}&tx_list'.format(Alice).encode()
    # As we can control the IV, XOR new string with original string (and the original, fixed IV) to obtain the IV that will make our forged message valid
    custom_iv = xor_string(fixed_iv, xor_string(valid_message_eve[:16], forged_first_block))
    # Construct message
    forged_message = forged_first_block + valid_message_eve[16:-32] + custom_iv + valid_message_eve[-16:]
    print('Forged message:                     {}'.format(forged_message))

    print('Send to server...')
    # Validate forged message
    assert_true(validate_transaction(forged_message))


## Challenge 50
@challenge(7, 50)
def challenge_50():
    # Create hash function
    original_key = b'YELLOW SUBMARINE'
    original_iv = b'\x00' * 16
    generate_hash = lambda javascript: set2.encrypt_aes_cbc(javascript, original_key, original_iv, False)[-16:]

    # Recreate original hash (the one we will forge)
    original_message = set2.pkcs7_add_padding(b"alert('MZA who was that?');\n", 16)
    original_hash = generate_hash(original_message)
    assert original_hash == bytes.fromhex('296b8d7cb78a243dda4d0a61d33bbdd1')

    # New piece of JavaScript
    new_message = b"alert('Ayo, the Wu is back!');//"
    # Find the last cipher block of our new JavaScript (will be the IV of the following block)
    ciphertext_block_1_2 = set2.encrypt_aes_cbc(new_message, original_key, original_iv, False)[-16:]
    # Generate a third plaintext block for our new JavaScript, by XORing the found IV with the first plaintext block of the original JavaScript
    plaintext_block_3 = xor_string(ciphertext_block_1_2[-16:], original_message[:16])
    # Now, append the found block plus the remaining blocks of the original JavaScript
    new_message += plaintext_block_3 + original_message[16:]
    # Hashing this will result in the original hash
    assert_true(generate_hash(new_message) == original_hash)


## Challenge 51
token = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
def compression_oracle(msg, cipher):
    template = "POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid={}\r\nContent-Length: {}\r\n{}"
    compress = zlib.compress
    return len(cipher(compress(template.format(token, len(msg), msg).encode())))

def find_token(msg, oracle):
    # Create a list of possible next characters
    alphabet = string.ascii_uppercase + string.ascii_lowercase + string.digits + '=' + '\r'

    # Create an outer loop - we need this if we rely on padding, such as for AES-CBC
    i = 0
    while True:
        result_set = {}
        # For each option:
        for option in alphabet:
            # Construct the new message
            new_msg = msg + option
            # Obtain oracle score (prepend text before message if padding is required)
            score = oracle(alphabet[:i] + new_msg)
            # Add score with value to result set
            result_set[score] = result_set.get(score, []) + [new_msg]
        if len(result_set) > 1: break
        i += 1

    # Iterate over the values with the lowest oracle scores:
    for option in result_set[min(result_set.keys())]:
        # If our option is a newline character, it probably means we have found the complete token, so we can return what we have
        if option[-1] == '\r':
            return msg
        # Else, call this function recursively
        return find_token(option, oracle)

@challenge(7, 51)
def challenge_51():
    # Prepare a Stream Cipher compression oracle and an AES-CBC compression oracle
    stream_oracle = lambda msg: compression_oracle(msg, lambda x: set3.encrypt_aes_ctr(x, key=set2.random_bytes(16), nonce=random.randint(2**8, 2**16)))
    cbc_oracle = lambda msg: compression_oracle(msg, lambda x: set2.encrypt_aes_cbc(x, key=set2.random_bytes(16), iv=set2.random_bytes(16)))

    # Define the base text
    base = 'POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid='

    # Find the tokens using the Stream Cipher
    print('Stream Cipher: ', end='')
    assert_true(find_token(base, oracle=stream_oracle)[len(base):] == token)

    # AES-CBC is more challenging, as it works with blocks.
    # To detect a successful guess, we'll have to add padding which will make 'wrong' guesses one block longer than the correct one
    print('AES-CBC:       ', end='')
    assert_true(find_token(base, oracle=cbc_oracle)[len(base):] == token)


## Execute individual challenges
if __name__ == '__main__':
    challenge_49()
    challenge_50()
    challenge_51()
