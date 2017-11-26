import re

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
    return bytearray([int(x) ^ int(y) for x, y in zip(a,b)])

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


## Execute individual challenges
if __name__ == '__main__':
    challenge_49()
