import re
import zlib
import string
import random
import math
from tqdm import tqdm

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


## Challenge 52
total_md_calls = 0

def MerkleDamgard(M, nbytes, H, get_map=False):
    # Use an (ugly) global variable to keep track of how often we call this hash function in total
    global total_md_calls
    total_md_calls += 1
    # Extract the blocks
    blocks = [M[i:i+16] for i in range(0, len(M), 16)]
    m = {}
    # Simulate Merkle Damgard structure
    for i, block in enumerate(blocks):
        H = set2.encrypt_aes_ecb(block, key=set2.pkcs7_add_padding(H, 16), padding=False)[:nbytes]
        m[H] = i
    # Return final block
    return (H, m) if get_map else H

def FindCollisions(n):
    # Define our hash functions `f` and `g` (cheap and expensive, respectively)
    cheap_hash = lambda x, y: MerkleDamgard(x, 2, y)
    expensive_hash = lambda x: MerkleDamgard(x, 3, b'\x00'*3)

    while True:
        hash_map = {}
        collisions = []
        # Start Phase 1: generate 2^n hash collisions using `f`
        with tqdm(desc="Phase 1", total=int(2**n)) as pbar:
            H = b'\x00'*2
            while len(collisions) < 2**n:
                # Generate random message
                message = set2.random_bytes(16)
                # Get hash value
                hash_value = cheap_hash(message, H)
                # If a new collision was found, update the progress bar
                if hash_value in hash_map and len(hash_map[hash_value]) == 1 and hash_map[hash_value][0] != message:
                    H = hash_value
                    # If it is the first collision, simply add it to the list
                    if len(collisions) < 1:
                        pbar.update(1)
                        collisions.append(hash_map[hash_value] + [message])
                    else:
                    # If it isn't, 'double' the existing collisions by simply appending our new message
                        for c in list(collisions):
                            #assert cheap_hash(c[0] + message, b'\x00'*2) == cheap_hash(c[1] + message, b'\x00'*2)
                            pbar.update(1)
                            collisions.append([c[0] + message, c[1] + message])
                    hash_map = {}
                else:
                    # Add found hash and message to `hash_map`, which keeps track of all hashes and corresponding messages
                    hash_map[hash_value] = hash_map.get(hash_value, []) + [message]

        # Start Phase 2: for the found 2^n collisions, try all pairs and see if they also collide under `g`
        with tqdm(desc="Phase 2", total=len(collisions)) as pbar:
            for collision in collisions:
                pbar.update(1)
                # If they collide, we're done
                if expensive_hash(collision[0]) == expensive_hash(collision[1]):
                    pbar.close()
                    print("Collision found!")
                    return
            else:
                # If no collisions under `g` were found, we have to start over
                pbar.set_description("Phase 2: No collision found (restart)")
                n += 2

@challenge(7, 52)
def challenge_52():
    FindCollisions(24 / 2)
    print("\nExpected n/o calls: {:,}".format(2 ** ((16 + 24) // 2)))
    print("Actual n/o calls:   {:,}".format(total_md_calls))


## Challenge 53
HASH_LENGTH = 2 #Just like the last challenge, we'll assume a hash length of 16 bits (=2 bytes) for simplicity

def expandable_message(k, md_hash):
    # Define the initial state
    initial_state = b'\x00'*HASH_LENGTH
    result = {}
    # Iterate from k to 0
    for i in range(k, 0, -1):
        # Generate a single message with a block length of 1
        single_msg = set2.random_bytes(16)
        single_msg_hash = md_hash(single_msg, initial_state)
        # Generate dummy blocks of length 2^(i-1)
        dummy_blocks = set2.random_bytes(16 * (2 ** (i - 1)))
        dummy_blocks_hash = md_hash(dummy_blocks, initial_state)

        poly_msg = None
        final_block = None
        # Bruteforce until we find a collision between `single_msg` and `dummy_blocks + final_block`
        while single_msg_hash != poly_msg:
            final_block = set2.random_bytes(16)
            poly_msg = md_hash(final_block, dummy_blocks_hash)
        # Verify the hashes are equal now
        assert md_hash(single_msg, initial_state) == md_hash(dummy_blocks + final_block, initial_state)
        # Append the shared hash, the short message and the long message to our result set
        result[i] = [single_msg_hash, single_msg, dummy_blocks + final_block]
        # Use the shared hash as the new initial state
        initial_state = single_msg_hash
    return result

@challenge(7, 53)
def challenge_53():
    # Define our Merkle Damgard hash function
    md_hash = lambda x, y, z=False: MerkleDamgard(x, HASH_LENGTH, y, z)
    # Generate the message we'll attack
    M = set2.random_bytes(16 * 16)
    # Generate the hashmap, i.e. the intermediate hashes per block
    M_hashmap = md_hash(M, b'\x00' * HASH_LENGTH, True)
    # Compute `k`
    k = int(math.log2(len(M) // 16))
    # Generate expandable message
    print('Message to preimage has {} blocks (i.e. k = {})'.format(len(M)//16, k))
    print("Generating expandable message... ", end='')
    expandable_output = expandable_message(k, md_hash)
    print('done')

    # Get hash of our final block in the expandable message
    final_hash = list(expandable_output.values())[-1][0]
    index = -1
    # Find an index that is at equal to or greater than `k`
    print("Generating bridge... ", end='')
    while index < k:
        bridge, bridge_hash = None, None
        # Check if generated message collides with one of our intermediate hashes
        while bridge_hash not in M_hashmap[1].keys():
            bridge = set2.random_bytes(16)
            bridge_hash = md_hash(bridge, final_hash)
        # If it does, that will be our index
        index = M_hashmap[1][bridge_hash]
    print("done\nFound collision against block {} of M".format(index))

    # The next step is to replace all blocks up until our collision (i.e. the bridge)
    # This requires some binary math, as sometimes the short message is required, while
    #  sometimes the long one is required.
    prefix_length = index
    prefix = b''
    for i in range(k, 0, -1):
        # Compute the length of the long message we're considering
        q = 2 ** (i - 1) + 1
        # If the prefix length minus the long message length is smaller than the remaining blocks:
        if prefix_length - q < i - 1:
            # Use short message
            prefix_length -= 1
            prefix += expandable_output[i][1]
        else:
            # Use long message
            prefix_length -= q
            prefix += expandable_output[i][2]
    # Construct the new message
    constructed_message = prefix + bridge + M[(16*(index+1)):]
    # Verify the constructed message has the same length and the same hash value as our original message
    assert_true(len(constructed_message) == len(M) and md_hash(constructed_message, b'\x00' * HASH_LENGTH) == md_hash(M, b'\x00' * HASH_LENGTH))


## Challenge 54
def generate_hash_tree(hashlist, messages, md_hash, pb):
    # If there is only one hash in the list, we're done
    if len(hashlist[-1]) == 1: return hashlist, messages
    # Create pairs, initialise variables
    pairs = zip(hashlist[-1][::2], hashlist[-1][1::2])
    msg = set2.random_bytes(16)
    found_hashes, found_msgs = [], []

    # Iterate over all pairs we have
    for x, y in pairs:
        # See if we found a collision
        while md_hash(msg, x) != md_hash(msg, y):
            # If not, generate a new message
            msg = set2.random_bytes(16)
        pb.update(1)
        # Append found hash to the hash tree's current level
        found_hashes.append(md_hash(msg, x))
        # Append found message to the message tree's current level
        found_msgs.append(msg)

    # Add new level to hash tree and message tree
    hashlist.append(found_hashes)
    messages.append(found_msgs)
    # Go one level deeper
    return generate_hash_tree(hashlist, messages, md_hash, pb)

@challenge(7, 54)
def challenge_54():
    # Set parameters, define hash function
    k = 4   # 2^4 = 16
    md_hash = lambda x, y: MerkleDamgard(x, 2, y)
    START_IV = b'\x00'*16

    # Generate `2^k` random messages with their hashes, then add them as leaves to the hash/message tree
    hash_tree, msg_tree = [[]], [[]]
    for _ in range(2**k):
        msg = set2.random_bytes(16)
        msg_tree[0].append(msg)
        hash_tree[0].append(md_hash(msg, START_IV))

    # Generate full hash/message tree
    print('k = {}'.format(k))
    with tqdm(desc="Generating hash tree", total=(2**k)-1) as progress:
        hash_tree, msg_tree = generate_hash_tree(hash_tree, msg_tree, md_hash, progress)
    # Make claim based on the root of the hash tree
    hash_value = hash_tree[-1][0]
    print('> I hereby claim the hash will be equal to {}!'.format(hash_value))

    # Now, _after_ we have made our claim, craft our message with the match results
    msg = b'Ajax-PSV=3-0; Feyenoord-RKC=0-15'
    # Generate hash of our message
    msg_hash = md_hash(msg, START_IV)
    # Our crafted message starts with the original message
    crafted_msg = msg
    # Find a collision between our message's hash and one of the leaves in the hash tree
    glue, glue_hash = None, None
    while glue_hash not in hash_tree[0]:
        glue = set2.random_bytes(16)
        glue_hash = md_hash(glue, msg_hash)
    # Append the glue to our crafted message
    crafted_msg += glue
    # Find the index of the leaf we found a collision against
    index = hash_tree[0].index(glue_hash)
    # Now find the remaining `k` blocks that will eventually hash to `hash_value`
    for level in range(1, k+1):
        index = index // 2
        crafted_msg += msg_tree[level][index]
    # Verify our crafted message hashes to the hash value we claimed it would have
    assert_true(md_hash(crafted_msg, START_IV) == hash_value)


## Execute individual challenges
if __name__ == '__main__':
    challenge_49()
    challenge_50()
    challenge_51()
    challenge_52()
    challenge_53()
    challenge_54()
