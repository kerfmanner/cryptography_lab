import secrets
from math import floor, lcm

EXPONENENT = 65537


def generate_number(length):
    """
    Generates random big odd number with given bit length.
    Returns the number.
    """
    return (1 << (length - 1)) | secrets.randbits(length - 1) | 1


def test_primality(num, accuracy_rate=100):
    """
    Test number for primality using Fermat primality test.
    """
    for _ in range(accuracy_rate):
        a = secrets.randbelow(num - 1) + 1
        if pow(a, num - 1, num) != 1:
            return False
    return True


def random_length(base_length, key_length=2048):
    """
    Generate random length from base_length to key_length - base_length * 2 - 1.
    """
    added_length = secrets.randbelow(key_length - base_length * 2)
    if added_length % 2:
        added_length -= 1
    return base_length + added_length


def generate_two_big_random_prime_numbers(key_length=2048):
    """Generates two big random big prime number to generate a pair of keys"""
    first_length = random_length(812, key_length=key_length)
    while True:
        a = generate_number(first_length)
        if test_primality(a):
            break
    while True:
        b = generate_number(key_length - first_length)
        if test_primality(b):
            return a, b


def carmichell_totient_function(prime_1, prime_2):
    """Carmichell totient function to create a pair of keys."""
    return lcm(prime_1 - 1, prime_2 - 1)


def find_secret_exponent(carmichell, public_exponent):
    """Generates private key exponent"""
    return pow(public_exponent, -1, carmichell)


def make_key_pair():
    """Makes two keys public and private"""
    p, q = generate_two_big_random_prime_numbers()
    n = p * q
    ctf = carmichell_totient_function(p, q)
    public_key = (n, EXPONENENT)
    private_key = find_secret_exponent(ctf, EXPONENENT)
    return public_key, private_key


def get_block_size(n):
    """Get the maximum block size base on the first part of public key n."""
    return floor(n.bit_length() / 8) - 1


def add_padding_to_message(block_size, encoded_message):
    """
    Adds PKCS#5 padding to the message.
    It works by checking how many bytes is missing to fill the last block.
    And adds that amount at the end. If the last block is full, it adds a whole block of block_size - 1.
    Later after decoding we look at last byte and remove the amount of last bytes equal to value of byte.
    """
    amount_of_absent_bytes = block_size - (len(encoded_message) % block_size)
    return encoded_message + bytes([amount_of_absent_bytes] * amount_of_absent_bytes)


def encrypt_message(public_key, encoded_message):
    """
    Encrypts the encoded message using RSA.
    """
    encrypted_message = []
    block_size = get_block_size(public_key[0])
    pointer = 0
    encoded_message_with_padding = add_padding_to_message(block_size, encoded_message)

    while pointer != len(encoded_message_with_padding):
        encoded_block = pow(
            int.from_bytes(
                encoded_message_with_padding[pointer : pointer + block_size]
            ),
            EXPONENENT,
            public_key[0],
        )
        bytes_encoded_block = encoded_block.to_bytes(256)
        encrypted_message.append(bytes_encoded_block)
        pointer += block_size
    return b"".join(encrypted_message)


def get_encrypted_blocks_from_bytes(encrypted_message, encrypt_num_size=256):
    """Helper function to decrypt, gets the bytes that represent number that was encoded in each block."""
    pointer = 0
    blocks = []
    while pointer != len(encrypted_message):
        blocks.append(encrypted_message[pointer : pointer + encrypt_num_size])
        pointer += encrypt_num_size
    return blocks


def get_rid_of_padding(decrypt_message):
    """Gets rid of padding"""
    padding = decrypt_message[-1]
    return decrypt_message[: len(decrypt_message) - padding]


def decrypt_message(public_key, private_key, encrypted_message):
    """Decrypt the message using RSA."""
    encrypted_blocks = get_encrypted_blocks_from_bytes(encrypted_message)
    block_byte_size = get_block_size(public_key[0])
    decrypted_message = b""

    while encrypted_blocks:
        encr_block_num = int.from_bytes(encrypted_blocks.pop(0))
        decrypted_block_num = pow(encr_block_num, private_key, public_key[0])
        decrypted_block = decrypted_block_num.to_bytes(block_byte_size)
        decrypted_message += decrypted_block

    decrypted_message = get_rid_of_padding(decrypted_message)
    return decrypted_message


def encode_public_key(public_key):
    """Encode the public key"""
    components = []
    components.append(public_key[0].to_bytes(256))
    components.append(public_key[1].to_bytes(256))
    return b"".join(components)


def decode_public_key(encoded_public_key):
    """Decode the public key"""
    return (
        int.from_bytes(encoded_public_key[:256]),
        int.from_bytes(encoded_public_key[256:]),
    )
