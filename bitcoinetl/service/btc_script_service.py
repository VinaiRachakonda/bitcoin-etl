import binascii
import hashlib
import base58

def script_hex_to_non_standard_address(script_hex):
    if script_hex is None:
        script_hex = ''
    
    utxo_hash = script_pub_key_to_pub_key_hash(script_hex)
    utxo_addr = pub_key_hash_to_addr(utxo_hash)
    return utxo_addr.decode("utf-8")

def script_pub_key_to_pub_key_hash(script_pub_key: str, type: str = 'pubkey'):
    """
    Create a public key hash from scriptPubKey hex

    :param script_pub_key: scriptPubKey hex in hexadecimal notation
    :type script_pub_key: str
    :param type: type of the scriptPubKey
    :type type: str
    :return: hash of public key for P2PK address
    :rtype: bytes
    """
    try:
        if type == 'pubkey':
            # Extract Public Key from ScriptPubKey
            pubkey_hex = script_pub_key[2:-2]
            # Convert Public Key hex too binary
            pubkey_bin = binascii.unhexlify(pubkey_hex)
            # Create SHA-256 hash from Public Key binary
            pub_key_hash = hashlib.sha256(pubkey_bin).digest()
            # Compute RIPEMD-160 hash value/digest
            ripemd160 = hashlib.new('ripemd160')
            ripemd160.update(pub_key_hash)
            pub_key_double_hash = ripemd160.digest()

            return pub_key_double_hash

    except Exception as e:
        print(e)


def pub_key_hash_to_addr(pubkeyhash: bytes, version_prefix: bytes = b'\x00'):
    """
    Create a Base58Check-encoded address from public key hash

    :param pubkeyhash: hash of public key
    :type pubkeyhash: bytes
    :param version_prefix: a version byte added to hash
    :type version_prefix: bytes
    :return: An bitcoin address in Base58Check format
    :rtype: bytes
    """
    try:
        # First add version byte to get a padded hash
        hash_versioned = version_prefix + pubkeyhash
        # Apply the SHA256 hash algorithm twice
        hash_first = hashlib.sha256(hash_versioned).digest()
        hash_second = hashlib.sha256(hash_first).digest()
        # Add the first four bytes as checksum
        hash_checksum = hash_versioned + hash_second[:4]
        # Encode in Base58Check
        base58check_encoded_address = base58.b58encode(hash_checksum)

        return base58check_encoded_address

    except Exception as e:
        print(e)
