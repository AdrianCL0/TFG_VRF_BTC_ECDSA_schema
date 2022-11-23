# Convert the blockchain.info wallet key (priv:) from Wif58
# Usage: python3 convert_blockchain_info_wallet_priv_key_to_WIF.py
# Important: You need Python 3. Older versions will not work.

# Step 1.
# Start with the blockchain.info wallet priv: key
BLOCKCHAIN_WALLET_PRIV = input("\nEnter the blockchain.info wallet 'priv:' key: ") 
print("Blockchain Wallet Priv: " + BLOCKCHAIN_WALLET_PRIV)

# Step 2.
# Base58 decode (with checksum)

from hashlib import sha256
from collections import deque
DEFAULT_CHARSET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def _b58decode_int(val, base, charset):
        output = 0
        for char in val:
            output = output * base + charset.index(char)
        return output

# Decode base58check encoded input to original raw bytes.
def b58decode(val, charset=DEFAULT_CHARSET):
    if isinstance(val, str):
        val = val.encode()

    if isinstance(charset, str):
        charset = charset.encode()

    base = len(charset)

    if not base == 58:
        raise ValueError('charset base must be 58, not %s' % base)

    pad_len = len(val)
    val = val.lstrip(bytes([charset[0]]))
    pad_len -= len(val)

    acc = _b58decode_int(val, base, charset)

    result = deque()
    while acc > 0:
        acc, mod = divmod(acc, 256)
        result.appendleft(mod)

    prefix = b'\0' * pad_len
    return prefix + bytes(result)

# decode the blockchain private key from base58 checksum, to hex
b = b58decode(BLOCKCHAIN_WALLET_PRIV)
PK0 = b.hex()
print("Private Key Hex: " + PK0)

# Step 3.
# Convert hex private key to WIF
# See: https://gist.github.com/Jun-Wang-2018/3105e29e0d61ecf88530c092199371a7

# From private key(hex) to Wallet Import Format(WIF)
# Reference: https://medium.freecodecamp.org/how-to-create-a-bitcoin-wallet-address-from-a-private-key-eca3ddd9c05f
#            https://docs.python.org/2/library/hashlib.html
import codecs  #If not installed: "pip3 install codecs"
import hashlib
PK1 = '80'+ PK0
PK2 = hashlib.sha256(codecs.decode(PK1, 'hex'))
PK3 = hashlib.sha256(PK2.digest())
checksum = codecs.encode(PK3.digest(), 'hex')[0:8]
PK4 = PK1 + str(checksum)[2:10]  #I know it looks wierd

# Define base58
def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add '1' for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

WIF = base58(PK4)
print("WIF: " + WIF)
print("\nTo import into electrum, enter:\np2pkh:" + WIF)
print("\n")
