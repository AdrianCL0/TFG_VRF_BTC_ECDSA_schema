from collections import deque
DEFAULT_CHARSET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
import base58


def _b58decode_int(val, base, charset):
        output = 0
        for char in val:
            output = output * base + charset.index(char)
        return output


#Decodes a WIF base58 into a int value
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
    aux= prefix + bytes(result)
    PK0 = aux.hex()
    PK0=PK0[2:]
    sk= int(PK0[:64],16)
    return sk

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
    
    




