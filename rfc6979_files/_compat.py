"""
Common functions for providing cross-python version compatibility.
"""
import sys
import re
import binascii
from six import integer_types


def str_idx_as_int(string, index):
    """Take index'th byte from string, return as integer"""
    val = string[index]
    if isinstance(val, integer_types):
        return val
    return ord(val)


if sys.version_info < (3, 0):  # pragma: no branch
    import platform

    def normalise_bytes(buffer_object):
        """Cast the input into array of bytes."""
        # flake8 runs on py3 where `buffer` indeed doesn't exist...
        return buffer(buffer_object)  # noqa: F821

    def hmac_compat(ret):
        return ret

    if (
        sys.version_info < (2, 7)
        or sys.version_info < (2, 7, 4)
        or platform.system() == "Java"
    ):  # pragma: no branch

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            return re.sub(r"\s+", "", text)

        def compat26_str(val):
            return str(val)

        def bit_length(val):
            if val == 0:
                return 0
            return len(bin(val)) - 2

    else:

        def remove_whitespace(text):
            """Removes all whitespace from passed in string"""
            return re.sub(r"\s+", "", text, flags=re.UNICODE)

        def compat26_str(val):
            return val

        def bit_length(val):
            """Return number of bits necessary to represent an integer."""
            return val.bit_length()

    def b2a_hex(val):
        return binascii.b2a_hex(compat26_str(val))

    def a2b_hex(val):
        try:
            return bytearray(binascii.a2b_hex(val))
        except Exception as e:
            raise ValueError("base16 error: %s" % e)

    def bytes_to_int(val, byteorder):
        """Convert bytes to an int."""
        if not val:
            return 0
        if byteorder == "big":
            return int(b2a_hex(val), 16)
        if byteorder == "little":
            return int(b2a_hex(val[::-1]), 16)
        raise ValueError("Only 'big' and 'little' endian supported")

    def int_to_bytes(val, length=None, byteorder="big"):
        """Return number converted to bytes"""
        if length is None:
            length = byte_length(val)
        if byteorder == "big":
            return bytearray(
                (val >> i) & 0xFF for i in reversed(range(0, length * 8, 8))
            )
        if byteorder == "little":
            return bytearray(
                (val >> i) & 0xFF for i in range(0, length * 8, 8)
            )
        raise ValueError("Only 'big' or 'little' endian supported")

else:
    if sys.version_info < (3, 4):  # pragma: no branch
        # on python 3.3 hmac.hmac.update() accepts only bytes, on newer
        # versions it does accept memoryview() also
        def hmac_compat(data):
            if not isinstance(data, bytes):  # pragma: no branch
                return bytes(data)
            return data

        def normalise_bytes(buffer_object):
            """Cast the input into array of bytes."""
            if not buffer_object:
                return b""
            return memoryview(buffer_object).cast("B")

    else:

        def hmac_compat(data):
            return data

        def normalise_bytes(buffer_object):
            """Cast the input into array of bytes."""
            return memoryview(buffer_object).cast("B")

    def compat26_str(val):
        return val

    def remove_whitespace(text):
        """Removes all whitespace from passed in string"""
        return re.sub(r"\s+", "", text, flags=re.UNICODE)

    def a2b_hex(val):
        try:
            return bytearray(binascii.a2b_hex(bytearray(val, "ascii")))
        except Exception as e:
            raise ValueError("base16 error: %s" % e)

    # pylint: disable=invalid-name
    # pylint is stupid here and doesn't notice it's a function, not
    # constant
    bytes_to_int = int.from_bytes
    # pylint: enable=invalid-name

    def bit_length(val):
        """Return number of bits necessary to represent an integer."""
        return val.bit_length()

    def int_to_bytes(val, length=None, byteorder="big"):
        """Convert integer to bytes."""
        if length is None:
            length = byte_length(val)
        # for gmpy we need to convert back to native int
        if type(val) != int:
            val = int(val)
        return bytearray(val.to_bytes(length=length, byteorder=byteorder))


def byte_length(val):
    """Return number of bytes necessary to represent an integer."""
    length = bit_length(val)
    return (length + 7) // 8