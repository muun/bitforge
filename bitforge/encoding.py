import utils, binascii, hashlib
from errors import StringError


class EncodingError(StringError):
    "The string {string} is not properly encoded"


class InvalidBase58h(EncodingError):
    "The string {string} is not valid base58/check"


class InvalidHex(EncodingError):
    "The string {string} is not valid hexadecimal"


class InvalidScriptNumber(EncodingError):
    "The script number {string} is too long"


class InvalidMinimalScriptNumber(EncodingError):
    "The script number {string} is not minimally encoded"


def encode_base58h(bytes):
    return utils.encoding.b2a_hashed_base58(bytes)


def decode_base58h(string):
    try:
        return utils.encoding.a2b_hashed_base58(string)

    except utils.encoding.EncodingError:
        raise InvalidBase58h(string)


def encode_int(integer, big_endian = True, length = None):
    if integer == 0:
        return chr(0) if length is None else chr(0) * length

    bytes = bytearray()

    while integer > 0:
        bytes.append(integer & 0xff)
        integer >>= 8

    if length is not None:
        zeros = chr(0) * length # TODO if number can't fit in length, raise
        bytes = (bytes + zeros)[:length]

    if big_endian:
        bytes.reverse()

    return str(bytes)


def decode_int(bytes, big_endian = True):
    if not big_endian:
        bytes = reversed(bytes)

    integer = 0

    for char in bytes:
        integer <<= 8
        integer += ord(char)

    return integer


def encode_varint(integer):
    # TODO check integer is a postive number
    if integer < 253:
        return encode_int(integer)

    elif integer <= 0xFFFF:
        return chr(253) + encode_int(integer, length = 2, big_endian = False)

    elif integer <= 0xFFFFFFFF:
        return chr(254) + encode_int(integer, length = 4, big_endian = False)

    else:
        return chr(255) + encode_int(integer, length = 8, big_endian = False)

  # if (n < 253) {
  #   buf = new Buffer(1);
  #   buf.writeUInt8(n, 0);
  # } else if (n < 0x10000) {
  #   buf = new Buffer(1 + 2);
  #   buf.writeUInt8(253, 0);
  #   buf.writeUInt16LE(n, 1);
  # } else if (n < 0x100000000) {
  #   buf = new Buffer(1 + 4);
  #   buf.writeUInt8(254, 0);
  #   buf.writeUInt32LE(n, 1);
  # } else {
  #   buf = new Buffer(1 + 8);
  #   buf.writeUInt8(255, 0);
  #   buf.writeInt32LE(n & -1, 1);
  #   buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
  # }


def encode_hex(bytes):
    return binascii.hexlify(bytes)


def decode_hex(string):
    try:
        return binascii.unhexlify(string)
    except:
        # unhexlify() throws 2 different exceptions (length, and alphabet)
        raise InvalidHex(string)


def sha256(bytes):
    return hashlib.sha256(bytes).digest()


def sha1(bytes):
    return hashlib.sha1(bytes).digest()


def ripemd160(bytes):
    return hashlib.new('ripemd160', bytes).digest()


def hash160(bytes):
    return ripemd160(sha256(bytes)).digest()


def decode_script_number(bytes, f_require_minimal = False, size = 4):
    """
    Create a number from a "ScriptNum":
    This is analogous to the constructor for CScriptNum in bitcoind. Many ops in
    bitcoind's script interpreter use CScriptNum. An error is thrown if trying
    to input a number bigger than 4 bytes. A third argument, `size`, is provided
    to extend the hard limit of 4 bytes, as some usages require more than 4 bytes.
    """
    if len(bytes) >= size:
        raise InvalidScriptNumber(bytes)

    if f_require_minimal and len(bytes) > 0:
        # Check the number is encoded with the minimum possible number of bytes.

        # If the most-significant-byte - excluding the sign bit - is zero
        # then we're not minimal. Note how this test also rejects the
        # negative-zero encoding, 0x80.
        if not (decode_int(bytes[-1]) & 0x7f):
            # One exception: if there's more than one byte and the most
            # significant bit of the second-most-significant-byte is set
            # it would conflict with the sign bit. An example of this case
            # is +-255, which encode to 0xff00 and 0xff80 respectively.
            # (big-endian).
            if len(bytes) <= 1 or not (decode_int(bytes[-2]) & 0x80):
                raise InvalidMinimalScriptNumber(bytes)

    if len(bytes) == 0:
        number = 0

    elif decode_int(bytes[-1]) & 0x80:
        bytes = bytes[:-1] + encode_int(decode_int(bytes[-1]) & 0x7f)
        number = decode_int(bytes, big_endian = False) * -1

    else:
        number = decode_int(bytes, big_endian = False)

    return number


def encode_script_number(integer):
    if integer == 0:
        bytes = bytearray()

    elif integer > 0:
        bytes = encode_int(integer, big_endian = False)
        if decode_int(bytes[-1]) & 0x80:
            bytes += encode_int(0x00)

    else:
        bytes = encode_int(-integer, big_endian = False)
        if decode_int(bytes[-1]) & 0x80:
            bytes += encode_int(0x80)
        else:
            bytes = bytes[:-1] + encode_int(decode_int(bytes[-1]) | 0x80)

    return bytes
