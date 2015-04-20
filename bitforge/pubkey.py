import collections
import networks, utils
from address import Address
from errors import *
from encoding import *


BasePublicKey = collections.namedtuple('PublicKey',
    ['pair', 'network', 'compressed']
)

class PublicKey(BasePublicKey):

    class Error(BitforgeError):
        pass

    class InvalidPair(Error, ObjectError):
        "The PublicKey pair {object} is invalid (not a point of the curve)"

    class InvalidWifLength(Error, StringError):
        "The WIF {string} should be 33 (uncompressed) or 34 (compressed) bytes long, not {length}"

    class InvalidSecretLength(Error, StringError):
        "The secret {string} should be 32 bytes long, not {length}"

    class InvalidCompressionByte(Error, StringError):
        "The length of the WIF {string} suggests it's compressed, but it doesn't end in '\1'"

    class UnknownNetwork(Error, networks.UnknownNetwork):
        "No network for PublicKey with an attribute '{key}' of value {value}"

    class InvalidBinary(Error, StringError):
        "The buffer {string} is not in any recognized format"


    def __new__(cls, pair, network = networks.default, compressed = True):
        network = networks.find(network)  # may raise UnknownNetwork

        if not utils.ecdsa.is_public_pair_valid(pair):
            raise PublicKey.InvalidPair(pair)

        return super(PublicKey, cls).__new__(cls, pair, network, compressed)

    @staticmethod
    def from_private_key(privkey):
        pair = utils.public_pair_for_secret_exponent(
            utils.generator_secp256k1, privkey.secret
        )

        # The constructor will validate the pair
        return PublicKey(pair, privkey.network, privkey.compressed)

    @staticmethod
    def from_bytes(bytes, network = networks.default):
        try:
            pair       = utils.encoding.sec_to_public_pair(bytes)
            compressed = utils.encoding.is_sec_compressed(bytes)
        except utils.encoding.EncodingError:
            raise PublicKey.InvalidBinary(bytes)

        return PublicKey(pair, network, compressed)

    @staticmethod
    def from_hex(string, network = networks.default):
        try:
            bytes = decode_hex(string)
        except InvalidHex:
            raise PublicKey.InvalidHex(string)

        return PublicKey.from_bytes(bytes, network)


    def to_bytes(self):
        return utils.encoding.public_pair_to_sec(self.pair, self.compressed)

    def to_hex(self):
        return binascii.hexlify(self.to_bytes())

    def to_address(self):
        return Address.from_public_key(self)

    def __repr__(self):
        return "<PublicKey: %s, network: %s>" % (self.to_hex(), self.network.name)
