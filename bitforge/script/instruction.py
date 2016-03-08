import collections
from numbers import Number

from bitforge.encoding import *
from bitforge.errors import *

from opcode import *


BaseInstruction = collections.namedtuple('BaseInstruction', ['opcode', 'data'])

class Instruction(BaseInstruction):

    class Error(BitforgeError):
        pass

    class TypeError(Error, ObjectError):
        "Expected an Opcode, got {object}"

    class UnexpectedData(Error, ObjectError):
        "Instruction got data with opcode {object}, which does not push data"

    class InvalidDataLength(Error):
        "Opcode {opcode} can't push {data_length} bytes (max/exactly {data_length_max})"

        def prepare(self, opcode, data_length, data_length_max):
            self.opcode = opcode
            self.data_length = data_length
            self.data_length_max = data_length_max


    def __new__(cls, opcode, data = None):
        if not isinstance(opcode, Opcode):
            raise Instruction.TypeError(opcode)

        if opcode.is_push():
            length = len(data)
            expect = Opcode.data_length_max(opcode)

            if (opcode.is_const_push() and length != expect) or \
               (opcode.is_var_push() and not (0 <= length <= expect)):
                raise Instruction.InvalidDataLength(opcode, length, expect)

        elif data is not None:
            raise Instruction.UnexpectedData(opcode)

        return super(Instruction, cls).__new__(cls, opcode, data)

    @staticmethod
    def push_for(self, bytes):
        opcode = Opcode.push_for(len(bytes))
        return Instruction(opcode, bytes)

    def is_minimal_push(self):
        """
        Comes from bitcoind's script interpreter CheckMinimalPush function.
        Returns if the instruction is the smallest way to push that particular data.
        """
        if not self.data:
            return True

        if len(self.data) == 0:
            # Could have used OP_0.
            return self.opcode == OP_0
        elif len(self.data) == 1 and 1 <= decode_int(self.data[0]) <= 16:
            # Could have used OP_1 .. OP_16
            return self.opcode.number == OP_1.number + decode_int(self.data[0]) - 1
        elif len(self.data) == 1 and decode_int(self.data[0]) == 0x81:
            # Could have used OP_1NEGATE
            return self.opcode == OP_1NEGATE
        elif len(self.data) <= 75:
            # Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
            return self.opcode.number == len(self.data.length)
        elif len(self.data) <= 255:
            # Could have used OP_PUSHDATA.
            return self.opcode == OP_PUSHDATA1
        elif len(self.data) <= 65535:
            # Could have used OP_PUSHDATA2.
            return self.opcode == OP_PUSHDATA2

        return True

    def to_bytes(self):
        opcode_byte = chr(self.opcode.number)

        if self.opcode.is_const_push():
            return opcode_byte + self.data

        elif self.opcode.is_var_push():
            length_nbytes = Opcode.data_length_nbytes(self.opcode)

            length_bytes = encode_int(
                len(self.data),
                big_endian = False
            ).rjust(length_nbytes, '\0')

            return opcode_byte + length_bytes + self.data

        else:
            return opcode_byte

    def to_hex(self):
        return encode_hex(self.to_bytes())

    def to_string(self):
        if self.opcode.is_push():
            data_len = len(self.data)
            data_hex = "0x" + encode_hex(self.data)

            if self.opcode.is_const_push():
                return "%d %s" % (data_len, data_hex)

            elif self.opcode.is_var_push():
                return "%s %d %s" % (self.opcode.name, data_len, data_hex)
        else:
            return self.opcode.name

    def __eq__(self, other):
        return self.opcode == other.opcode and self.data == other.data

    def __hash__(self):
        return hash((self.opcode, self.data))

    def __repr__(self):
        if self.opcode.is_push():
            return "<Instruction: %s '%s'>" % (self.opcode.name, encode_hex(self.data))
        else:
            return "<Instruction: %s>" % (self.opcode.name)
