import sys, inspect
from numbers import Number
from functools import total_ordering

from bitforge.errors import *

# Below is a list of all *named* opcodes. Their values, integers in the
# listing, will be dynamically replaced with Opcode instances further below.

# Numbers (in range [0, 16]):
OP_0  = 0
OP_1  = 81
OP_2  = 82
OP_3  = 83
OP_4  = 84
OP_5  = 85
OP_6  = 86
OP_7  = 87
OP_8  = 88
OP_9  = 89
OP_10 = 90
OP_11 = 91
OP_12 = 92
OP_13 = 93
OP_14 = 94
OP_15 = 95
OP_16 = 96

# Number -1:
OP_1NEGATE = 79

# Booleans:
OP_FALSE = 0
OP_TRUE  = 81

# Constant-length pushes, opcodes [1-75]:
# These opcodes HAVE NO PROPER NAME, they are represented as their numeric
# values in script.

# Variable-length pushes:
OP_PUSHDATA1 = 76
OP_PUSHDATA2 = 77
OP_PUSHDATA4 = 78

# Flow control:
OP_NOP      = 97
OP_VER      = 98
OP_IF       = 99
OP_NOTIF    = 100
OP_VERIF    = 101
OP_VERNOTIF = 102
OP_ELSE     = 103
OP_ENDIF    = 104
OP_VERIFY   = 105
OP_RETURN   = 106

# Stack operations:
OP_TOALTSTACK   = 107
OP_FROMALTSTACK = 108
OP_2DROP        = 109
OP_2DUP         = 110
OP_3DUP         = 111
OP_2OVER        = 112
OP_2ROT         = 113
OP_2SWAP        = 114
OP_IFDUP        = 115
OP_DEPTH        = 116
OP_DROP         = 117
OP_DUP          = 118
OP_NIP          = 119
OP_OVER         = 120
OP_PICK         = 121
OP_ROLL         = 122
OP_ROT          = 123
OP_SWAP         = 124
OP_TUCK         = 125

# String operations:
OP_CAT    = 126
OP_SUBSTR = 127
OP_LEFT   = 128
OP_RIGHT  = 129
OP_SIZE   = 130

# Bitwise logic:
OP_INVERT      = 131
OP_AND         = 132
OP_OR          = 133
OP_XOR         = 134
OP_EQUAL       = 135
OP_EQUALVERIFY = 136
OP_RESERVED1   = 137
OP_RESERVED2   = 138

# Mathematical operators:
OP_1ADD      = 139
OP_1SUB      = 140
OP_2MUL      = 141
OP_2DIV      = 142
OP_NEGATE    = 143
OP_ABS       = 144
OP_NOT       = 145
OP_0NOTEQUAL = 146
OP_ADD       = 147
OP_SUB       = 148
OP_MUL       = 149
OP_DIV       = 150
OP_MOD       = 151
OP_LSHIFT    = 152
OP_RSHIFT    = 153

# Comparison operators:
OP_BOOLAND            = 154
OP_BOOLOR             = 155
OP_NUMEQUAL           = 156
OP_NUMEQUALVERIFY     = 157
OP_NUMNOTEQUAL        = 158
OP_LESSTHAN           = 159
OP_GREATERTHAN        = 160
OP_LESSTHANOREQUAL    = 161
OP_GREATERTHANOREQUAL = 162
OP_MIN                = 163
OP_MAX                = 164
OP_WITHIN             = 165

# Cryptography:
OP_RIPEMD160 = 166
OP_SHA1 = 167
OP_SHA256 = 168
OP_HASH160 = 169
OP_HASH256 = 170
OP_CODESEPARATOR = 171
OP_CHECKSIG = 172
OP_CHECKSIGVERIFY = 173
OP_CHECKMULTISIG = 174
OP_CHECKMULTISIGVERIFY = 175

# Locktime:
OP_CHECKLOCKTIMEVERIFY = 177

# Ignored operations:
OP_NOP1  = 176
OP_NOP3  = 178
OP_NOP4  = 179
OP_NOP5  = 180
OP_NOP6  = 181
OP_NOP7  = 182
OP_NOP8  = 183
OP_NOP9  = 184
OP_NOP10 = 185

# Internal operations (invalid if found in script):
OP_PUBKEYHASH    = 253
OP_PUBKEY        = 254
OP_INVALIDOPCODE = 255
OP_RESERVED      = 80


@total_ordering
class Opcode(object):

    class Error(BitforgeError):
        pass

    class UnknownOpcodeName(Error, StringError):
        "No known operation named {string}"

    class UnknownOpcodeNumber(Error, NumberError):
        "No known operation numbered {number}"

    class InvalidConstPushLength(Error, StringError):
        "No constant push opcode can push {length} bytes (only [1-75])"

    class InvalidPushLength(Error, NumberError):
        "No Opcode can push {number} bytes"

    class TypeError(Error, ObjectError):
        "Opcodes are initialized from numbers and names, got object {object}"


    opcode_number_to_name = {}  # Filled after class definition


    def __init__(self, number):
        if not (0 <= number <= 255):
            raise Opcode.UnknownOpcodeNumber(number)

        self.number = number

    @property
    def name(self):
        if self.is_const_push():
            return "_PUSH_%d_BYTES" % self.number
        else:
            return Opcode.opcode_number_to_name[self.number]

    def is_push(self):
        return self.is_const_push() or self.is_var_push()

    def is_const_push(self):
        # Opcodes with `value` in the range [1, 75] push `value` bytes onto
        # the stack
        return 1 <= self.number <= 75

    def is_var_push(self):
        # PUSHDATA1, PUSHDATA2, and PUSHDATA4 push `n` bytes onto the stack,
        # where `n` is the integer in the 1/2/4 bytes following the opcode
        return self in (OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4)

    def __repr__(self):
        if self.is_const_push():
            return "<Opcode PUSH %d BYTES>" % self.number
        else:
            return "<Opcode %d: %s>" % (self.number, self.name)

    def __eq__(self, other):
        if not isinstance(other, Opcode):
            return False

        return self.number == other.number

    def __lt__(self, other):
        if not isinstance(other, Opcode):
            return False

        return self.number < other.number

    def __hash__(self):
        return hash(self.number)


    @staticmethod
    def for_number(n):
        if 0 <= n <= 16:
            return OP_0 if n == 0 else Opcode(OP_1.number + n - 1)
        else:
            raise ValueError("Expected number in range [0, 16], got %d" % n)

    @staticmethod
    def from_name(name):
        if not (name.startswith('OP_') and hasattr(Opcode, name)):
            raise Opcode.UnknownOpcodeName(name)

        return Opcode(getattr(Opcode, name))

    @staticmethod
    def const_push_for(length):
        if not (1 <= length <= 75):
            raise Opcode.InvalidConstPushLength(length)

        return Opcode(length)

    @staticmethod
    def var_push_for(length):
        if length < 1:
            raise InvalidPushLength(length)

        for opcode in [OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4]:
            if length <= Opcode.data_length_max(opcode):
                return opcode

        raise InvalidPushLength(length)

    @staticmethod
    def push_for(length):
        if length <= 75:
            return Opcode.const_push_for(length)
        else:
            return Opcode.var_push_for(length)

    @staticmethod
    def data_length_max(opcode):
        if opcode.is_const_push():
            return opcode.number

        elif opcode.is_var_push():
            return {
                OP_PUSHDATA1: 2 ** 8,
                OP_PUSHDATA2: 2 ** 16,
                OP_PUSHDATA4: 2 ** 32
            }[opcode] - 1

        else:
            return 0

    @staticmethod
    def data_length_nbytes(opcode):
        return {
            OP_PUSHDATA1: 1,
            OP_PUSHDATA2: 2,
            OP_PUSHDATA4: 4
        }[opcode]



# Walk the OP_* variables, mapping them to their names and creating Opcode objs:
_module = sys.modules[__name__]

for name, number in inspect.getmembers(_module):
    if name.startswith('OP_'):
        # Populate the reverse opcode-number-to-name map:
        Opcode.opcode_number_to_name[number] = name

        # Replace integer values with actual Opcode instances:
        setattr(_module, name, Opcode(number))

Opcode.opcode_number_to_name[OP_0] = 'OP_0' # shares number with OP_FALSE
Opcode.opcode_number_to_name[OP_1] = 'OP_1' # shares number with OP_TRUE

del _module # the expected use for this module is to import *
