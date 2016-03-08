from bitforge import Transaction
from bitforge.tools import Buffer

from bitforge.encoding import encode_script_number, decode_script_number
from bitforge.encoding import sha1, ripemd160, sha256, hash160

from opcode import *


class Interpreter(object):

    def __init__(self):
        self.initialize()

    def initialize(self):
        self.stack = []
        self.altstack = []
        self.pc = 0
        self.pbegincodehash = 0
        self.nop_count = 0
        self.vf_exec = []
        self.errstr = ''
        self.flags = 0

    def verify(self, script_sig, script_pubkey, tx, nin, flags):
        """
        Verifies a Script by executing it and returns true if it is valid.
        This function needs to be provided with the scriptSig and the scriptPubkey
        separately.

        :param script_sig: the script's first part (corresponding to the tx input)
        :param script_pubkey: the script's last part (corresponding to the tx output)
        :param tx: the transaction containing the script_sig in one input (used to
            check signature validity for some opcodes like OP_CHECKSIG)
        :param nin: index of the transaction input containing the scriptSig verified.
        :param flags: evaluation flags. See Interpreter.SCRIPT_* constants

        Translated from bitcoind's VerifyScript
        """
        self.script = script_sig
        self.tx = tx or Transaction([], [])
        self.nin = nin or 0
        self.flags = flags or 0

        if flags & Interpreter.SCRIPT_VERIFY_SIGPUSHONLY and not script_sig.is_push_only():
            self.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
            return False

        # Evaluate script_sig
        if not self.evaluate():
            return False

        if self.flags & Interpreter.SCRIPT_VERIFY_P2SH:
            stack_copy = list(this.stack)

        stack = self.stack
        self.initialize()
        self.script = script_pubkey
        self.stack = stack
        self.tx = tx or Transaction([], [])
        self.nin = nin or 0
        self.flags = flags or 0

        # evaluate script_pubkey
        if not self.evaluate():
            return False

        if len(self.stack) == 0:
            self.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_RESULT'
            return False

        bytes = self.stack[-1]
        if not Interpreter.cast_to_bool(bytes):
            self.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_STACK'
            return False

        # Additional validation for spend-to-script-hash transactions:
        if (self.flags & Interpreter.SCRIPT_VERIFY_P2SH) and script_sig.is_script_hash_out():
            # script_sig must be literals-only or validation fails
            if not script_sig.is_push_only():
                self.errstr = 'SCRIPT_ERR_SIG_PUSHONLY'
                return False

            # stack_copy cannot be empty here, because if it was the
            # P2SH  HASH <> EQUAL  script_pubkey would be evaluated with
            # an empty stack and the EvalScript above would return false.
            if len(stack_copy) == 0:
                raise Exception('internal error - stack copy empty')

            redeem_bytes = stack_copy[-1]
            redeem_script = Script.from_bytes(redeem_bytes)
            stack_copy = stack_copy[:-1]

            self.initialize()
            self.script = redeem_script
            self.stack = stack_copy
            self.tx = tx or Transaction([], [])
            self.nin = nin or 0
            self.flags = flags or 0

            # Evaluate redeem_script
            if not self.evaluate():
                return False

            if len(stack_copy) == 0:
                self.errstr = 'SCRIPT_ERR_EVAL_FALSE_NO_P2SH_STACK'
                return False

            if not Interpreter.cast_to_bool(stack_copy[-1]):
                self.errstr = 'SCRIPT_ERR_EVAL_FALSE_IN_P2SH_STACK'
                return False

        return True

    def evaluate(self):
        """
        Based on bitcoind's EvalScript function, with the inner loop moved to
        Interpreter.step()
        bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
        """
        if len(self.script.to_bytes) > 10000:
            self.errstr = 'SCRIPT_ERR_SCRIPT_SIZE'
            return False

        try:
            while self.pc < len(self.script.instructions):
                if not self.step():
                    return False

            if len(self.stack) + len(self.altstack) > 1000:
                self.errstr = 'SCRIPT_ERR_STACK_SIZE'
                return False

        except Exception as e:
            self.errstr = 'SCRIPT_ERR_UNKNOWN_ERROR: ' + e
            return False

        if len(self.vf_exec) > 0:
            self.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
            return False

        return True

    def step(self):
        """
        Based on the inner loop of bitcoind's EvalScript function
        bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
        """
        f_required_minimal = self.flags & Interpreter.SCRIPT_VERIFY_MINIMALDATA

        f_exec = False not in self.vf_exec
        instruction = self.script.instructions[self.pc]
        self.pc += 1

        if instruction.data and len(instruction.data) > Interpreter.MAX_SCRIPT_ELEMENT_SIZE:
            self.errstr = 'SCRIPT_ERR_PUSH_SIZE'
            return False

        # Note how Opcode.OP_RESERVED does not count towards the opcode limit.
        if instruction.opcode > OP_16:
            self.nop_count += 1  # TODO: use itertools.count
            if self.nop_count > 201:
                self.errstr = 'SCRIPT_ERR_OP_COUNT'
                return False

        if (instruction.opcode == OP_CAT or
            instruction.opcode == OP_SUBSTR or
            instruction.opcode == OP_LEFT or
            instruction.opcode == OP_RIGHT or
            instruction.opcode == OP_INVERT or
            instruction.opcode == OP_AND or
            instruction.opcode == OP_OR or
            instruction.opcode == OP_XOR or
            instruction.opcode == OP_2MUL or
            instruction.opcode == OP_2DIV or
            instruction.opcode == OP_MUL or
            instruction.opcode == OP_DIV or
            instruction.opcode == OP_MOD or
            instruction.opcode == OP_LSHIFT or
            instruction.opcode == OP_RSHIFT):

            self.errstr = 'SCRIPT_ERR_DISABLED_OPCODE'
            return False

        if f_exec and instruction.opcode <= OP_PUSHDATA4:
            if f_required_minimal and not instruction.is_minimal_push():
                self.errstr = 'SCRIPT_ERR_MINIMALDATA'
                return False

            if not instruction.data:
                self.stack.push(Interpreter.false)
            else:
                self.stack.push(instruction.data)

        elif f_exec or OP_IF <= instruction.opcode <= OP_ENDIF:
            if instruction.opcode in [OP_1NEGATE, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8, OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16]:
                number = instruction.opcode.number - (OP_1 - 1)
                bytes = encode_script_number(number)
                self.stack.push(bytes)
                # The result of theseopcodes should always be the minimal way to
                # push data, so no need to Check MinimalPush here.

            elif instruction.opcode == OP_NOP:
                pass

            elif instruction.opcode == OP_CHECKLOCKTIMEVERIFY:
                if self.flags & Interpreter.SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY:
                    if self.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                        self.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
                        return False

                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                # Note that elsewhere numeric opcodes are limited to
                # operands in the range -2**31+1 to 2**31-1, however it is
                # legal for opcodes to produce results exceeding that
                # range. This limitation is implemented by CScriptNum's
                # default 4-byte limit.
                #
                # If we kept to that limit we'd have a year 2038 problem,
                # even though the nLockTime field in transactions
                # themselves is uint32 which only becomes meaningless
                # after the year 2106.
                #
                # Thus as a special case we tell CScriptNum to accept up
                # to 5-byte bignums, which are good until 2**39-1, well
                # beyond the 2**32-1 limit of the nLockTime field itself.

                nlock_time = decode_script_number(self.stack[-1], f_required_minimal, 5)

                # In the rare event that the argument may be < 0 due to
                # some arithmetic being done first, you can always use
                # 0 MAX CHECKLOCKTIMEVERIFY.

                if nlock_time < 0:
                    self.errstr = 'SCRIPT_ERR_NEGATIVE_LOCKTIME'
                    return False

                # Actually compare the specified lock time with the transaction.
                if not self.check_lock_time(nlock_time):
                    self.errstr = 'SCRIPT_ERR_UNSATISFIED_LOCKTIME'
                    return False

            elif instruction.opcode in [OP_NOP1, OP_NOP3, OP_NOP4, OP_NOP5, OP_NOP6, OP_NOP7, OP_NOP8, OP_NOP9, OP_NOP10]:
                if self.flags & Interpreter.SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS:
                    self.errstr = 'SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS'
                    return False

            elif instruction.opcode in [OP_IF, OP_NOTIF]:
                # <expression> if [statements] [else  [statements]] endif
                f_value = False
                if f_exec:
                    if len(self.stack) < 1:
                        self.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
                        return False

                    bytes = self.stack.pop()
                    f_value = Interpreter.cast_to_bool(bytes)

                    if instruction.opcode == OP_NOTIF:
                        f_value = not f_value

                self.vf_exec.push(f_value)

            elif instruction.opcode == OP_ELSE:
                if len(self.vf_exec) == 0:
                    self.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
                    return False

                self.vf_exec[-1] = not self.vf_exec[-1]

            elif instruction.opcode == OP_ENDIF:
                if len(self.vf_exec) == 0:
                    self.errstr = 'SCRIPT_ERR_UNBALANCED_CONDITIONAL'
                    return False

                self.vf_exec.pop()

            elif instruction.opcode == OP_VERIFY:
                # (true -- ) or
                # (false -- false) and return
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack[-1]
                f_value = Interpreter.cast_to_bool(bytes)
                if f_value:
                    self.stack.pop()
                else:
                    self.errstr = 'SCRIPT_ERR_VERIFY'
                    return False

            elif instruction.opcode == OP_RETURN:
                self.errstr = 'SCRIPT_ERR_OP_RETURN'
                return False

            elif instruction.opcode == OP_TOALTSTACK:
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.altstack.push(self.stack.pop())

            elif instruction.opcode == OP_FROMALTSTACK:
                if len(self.altstack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_ALTSTACK_OPERATION'
                    return False

                self.stack.push(self.altstack.pop())

            elif instruction.opcode == OP_2DROP:
                # (x1, x2 -- )
                if len(self.stack.length < 2):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.stack = stack[:-2]

            elif instruction.opcode == OP_2DUP:
                # (x1, x2 -- x1 x2 x1 x2)
                if len(self.stack.length < 2):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2 = self.stack[-2:]
                self.stack += [x1, x2]

            elif instruction.opcode == OP_3DUP:
                # (x1, x2, x3 -- x1 x2 x3 x1 x2 x3)
                if len(self.stack.length < 3):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2, x3 = self.stack[-3:]
                self.stack += [x1, x2, x3]

            elif instruction.opcode == OP_2OVER:
                # (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
                if len(self.stack.length < 4):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2, x3, x4 = self.stack[-4:]
                self.stack += [x1, x2]

            elif instruction.opcode == OP_2ROT:
                # (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
                if len(self.stack.length < 6):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2, x3, x4, x5, x6 = self.stack[-6:]
                self.stack = self.stack[:-6] + [x3, x4, x5, x6, x1, x2]

            elif instruction.opcode == OP_2SWAP:
                # (x1 x2 x3 x4 -- x3 x4 x1 x2)
                if len(self.stack.length < 4):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2, x3, x4 = self.stack[-4:]
                self.stack = self.stack[:-4] + [x3, x4, x1, x2]

            elif instruction.opcode == OP_IFDUP:
                # (x - 0 | x x)
                if len(self.stack.length < 1):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack[-1]
                f_value = Interpreter.cast_to_bool(bytes)
                if f_value:
                    self.stack.push(bytes)

            elif instruction.opcode == OP_DEPTH:
                bytes = encode_script_number(len(self.stack))
                self.stack.push(bytes)

            elif instruction.opcode == OP_DROP:
                # ( x -- )
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.stack.pop()

            elif instruction.opcode == OP_DUP:
                # ( x -- x x )
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.stack.push(self.stack[-1])

            elif instruction.opcode == OP_NIP:
                # (x1 x2 -- x2)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.stack.pop(-2)

            elif instruction.opcode == OP_OVER:
                # (x1 x2 -- x1 x2 x1)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                self.stack.push(self.stack[-2])

            elif instruction.opcode in [OP_PICK, OP_ROLL]:
                # (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
                # (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack.pop()
                n = decode_script_number(bytes, f_required_minimal)
                if n < 0 or n >= len(self.stack):
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack[-n-1]
                if instruction.opcode == OP_ROLL:
                    self.stack.pop(-n-1)

                self.stack.push(bytes)

            elif instruction.opcode == OP_ROT:
                # (x1 x2 x3 -- x2 x3 x1)
                # x2 x1 x3  after first swap
                # x2 x3 x1  after second swap
                if len(self.stack) < 3:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2, x3 = self.stack[-3:]
                self.stack = self.stack[:-3] + [x2, x3, x1]

            elif instruction.opcode == OP_SWAP:
                # (x1 x2 -- x2 x1)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2 = self.stack[-2:]
                self.stack = self.stack[:-2] + [x2, x1]

            elif instruction.opcode == OP_TUCK:
                # (x1 x2 -- x2 x1 x2)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2 = self.stack[-2:]
                self.stack = self.stack[:-2] + [x2, x1, x2]

            elif instruction.opcode == OP_SIZE:
                # (in -- in size)
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                size = len(self.stack[-1])
                self.stack += [encode_script_number(size)]

            elif instruction.opcode in [OP_EQUAL, OP_EQUALVERIFY]:
                # case Opcode.OP_NOTEQUAL # use Opcode.OP_NUMNOTEQUAL
                # (x1 x2 - bool)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                x1, x2 = self.stack[-2:]
                f_equal = x1 == x2
                self.stack = self.stack[:-2] + [Interpreter.bool_bytes[f_equal]]

                if instruction.opcode == OP_EQUALVERIFY:
                    if f_equal:
                        self.stack.pop()
                    else:
                        self.errstr = 'SCRIPT_ERR_EQUALVERIFY'
                        return False

            elif instruction.opcode in [OP_1ADD, OP_1SUB, OP_NEGATE, OP_ABS, OP_NOT, OP_0NOTEQUAL]:
                # (in -- out)
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack[-1]
                number = decode_script_number(bytes, f_required_minimal)

                if instruction.opcode == OP_1ADD:
                    number += 1

                elif instruction.opcode == OP_1SUB:
                    number -= 1

                elif instruction.opcode == OP_NEGATE:
                    number = -number

                elif instruction.opcode == OP_ABS:
                    number = abs(-1)

                elif instruction.opcode == OP_NOT:
                    number = int(number == 0)

                elif instruction.opcode == OP_0NOTEQUAL:
                    number = int(number != 0)

                self.stack = self.stack[:-1] + [encode_script_number(number)]

            elif instruction.opcode in [
                OP_ADD, OP_SUB, OP_BOOLAND,
                OP_BOOLOR, OP_NUMEQUAL,
                OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL,
                OP_LESSTHAN, OP_GREATERTHAN,
                OP_LESSTHANOREQUAL,
                OP_GREATERTHANOREQUAL,
                OP_MIN, OP_MAX]:

                # (in -- out)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                number1 = decode_script_number(self.stack[-2], f_required_minimal)
                number2 = decode_script_number(self.stack[-1], f_required_minimal)

                if instruction.opcode == OP_ADD:
                    result = number1 + number2

                elif instruction.opcode == OP_SUB:
                    result = number1 - number2

                elif instruction.opcode == OP_BOOLAND:
                    result = all([number1, number2])

                elif instruction.opcode == OP_BOOLOR:
                    result = any([number1, number2])

                elif instruction.opcode in [OP_NUMEQUAL, OP_NUMEQUALVERIFY]:
                    result = int(number1 == number2)

                elif instruction.opcode == OP_NUMNOTEQUAL:
                    result = int(number1 != number2)

                elif instruction.opcode == OP_LESSTHAN:
                    result = number1 < number2

                elif instruction.opcode == OP_GREATERTHAN:
                    result = number1 > number2

                elif instruction.opcode == OP_LESSTHANOREQUAL:
                    result = number1 <= number2

                elif instruction.opcode == OP_GREATERTHANOREQUAL:
                    result = number1 >= number2

                elif instruction.opcode == OP_MIN:
                    result = min(number1, number2)

                elif instruction.opcode == OP_MAX:
                    result = max(number1, number2)

                self.stack = self.stack[:-2] + [encode_script_number(result)]

                if instruction.opcode == OP_NUMEQUALVERIFY:
                    if Interpreter.cast_to_bool(self.stack[-1]):
                        self.stack = self.stack[:-1]
                    else:
                        self.errstr = 'SCRIPT_ERR_NUMEQUALVERIFY'
                        return False

            elif instruction.opcode == OP_WITHIN:
                # (x min max -- out)
                if len(self.stack) < 3:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                number1, number2, number3 = map(decode_script_number, self.stack[-3:])
                f_value = number2 <= number1 < number3

                self.stack = self.stack[:-3] + [Interpreter.bool_bytes[f_value]]

            elif instruction.opcode in [OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256]:
                # (x min max -- out)
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                bytes = self.stack[-1]
                if instruction.opcode == OP_RIPEMD160:
                    result = ripemd160(bytes)
                elif instruction.opcode == OP_SHA1:
                    result = sha1(bytes)
                elif instruction.opcode == OP_SHA256:
                    result = sha256(bytes)
                elif instruction.opcode == OP_HASH160:
                    result = hash160(bytes)
                elif instruction.opcode == OP_HASH256:
                    result = sha256(sha256(bytes))

                self.stack = self.stack[:-1] + [result]

            elif instruction.opcode == OP_CODESEPARATOR:
                # hash starts after the code separator
                self.pbegincodehash = self.pc

            elif instruction.opcode in [OP_CHECKSIG, OP_CHECKSIGVERIFY]:
                # (sig pubkey -- bool)
                if len(self.stack) < 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                sig_bytes, pubkey_bytes = self.stack[-2:]

                # Subset of script starting at the most recent codeseparator
                # CScript scriptCode(pbegincodehash, pend);
                from_instruction = self.pbegincodehash
                subscript = Script(self.instructions[from_instruction:])

                # Drop the signature, since there's no way for a signature to sign itself
                subscript.remove_opcode_by_data(sig_bytes)

                if not self.check_signature_encoding(sig_bytes) or not self.check_pubkey_encoding(pubkey_bytes):
                    return False

                try:
                    signature = Signature.from_tx_format(sig_bytes)
                    pubkey = PublicKey.from_bytes(pubkey_bytes)
                    f_success = self.tx.verify_signature(signature, pubkey, this.nin, subscript)
                except:
                    f_success = False

                self.stack = self.stack[:-2] + [Interpreter.bool_bytes[f_success]]
                if instruction.opcode == OP_CHECKSIGVERIFY:
                    if f_success:
                        self.stack = self.stack[:-1]
                    else:
                        self.errstr = 'SCRIPT_ERR_CHECKSIGVERIFY'
                        return False

            elif instruction.opcode in [OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY]:
                # ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                ikey = 2
                keys_count = decode_script_number(self.stack[-1], f_required_minimal)
                if not (0 <= keys_count <= 20):
                    self.errstr = 'SCRIPT_ERR_PUBKEY_COUNT'
                    return False

                self.nop_count += keys_count
                if self.nop_count > 201:
                    self.errstr = 'SCRIPT_ERR_OP_COUNT'
                    return False

                if len(self.stack) < keys_count + 2:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                isig = keys_count + 3
                sigs_count = decode_script_number(self.stack[-keys_count-2], f_required_minimal)
                if not (0 <= sigs_count <= keys_count):
                    self.errstr = 'SCRIPT_ERR_SIG_COUNT'
                    return False

                if len(self.stack) < keys_count + sigs_count + 3:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                # Subset of script starting at the most recent codeseparator
                from_instruction = self.pbegincodehash
                subscript = Script(self.instructions[from_instruction:])

                for i in range(sigs_count):
                    sig_bytes = self.stack[-isig-i]
                    subscript.remove_opcode_by_data(sig_bytes)

                total_elements = sigs_count + keys_count + 2
                f_success = True
                while f_success and sigs_count > 0:
                    sig_bytes = self.stack[-isig]
                    pubkey_bytes = self.stack[-ikey]

                    if not self.check_signature_encoding(sig_bytes) or not self.check_pubkey_encoding(pubkey_bytes):
                        return False

                    try:
                        signature = Signature.from_tx_format(sig_bytes)
                        pubkey = PublicKey.from_bytes(pubkey_bytes, False)
                        f_ok = self.tx.verify_signature(signature, pubkey, self.nin, subscript)
                    except:
                        f_ok = False

                    if f_ok:
                        isig += 1
                        sigs_count -= 1

                    ikey += 1
                    keys_count -= 1

                    # If there are more signature left than keys left,
                    # then too many signatures have failed
                    if sigs_count > keys_count:
                        f_success = False

                # Clean up stack of actual arguments
                self.stack = self.stack[:-total_elements]

                # A bug causes CHECKMULTISIG to consume one extra argument
                # whose contents were not checked in any way.
                #
                # Unfortunately this is a potential source of mutability,
                # so optionally verify it is exactly equal to zero prior
                # to removing it from the stack.
                if len(self.stack) < 1:
                    self.errstr = 'SCRIPT_ERR_INVALID_STACK_OPERATION'
                    return False

                if (self.flags & Interpreter.SCRIPT_VERIFY_NULLDUMMY) and len(self.stack[-1]):
                    self.errstr = 'SCRIPT_ERR_SIG_NULLDUMMY'
                    return False

                self.stack = self.stack[:-1] + [Interpreter.bool_bytes[f_success]]

                if instruction.opcode == OP_CHECKMULTISIGVERIFY:
                    if f_success:
                        self.stack[:-1]
                    else:
                        self.errstr = 'SCRIPT_ERR_CHECKMULTISIGVERIFY'
                        return False

            # Default
            else:
                self.errstr = 'SCRIPT_ERR_BAD_OPCODE'
                return False

        return True

    def check_lock_time(self, nlock_time):
        pass

    def check_signature_encoding(self, bytes):
        pass

    def check_pubkey_encoding(self, bytes):
        pass

    @staticmethod
    def cast_to_bool(bytes):
        pass


    # Interpreter constants
    true = Buffer([1])
    false = Buffer([])
    bool_bytes = {
        True: Buffer([1]),
        False: Buffer([]),
    }

    MAX_SCRIPT_ELEMENT_SIZE = 520
    LOCKTIME_THRESHOLD = 500000000

    # Flags taken from bitcoind
    # bitcoind commit: b5d1b1092998bc95313856d535c632ea5a8f9104
    SCRIPT_VERIFY_NONE = 0

    # Evaluate P2SH subscripts (softfork safe, BIP16).
    SCRIPT_VERIFY_P2SH = 1 << 0

    # Passing a non-strict-DER signature or one with undefined hashtype to a checksig operation causes script failure.
    # Passing a pubkey that is not (0x04 + 64 bytes) or (0x02 or 0x03 + 32 bytes) to checksig causes that pubkey to be
    # skipped (not softfork safe: this flag can widen the validity of OP_CHECKSIG OP_NOT).
    SCRIPT_VERIFY_STRICTENC = 1 << 1

    # Passing a non-strict-DER signature to a checksig operation causes script failure (softfork safe, BIP62 rule 1)
    SCRIPT_VERIFY_DERSIG = 1 << 2

    # Passing a non-strict-DER signature or one with S > order/2 to a checksig operation causes script failure
    # (softfork safe, BIP62 rule 5).
    SCRIPT_VERIFY_LOW_S = 1 << 3

    # Verify dummy stack item consumed by CHECKMULTISIG is of zero-length (softfork safe, BIP62 rule 7).
    SCRIPT_VERIFY_NULLDUMMY = 1 << 4

    # Using a non-push operator in the scriptSig causes script failure (softfork safe, BIP62 rule 2).
    SCRIPT_VERIFY_SIGPUSHONLY = 1 << 5

    # Require minimal encodings for all push operations (OP_0... OP_16, OP_1NEGATE where possible, direct
    # pushes up to 75 bytes, OP_PUSHDATA up to 255 bytes, OP_PUSHDATA2 for anything larger). Evaluating
    # any other push causes the script to fail (BIP62 rule 3).
    # In addition, whenever a stack element is interpreted as a number, it must be of minimal length (BIP62 rule 4).
    # (softfork safe)
    SCRIPT_VERIFY_MINIMALDATA = 1 << 6

    # Discourage use of NOPs reserved for upgrades (NOP1-10)
    #
    # Provided so that nodes can avoid accepting or mining transactions
    # containing executed NOP's whose meaning may change after a soft-fork,
    # thus rendering the script invalid; with this flag set executing
    # discouraged NOPs fails the script. This verification flag will never be
    # a mandatory flag applied to scripts in a block. NOPs that are not
    # executed, e.g.  within an unexecuted IF ENDIF block, are *not* rejected.
    SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS = 1 << 7

    # CLTV See BIP65 for details.
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY = 1 << 9
