from Crypto.Cipher import AES, ChaCha20
from Crypto.Util import Padding as CryptoPadding
import hashlib
from construct import (
    Adapter, BitStruct, BitsSwapped, Container,
    Flag, Padding, RepeatUntil, Subconstruct, Construct, ListContainer
)
from lxml import etree
import base64
import zlib
from io import BytesIO

class HeaderChecksumError(Exception):
    pass
class CredentialsError(Exception):
    pass
class PayloadChecksumError(Exception):
    pass

def Reparsed(subcon_out):
    class Reparsed(Adapter):
        """Bytes <---> Parsed subcon result
        Takes in bytes and reparses it with subcon_out"""

        def _decode(self, data, con, path):
            return subcon_out.parse(data, **con)

        def _encode(self, obj, con, path):
            return subcon_out.build(obj, **con)

    return Reparsed


def aes_kdf(key, rounds, password=None, keyfile=None):
    """set up a context for AES128-ECB encryption to find transformed_key"""

    cipher = AES.new(key, AES.MODE_ECB)
    key_composite = compute_key_composite(
        password=password,
        keyfile=keyfile
    )

    # get the number of rounds from the header and transform the key_composite
    transformed_key = key_composite
    for _ in range(0, rounds):
        transformed_key = cipher.encrypt(transformed_key)

    return hashlib.sha256(transformed_key).digest()


def compute_key_composite(password=None, keyfile=None):
    """Compute composite key.
    Used in header verification and payload decryption."""

    # hash the password
    if password:
        password_composite = hashlib.sha256(password.encode('utf-8')).digest()
    else:
        password_composite = b''
    # hash the keyfile
    if keyfile:
        # try to read XML keyfile
        try:
            with open(keyfile, 'r') as f:
                tree = etree.parse(f).getroot()
                keyfile_composite = base64.b64decode(tree.find('Key/Data').text)
        # otherwise, try to read plain keyfile
        except (etree.XMLSyntaxError, UnicodeDecodeError):
            try:
                with open(keyfile, 'rb') as f:
                    key = f.read()
                    # if the length is 32 bytes we assume it is the key
                    if len(key) == 32:
                        keyfile_composite = key
                    # if the length is 64 bytes we assume the key is hex encoded
                    if len(key) == 64:
                        keyfile_composite =  key.decode('hex')
                    # anything else may be a file to hash for the key
                    keyfile_composite = hashlib.sha256(key).digest()
            except:
                raise IOError('Could not read keyfile')

    else:
        keyfile_composite = b''

    # create composite key from password and keyfile composites
    return hashlib.sha256(password_composite + keyfile_composite).digest()

def compute_master(context):
    """Computes master key from transformed key and master seed.
    Used in payload decryption."""

    # combine the transformed key with the header master seed to find the master_key
    master_key = hashlib.sha256(
        context._.header.value.dynamic_header.master_seed.data +
        context.transformed_key).digest()
    return master_key


class XML(Adapter):
    """Bytes <---> lxml etree"""

    def _decode(self, data, con, path):
        return etree.parse(BytesIO(data))

    def _encode(self, tree, con, path):
        return etree.tostring(tree)


class Concatenated(Adapter):
    """Data Blocks <---> Bytes"""

    def _decode(self, blocks, con, path):
        return b''.join([block.block_data for block in blocks])

    def _encode(self, payload_data, con, path):
        blocks = []
        # split payload_data into 1 MB blocks (spec default)
        i = 0
        while i < len(payload_data):
            blocks.append(Container(block_data=payload_data[i:i + 2**20]))
            i += 2**20
        blocks.append(Container(block_data=b''))

        return blocks

class DecryptPayload(Adapter):
    """Encrypted Bytes <---> Decrypted Bytes"""

    def _decode(self, payload_data, con, path):
        cipher = self.get_cipher(
            con.master_key,
            con._.header.value.dynamic_header.encryption_iv.data
        )
        payload_data = cipher.decrypt(payload_data)

        return payload_data

    def _encode(self, payload_data, con, path):
        payload_data = CryptoPadding.pad(payload_data, 16)
        cipher = self.get_cipher(
            con.master_key,
            con._.header.value.dynamic_header.encryption_iv.data
        )
        payload_data = cipher.encrypt(payload_data)

        return payload_data

class AES256Payload(DecryptPayload):
    def get_cipher(self, master_key, encryption_iv):
        return AES.new(master_key, AES.MODE_CBC, encryption_iv)

class ChaCha20Payload(DecryptPayload):
    def get_cipher(self, master_key, encryption_iv):
        return ChaCha20.new(key=master_key, nonce=encryption_iv)

class TwoFishPayload(DecryptPayload):
    def get_cipher(self, master_key, encryption_iv):
        raise Exception("TwoFish not implemented")


class Decompressed(Adapter):
    """Compressed Bytes <---> Decompressed Bytes"""

    def _decode(self, data, con, path):
        return zlib.decompress(data, 16 + 15)

    def _encode(self, data, con, path):
        compressobj = zlib.compressobj(
            6,
            zlib.DEFLATED,
            16 + 15,
            zlib.DEF_MEM_LEVEL,
            0
        )
        data = compressobj.compress(data)
        data += compressobj.flush()
        # pad to multiple of 16 bytes
        return data



class DynamicDict(Adapter):
    """ListContainer <---> Container
    Convenience mapping so we dont have to iterate ListContainer to find
    the right item"""

    def __init__(self, key, subcon):
        super().__init__(subcon)
        self.key = key

    # map ListContainer to Container
    def _decode(self, obj, context, path):
        d = {item[self.key]:item for item in obj}
        return Container(d)

    # map Container to ListContainer
    def _encode(self, obj, context, path):
        return ListContainer(obj.values())

# is the payload compressed?
CompressionFlags = BitsSwapped(
    BitStruct("compression" / Flag, Padding(8 * 4 - 1))
)

