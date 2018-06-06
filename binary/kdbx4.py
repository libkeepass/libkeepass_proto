#!/bin/env python3
# Evan Widloski - 2018-04-11
# keepass decrypt experimentation

import struct
import hashlib
import argon2
import zlib
import copy
import hmac
from io import BytesIO
from construct import (
    Byte, Bytes, Int16ul, Int32ul, RepeatUntil, GreedyBytes, Struct, this,
    BitsSwapped, RawCopy, Mapping, Adapter, Container, Switch, Flag, Prefixed,
    ListContainer, Int64ul, Int32sl, Int64sl, GreedyString, BitStruct, Padding,
    Peek, Checksum, Computed, IfThenElse, Pointer, Tell
)
from common import (
    aes_kdf, Concatenated, AES256Payload, ChaCha20Payload, TwoFishPayload,
    DynamicDict, compute_key_composite, Reparsed, Decompressed,
    compute_master, CompressionFlags
)

database = 'test4.kdbx'
password = b'shatpass'
# password = None
keyfile = 'test4.key'
# keyfile = None

s = BytesIO(open(database, 'rb').read())

# -------------------- Key Derivation --------------------

# https://github.com/keepassxreboot/keepassxc/blob/8324d03f0a015e62b6182843b4478226a5197090/src/format/KeePass2.cpp#L24-L26 
kdf_uuids = {
    'argon2': b'\xefcm\xdf\x8c)DK\x91\xf7\xa9\xa4\x03\xe3\n\x0c',
    'aes': b'\xc9\xd9\xf3\x9ab\x8aD`\xbft\r\x08\xc1\x8aO\xea',
}

def compute_transformed(context, key_composite):
    """Compute transformed key for opening database"""

    kdf_parameters = context.header.value.dynamic_header.kdf_parameters.data.dict

    if kdf_parameters['$UUID'].value == kdf_uuids['argon2']:
        transformed_key = argon2.low_level.hash_secret_raw(
            secret=key_composite,
            salt=kdf_parameters['S'].value,
            hash_len=32,
            type=argon2.low_level.Type.D,
            time_cost=kdf_parameters['I'].value,
            memory_cost=kdf_parameters['M'].value // 1024,
            parallelism=kdf_parameters['P'].value,
            version=kdf_parameters['V'].value
        )
    elif kdf_parameters['$UUID'].value == kdf_uuids['aes']:
        transformed_key = aes_kdf(
            kdf_parameters['S'].value,
            kdf_parameters['R'].value,
            key_composite
        )
    else:
        raise Exception('Unsupported key derivation method')

    return transformed_key

def compute_header_hmac_hash(context):
    """Compute HMAC-SHA256 hash of header.
    Used to prevent header tampering."""

    return hmac.new(
        hashlib.sha512(
            b'\xff' * 8 +
            hashlib.sha512(
                context.header.value.dynamic_header.master_seed.data +
                context.transformed_key +
                b'\x01'
            ).digest()
        ).digest(),
        context.header.data,
        hashlib.sha256
    ).digest()


#--------------- KDF Params / Plugin Data ----------------

VariantDictionaryItem = Struct(
    "type" / Byte,
    "key" / Prefixed(Int32ul, GreedyString('utf8')),
    "value" / Prefixed(
        Int32ul,
        Switch(
            this.type,
            {0x04: Int32ul,
             0x05: Int64ul,
             0x08: Flag,
             0x0C: Int32sl,
             0x0D: Int64sl,
             0x42: GreedyBytes,
             0x18: GreedyString
            }
        )
    ),
    "next_byte" / Peek(Byte)
)

# new dynamic dictionary structure added in KDBX4
VariantDictionary = Struct(
    "version" / Bytes(2),
    "dict" / DynamicDict(
        'key',
        RepeatUntil(
            lambda item,a,b: item.next_byte == 0x00,
            VariantDictionaryItem
        )
    ),
    Padding(1) * "null padding"
)

# -------------------- Dynamic Header --------------------

# payload encryption method
# https://github.com/keepassxreboot/keepassxc/blob/8324d03f0a015e62b6182843b4478226a5197090/src/format/KeePass2.cpp#L24-L26
CipherId = Mapping(
    GreedyBytes,
    {'aes256': b'1\xc1\xf2\xe6\xbfqCP\xbeX\x05!j\xfcZ\xff',
     'twofish': b'\xadh\xf2\x9fWoK\xb9\xa3j\xd4z\xf9e4l',
     'chacha20': b'\xd6\x03\x8a+\x8boL\xb5\xa5$3\x9a1\xdb\xb5\x9a'
    }
)

# https://github.com/dlech/KeePass2.x/blob/dbb9d60095ef39e6abc95d708fb7d03ce5ae865e/KeePassLib/Serialization/KdbxFile.cs#L234-L246

DynamicHeaderItem = Struct(
    "id" / Mapping(
        Byte,
        {'end': 0,
         'comment': 1,
         'cipher_id': 2,
         'compression_flags': 3,
         'master_seed': 4,
         'encryption_iv': 7,
         'kdf_parameters': 11,
         'public_custom_data': 12
        }
    ),
    "data" / Prefixed(
        Int32ul,
        Switch(
            this.id,
            {'compression_flags': CompressionFlags,
             'kdf_parameters': VariantDictionary,
             'cipher_id': CipherId
            },
            default=GreedyBytes
        )
    )
)

DynamicHeader = DynamicDict(
    'id',
    RepeatUntil(
        lambda item, a, b: item.id == 'end',
        DynamicHeaderItem
    )
)
# -------------------- Payload Verification --------------------

def compute_payload_block_hash(this):
    """Compute hash of each payload block.
    Used to prevent payload corruption and tampering."""

    return hmac.new(
        hashlib.sha512(
            struct.pack('<Q', this._index) +
            hashlib.sha512(
                this._.header.value.dynamic_header.master_seed.data +
                this._.transformed_key + b'\x01'
            ).digest()
        ).digest(),
        struct.pack('<Q', this._index) +
        struct.pack('<I', len(this.block_data)) +
        this.block_data, hashlib.sha256
    ).digest()



# -------------------- Payload Decryption/Decompression --------------------


# encrypted payload is split into multiple data blocks with hashes
EncryptedPayloadBlock = Struct(
    "hmac_hash_offset" / Tell,
    Padding(32),
    "block_data" / Prefixed(Int32ul, GreedyBytes),
    # hmac_hash has to be at the end with a pointer because it needs to
    # come after other fields
    "hmac_hash" / Pointer(
        this.hmac_hash_offset,
        Checksum(
            Bytes(32),
            compute_payload_block_hash,
            this
        )
    )
)

EncryptedPayload = Concatenated(RepeatUntil(
    lambda item, a, b: len(item.block_data) == 0,
    EncryptedPayloadBlock
))

DecryptedPayload = Switch(
    this.header.value.dynamic_header.cipher_id.data,
    {'aes256': AES256Payload(EncryptedPayload),
     'chacha20': ChaCha20Payload(EncryptedPayload),
     'twofish': TwoFishPayload(EncryptedPayload)
    }
)


InnerHeaderItem = Struct(
    "type" / Mapping(
        Byte,
        {'end': 0x00,
         'inner_random_stream_id': 0x01,
         'inner_random_stream_key': 0x02,
         'binary': 0x03
        }
    ),
    "data" / Prefixed(Int32ul, GreedyBytes)
)

# another binary header inside decrypted and decompressed Payload
InnerHeader = DynamicDict(
    'type',
    RepeatUntil(lambda item,a,b: item.type == 'end', InnerHeaderItem)
)

UnpackedPayload = Reparsed(
    Struct(
        "inner_header" / InnerHeader,
        "xml" / GreedyBytes
    )
)

KDBX4 = Struct(
    "header" / RawCopy(
        Struct(
            "magic1" / Bytes(4),
            "magic2" / Bytes(4),
            "minor_version" / Int16ul,
            "major_version" / Int16ul,
            "dynamic_header" / DynamicHeader
        )
    ),
    "transformed_key" / Computed(
        lambda cont: compute_transformed(
            cont,
            compute_key_composite(password=password, keyfile=keyfile)
        )
    ),
    "master_key" / Computed(lambda cont: compute_master(cont)),
    "SHA256 checksum" * Checksum(
        Bytes(32),
        lambda data: hashlib.sha256(data).digest(),
        this.header.data
    ),
    "HMAC-SHA256 checksum" * Checksum(Bytes(32), compute_header_hmac_hash, this),
    "payload" / UnpackedPayload(
        IfThenElse(
            this.header.value.dynamic_header.compression_flags.data.compression,
            Decompressed(DecryptedPayload),
            DecryptedPayload
        )
    )
)

result = KDBX4.parse_stream(s)

KDBX4.parse(KDBX4.build(result))
