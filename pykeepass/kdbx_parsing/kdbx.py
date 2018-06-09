from construct import Struct, Switch, Bytes, Int16ul, RawCopy, this, Embedded
from .kdbx3 import DynamicHeader as DynamicHeader3
from .kdbx3 import Body as Body3
from .kdbx4 import DynamicHeader as DynamicHeader4
from .kdbx4 import Body as Body4
from io import BytesIO

KDBX = Struct(
    "header" / RawCopy(
        Struct(
            "magic1" / Bytes(4),
            "magic2" / Bytes(4),
            "minor_version" / Int16ul,
            "major_version" / Int16ul,
            "dynamic_header" / Switch(
                this.major_version,
                {3: DynamicHeader3,
                 4: DynamicHeader4
                }
            )
        )
    ),
    "body" / Switch(
        this.header.value.major_version,
        {3: Body3,
         4: Body4
        }
    )
)

# password = b'shatpass'

# keyfile = 'test3.key'
# result = KDBX.parse_file('test3.kdbx', password=password, keyfile=keyfile)
# KDBX.parse(
#     KDBX.build(
#         result,
#         password=password,
#         keyfile=keyfile
#     ),
#     password=password,
#     keyfile=keyfile
# )

# keyfile = 'test4.key'
# result = KDBX.parse_file(s, password=password, keyfile=keyfile)

# KDBX.parse(
#     KDBX.build(
#         result,
#         password=password,
#         keyfile=keyfile
#     ),
#     password=password,
#     keyfile=keyfile
# )
