libkeepass
----------

Low level library for parsing Keepass KDBX3 and KDBX4 files.

.. code:: python

    from libkeepass import KDBX
    result = KDBX.parse_file('test3.kdbx', password='password', keyfile='test3.key')
    print(result)
    # Container: 
    #     header = Container: 
    #         data = b'\x03\xd9\xa2\x9ag\xfbK\xb5\x01\x00\x03\x00\x02\x10\x001'... (truncated, total 222)
    #         value = Container: 
    #             magic1 = b'\x03\xd9\xa2\x9a' (total 4)
    #             magic2 = b'g\xfbK\xb5' (total 4)
    #             minor_version = 1
    #             major_version = 3
    #             dynamic_header = Container: 
    #                 cipher_id = Container: 
    #                     id = u'cipher_id' (total 9)
    #                     data = u'aes256' (total 6)
    #                 compression_flags = Container: 
    #                     id = u'compression_flags' (total 17)
    #                     data = Container: 
    #                         compression = True
    #                 master_seed = Container: 
    #                     id = u'master_seed' (total 11)
    #                     data = b"\xa8\x82o6\xa8P\xef\x90\x9d\x01Qj#\xe9'\x81"... (truncated, total 32)
    #                 transform_seed = Container: 
    #                     id = u'transform_seed' (total 14)
    #                     data = b'\x1cc\x8dN\x8e9\xaa\x13\x9aE\xc9\xab\x12\x18\xa2\x1d'... (truncated, total 32)
    #                 transform_rounds = Container: 
    #                     id = u'transform_rounds' (total 16)
    #                     data = 100000
    #                 encryption_iv = Container: 
    #                     id = u'encryption_iv' (total 13)
    #                     data = b'\x17O\x19\x13=Q\x94P3.\x0c\xe3q\xf8\x1b\x94' (total 16)
    #                 protected_stream_key = Container: 
    #                     id = u'protected_stream_key' (total 20)
    #                     data = b'\x15(\xb5\x14sj\xf7p\x925\xc5\x85\xc6L7\xc5'... (truncated, total 32)
    #                 stream_start_bytes = Container: 
    #                     id = u'stream_start_bytes' (total 18)
    #                     data = b'\x95\xd0\x1f\xac\xaf\xe9 \x0e\x81\xce \xae`\x8e\xc1<'... (truncated, total 32)
    #                 inner_random_stream_id = Container: 
    #                     id = u'inner_random_stream_id' (total 22)
    #                     data = b'\x02\x00\x00\x00' (total 4)
    #                 end = Container: 
    #                     id = u'end' (total 3)
    #                     data = b'\r\n\r\n' (total 4)
    #         offset1 = 0
    #         offset2 = 222
    #         length = 222
    #     body = Container: 
    #         transformed_key = b'-\xe9\x14/\xf1\x1f\x9d\xc7\x06G\xa83\x9a\xf7\x8c\xd4'... (truncated, total 32)
    #         master_key = b"\tH\xfe'\xd12\x19\xc1\x81\xa2\xbf\r\xb3\x7f\xee/"... (truncated, total 32)
    #         payload = Container: 
    #             xml = <lxml.etree._ElementTree object at 0x7fc0bc13bc08>
