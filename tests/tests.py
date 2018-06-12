import unittest
from libkeepass import KDBX

class FileTests(unittest.TestCase):

    def test_open_save(self):
        """try to open all databases, save them, then open the result"""

        databases = [
            'test3.kdbx', 'test4.kdbx',
            # also test original libkeepass databases
            'sample1.kdbx', 'sample2.kdbx', 'sample3.kdbx', 'sample4.kdbx'

        ]
        passwords = [
            'password', 'password',
            'asdf', 'asdf', 'qwer', 'qwer'
        ]
        keyfiles = [
            'test3.key', 'test4.key',
            None, 'sample2_keyfile.key', 'sample3_keyfile.exe', 'sample3_keyfile.exe'
        ]

        for database, password, keyfile in zip(databases, passwords, keyfiles):
            print(database, password, keyfile)
            KDBX.parse(
                KDBX.build(
                    KDBX.parse_file(
                        database,
                        password=password,
                        keyfile=keyfile
                    ),
                    password=password,
                    keyfile=keyfile
                ),
                password=password,
                keyfile=keyfile
            )


if __name__ == '__main__':
    unittest.main()
