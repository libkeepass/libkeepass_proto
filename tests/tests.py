import unittest
from libkeepass import KDBX

class FileTests(unittest.TestCase):

    # open database
    def setUp(self):
        self.password='password'
        self.keyfile3 = 'test3.key'
        self.keyfile4 = 'test4.key'

        self.kdbx3 = KDBX.parse_file(
            'test3.kdbx',
            password='password',
            keyfile=self.keyfile3
        )
        self.kdbx4 = KDBX.parse_file(
            'test4.kdbx',
            password='password',
            keyfile=self.keyfile4
        )

    # test that saved databases can be parsed again
    def test_save(self):
        KDBX.parse(
            KDBX.build(
                self.kdbx3,
                password=self.password,
                keyfile=self.keyfile3
            ),
            password=self.password,
            keyfile=self.keyfile3
        )
        KDBX.parse(
            KDBX.build(
                self.kdbx4,
                password=self.password,
                keyfile=self.keyfile4
            ),
            password=self.password,
            keyfile=self.keyfile4
        )

if __name__ == '__main__':
    unittest.main()
