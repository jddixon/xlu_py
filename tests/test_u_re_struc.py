#!/usr/bin/env python3
# dev/py/xlattice_py/test_re_struc.py

""" Test restructing of content-keyed store. """

import hashlib
import os
import unittest
# from binascii import hexlify

from rnglib import SimpleRNG
from xlattice import HashTypes, check_hashtype
from xlattice.u import UDir, DirStruc


class TestReStruc(unittest.TestCase):
    """ Test restructing of content-keyed store. """

    def setUp(self):
        self.rng = SimpleRNG()

    def make_values(self, hashtype=False, m__=1, n__=1, l__=1):
        """
        Create at least m and then up to n more values of random length
        up to l (letter L) and compute their SHAx hashes.
        return list of values and a list of their hashes
        """

        check_hashtype(hashtype)

        # DEBUG
        # print("make_values: m__ = %d, n__ = %d, l__ = %d)" % (m__, n__, l__))
        # END
        if m__ <= 0:
            m__ = 1
        if n__ <= 0:
            n__ = 1
        if l__ <= 0:
            l__ = 1

        nnn = m__ + self.rng.next_int16(n__)       # random count of values

        values = []
        hex_hashes = []

        # DEBUG
        # print("VALUES AND HASHES")
        # END
        for _ in range(nnn):
            count = 1 + self.rng.next_int16(l__)   # so that count >= 1
            v__ = self.rng.some_bytes(count)       # that many random bytes
            values.append(v__)
            if hashtype == HashTypes.SHA1:
                sha = hashlib.sha1()
            elif hashtype == HashTypes.SHA2:
                sha = hashlib.sha256()
            elif hashtype == HashTypes.SHA3:
                # pylint: disable=no-member
                sha = hashlib.sha3_256()
            sha.update(v__)
            h__ = sha.hexdigest()
            # DEBUG
            # print("  %02d %s %s" % (_, hexlify(v).decode('utf8'),h__))
            # END
            hex_hashes.append(h__)

        return (values, hex_hashes)

    def do_test_re_struc(self, old_struc, new_struc, hashtype):
        """
        Create a unique test directory u_dir.  We expect this to write
        a characteristic signature into u_dir.
        """
        u_path = os.path.join('tmp', self.rng.next_file_name(8))
        while os.path.exists(u_path):
            u_path = os.path.join('tmp', self.rng.next_file_name(8))

        # DEBUG
        # print("\ncreating %-12s, old_struc=%s, new_struc=%s, hashtype=%s" % (
        #     u_path,
        #     UDir.dir_strucToName(old_struc),
        #     UDir.dir_strucToName(new_struc),
        #     hashtype))
        # END
        u_dir = UDir(u_path, old_struc, hashtype)
        self.assertEqual(hashtype, u_dir.hashtype)
        self.assertEqual(old_struc, u_dir.dir_struc)

        # Verify that the signature datum (SHAx_HEX_NONE) is present
        # in the file system.  How this is stored depends upon old_struc;
        # what value is stored depends upon hashtype.
        old_sig = u_dir.dir_struc_sig(u_path, old_struc, hashtype)
        self.assertTrue(os.path.exists(old_sig))

        values, hex_hashes = self.make_values(hashtype, 32, 32, 128)
        count = len(values)
        for nnn in range(count):
            u_dir.put_data(values[nnn], hex_hashes[nnn])
        # DEBUG
        # print("HASHES:")
        # END
        for nnn in range(count):
            # DEBUG
            # print("  %02d: %s" % (n, hex_hashes[nnn]))
            # END
            self.assertTrue(u_dir.exists(hex_hashes[nnn]))

        # restructure the directory
        u_dir.re_struc(new_struc)

        new_sig = u_dir.dir_struc_sig(u_path, new_struc, hashtype)
        self.assertTrue(os.path.exists(new_sig))
        self.assertFalse(os.path.exists(old_sig))

        for nnn in range(count):
            self.assertTrue(u_dir.exists(hex_hashes[nnn]))

        # XXX STUB: veriy any useless directories have been removed
        # for example: if going from DirStruc.DIR256x256 to DirStruc.DIR_FLAT,
        # directories like 00 and 00/00 should have been removed

    def test_re_struc(self):
        """ Test all combinations of dir structure and hash type. """
        for old_struc in DirStruc:
            for new_struc in DirStruc:
                if old_struc != new_struc:
                    for using in [HashTypes.SHA1, HashTypes.SHA2, ]:
                        self.do_test_re_struc(old_struc, new_struc, using)


if __name__ == '__main__':
    unittest.main()
