#!/usr/bin/env python3
# xlu/tests/test_u.py

""" Test U and UDir functionality. """

import hashlib
import os
import time
import unittest
# from enum import IntEnum

from xlattice import HashTypes
from xlu import (DirStruc, UDir,
                 file_sha1hex, file_sha2hex, file_sha3hex,
                 file_blake2b_hex)

from rnglib import SimpleRNG

DATA_PATH = 'myData'   # contains files of random data
U_PATH = 'myU1'        # those same files stored by content hash
U_TMP_PATH = 'myU1/tmp'


class TestU(unittest.TestCase):
    """ Test U and UDir functionality. """

    def setUp(self):
        self.rng = SimpleRNG(time.time())
        if not os.path.exists(DATA_PATH):
            os.mkdir(DATA_PATH)
        if not os.path.exists(U_PATH):
            os.mkdir(U_PATH)
        if not os.path.exists(U_TMP_PATH):
            os.mkdir(U_TMP_PATH)

    def tearDown(self):
        # probably should clear DATA_PATH and U_PATH directories
        pass

    def do_discovery_test(self, dir_struc, hashtype):
        """ Verify that discovery of directory structure works. """

        u_path = os.path.join('tmp', self.rng.next_file_name(16))
        while os.path.exists(u_path):
            u_path = os.path.join('tmp', self.rng.next_file_name(16))

        u_dir = UDir(u_path, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, u_path)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        u2_ = UDir.discover(u_path)
        self.assertEqual(u2_.u_path, u_path)
        self.assertEqual(u2_.dir_struc, dir_struc)
        # DEBUG
        if u2_.hashtype != hashtype:
            print("do_discovery_test:")
            print("  dir_struc: %s" % dir_struc.name)
            print("  hashtype: %s" % hashtype)
        # END
        self.assertEqual(u2_.hashtype, hashtype)

    def test_discovery(self):
        """ Verify that discovery of directory structure works. """

        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_discovery_test(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_copy_and_put(self, dir_struc, hashtype):
        """ Check copying a directory structure into a content-keyed store."""

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        for _ in range(1024):
            # create a random file                            maxLen    minLen
            (d_len, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
            if hashtype == HashTypes.SHA1:
                d_key = file_sha1hex(d_path)
            elif hashtype == HashTypes.SHA2:
                d_key = file_sha2hex(d_path)
            elif hashtype == HashTypes.SHA3:
                d_key = file_sha3hex(d_path)
            elif hashtype == HashTypes.BLAKE2B:
                d_key = file_blake2b_hex(d_path)

            # copy this file into U
            (u_len, u_key) = u_dir.copy_and_put(d_path, d_key)
            self.assertEqual(d_len, u_len)
            self.assertEqual(d_key, u_key)

            # verify that original and copy both exist
            self.assertTrue(os.path.exists(d_path))
            u_path = u_dir.get_path_for_key(u_key)
            self.assertTrue(os.path.exists(u_path))

            if hashtype == HashTypes.SHA1:
                u_key_kex = file_sha1hex(u_path)
            elif hashtype == HashTypes.SHA2:
                u_key_kex = file_sha2hex(u_path)
            elif hashtype == HashTypes.SHA3:
                u_key_kex = file_sha3hex(u_path)
            elif hashtype == HashTypes.BLAKE2B:
                u_key_kex = file_blake2b_hex(u_path)
            self.assertEqual(u_key_kex, d_key)

    def test_copy_and_put(self):
        """ Check copying a directory structure into a content-keyed store."""
        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_copy_and_put(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_exists(self, dir_struc, hashtype):
        """we are testing whether = u_dir.exists(u_path, key) """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        (_, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        if hashtype == HashTypes.SHA1:
            d_key = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            d_key = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            d_key = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            d_key = file_blake2b_hex(d_path)
        (_, u_key) = u_dir.copy_and_put(d_path, d_key)
        u_path = u_dir.get_path_for_key(u_key)
        self.assertTrue(os.path.exists(u_path))
        self.assertTrue(u_dir.exists(u_key))
        os.unlink(u_path)
        self.assertFalse(os.path.exists(u_path))
        self.assertFalse(u_dir.exists(u_key))

    def test_exists(self):
        """ Run existence tests over all combinations. """
        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_exists(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_file_len(self, dir_struc, hashtype):
        """we are testing len = u_dir.fileLen(u_path, key) """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        (d_len, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        if hashtype == HashTypes.SHA1:
            d_key = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            d_key = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            d_key = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            d_key = file_blake2b_hex(d_path)
        (u_len, u_key) = u_dir.copy_and_put(d_path, d_key)
        # u_path = u_dir.get_path_for_key(u_key)              # XXX unused
        self.assertEqual(d_len, u_len)
        self.assertEqual(d_len, u_dir.file_len(u_key))

    def test_file_len(self):
        """ Test file_len() for all structures and hash types. """
        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_file_len(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_file_sha(self, dir_struc, hashtype):
        """ we are testing shaXKey = file_shaXHex(path) """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        (d_len, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        with open(d_path, 'rb') as file:
            data = file.read()
        if hashtype == HashTypes.SHA1:
            digest = hashlib.sha1()
        elif hashtype == HashTypes.SHA2:
            digest = hashlib.sha256()
        elif hashtype == HashTypes.SHA3:
            # pylint: disable=no-member
            digest = hashlib.sha3_256()
        elif hashtype == HashTypes.BLAKE2B:
            digest = hashlib.blake2b(digest_size=32)
        digest.update(data)
        d_key = digest.hexdigest()
        if hashtype == HashTypes.SHA1:
            fsha = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            fsha = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            fsha = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            fsha = file_blake2b_hex(d_path)
        self.assertEqual(d_key, fsha)

    def test_file_sha(self):
        """ Verify content keys match file names for combinations. """
        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_file_sha(dir_struc, using)

    # ---------------------------------------------------------------
    def do_test_get_path_for_key(self, dir_struc, hashtype):
        """ we are testing path = get_path_for_key(u_path, key) """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        (d_len, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        if hashtype == HashTypes.SHA1:
            d_key = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            d_key = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            d_key = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            d_key = file_blake2b_hex(d_path)
        (_, u_key) = u_dir.copy_and_put(d_path, d_key)
        self.assertEqual(u_key, d_key)
        u_path = u_dir.get_path_for_key(u_key)

        # XXX implementation-dependent tests
        #
        if dir_struc == DirStruc.DIR_FLAT:
            expected_path = os.path.join(U_PATH, u_key)
        elif dir_struc == DirStruc.DIR16x16:
            expected_path = "%s/%s/%s/%s" % (U_PATH, u_key[0], u_key[1], u_key)
        elif dir_struc == DirStruc.DIR256x256:
            expected_path = "%s/%s/%s/%s" % (U_PATH,
                                             u_key[0:2], u_key[2:4], u_key)
        else:
            self.fail("INTERNAL ERROR: unexpected dir_struc %d" % dir_struc)

        # DEBUG
        if expected_path != u_path:
            print("dir_struc:   %s" % dir_struc.name)
            print("u_path:      %s" % u_path)
            print("expected:    %s" % expected_path)
        # END

        self.assertEqual(expected_path, u_path)

    def test_get_path_for_key(self):
        """ Verify path correct for content for all combinations. """

        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_get_path_for_key(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_put(self, dir_struc, hashtype):
        """we are testing (len,hash)  = put(inFile, u_path, key) """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        (d_len, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        if hashtype == HashTypes.SHA1:
            d_key = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            d_key = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            d_key = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            d_key = file_blake2b_hex(d_path)
        with open(d_path, 'rb') as file:
            data = file.read()
        dupe_path = os.path.join(DATA_PATH, d_key)
        with open(dupe_path, 'wb') as file:
            file.write(data)

        (u_len, u_key) = u_dir.put(d_path, d_key)
        # u_path =
        u_dir.get_path_for_key(u_key)       # unused value

        # inFile is renamed
        self.assertFalse(os.path.exists(d_path))
        self.assertTrue(u_dir.exists(u_key))

        (_, dupe_key) = u_dir.put(dupe_path, d_key)
        # dupe file is deleted'
        self.assertEqual(u_key, dupe_key)
        self.assertFalse(os.path.exists(dupe_path))
        self.assertTrue(u_dir.exists(u_key))

    def test_put(self):
        """ Verify len,hash correct on file puts for all combinations. """

        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_put(dir_struc, using)

    # ---------------------------------------------------------------

    def do_test_put_data(self, dir_struc, hashtype):
        """
        We are testing (len,hash)  = put_data(data, u_path, key)
        """

        u_dir = UDir(U_PATH, dir_struc, hashtype)
        self.assertEqual(u_dir.u_path, U_PATH)
        self.assertEqual(u_dir.dir_struc, dir_struc)
        self.assertEqual(u_dir.hashtype, hashtype)

        # this is just lazy coding ;-)
        (_, d_path) = self.rng.next_data_file(DATA_PATH, 16 * 1024, 1)
        if hashtype == HashTypes.SHA1:
            d_key = file_sha1hex(d_path)
        elif hashtype == HashTypes.SHA2:
            d_key = file_sha2hex(d_path)
        elif hashtype == HashTypes.SHA3:
            d_key = file_sha3hex(d_path)
        elif hashtype == HashTypes.BLAKE2B:
            d_key = file_blake2b_hex(d_path)
        with open(d_path, 'rb') as file:
            data = file.read()

        (_, u_key) = u_dir.put_data(data, d_key)
        self.assertEqual(d_key, u_key)
        self.assertTrue(u_dir.exists(d_key))
        # u_path = u_dir.get_path_for_key(u_key)

    def test_put_data(self):
        """ Verify len,hash correct on data puts for all combinations. """

        for dir_struc in DirStruc:
            for using in [HashTypes.SHA1, HashTypes.SHA2,
                          HashTypes.SHA3, HashTypes.BLAKE2B]:
                self.do_test_put_data(dir_struc, using)


if __name__ == '__main__':
    unittest.main()
