# xlu_py/src/xlu/__init__.py

import binascii
from enum import IntEnum
import io
import re
import shutil
import sys
import time
import hashlib
import os

try:
    from os import scandir
except ImportError:
    from scandir import scandir

import rnglib
from xlattice import(HashTypes, check_hashtype,
                     SHA1_BIN_NONE, SHA2_BIN_NONE, SHA3_BIN_NONE,
                     SHA1_HEX_NONE, SHA2_HEX_NONE, SHA3_HEX_NONE,
                     SHA1_B64_NONE,
                     SHA1_BIN_LEN, SHA1_HEX_LEN,
                     SHA2_BIN_LEN, SHA2_HEX_LEN,
                     SHA3_BIN_LEN, SHA3_HEX_LEN,
                     BLAKE2B_BIN_LEN, BLAKE2B_HEX_LEN,
                     BLAKE2B_BIN_NONE, BLAKE2B_HEX_NONE)


if sys.version_info < (3, 6):
    import sha3         # monkey-patches hashlib
    assert sha3         # suppress warning

__all__ = ['__version__', '__version_date__',

           # classes
           'UDir', 'ULock',
           'XLUError',

           # functions
           'file_sha1bin', 'file_sha1hex',
           'file_sha2bin', 'file_sha2hex',
           'file_sha3bin', 'file_sha3hex',
           'file_blake2b_bin', 'file_blake2b_hex', ]

__version__ = '1.10.5'
__version_date__ = '2018-02-10'

# == HACKS ==========================================================

# The next line needs to be synchronized
RNG = rnglib.SimpleRNG(time.time())


# - fileSHA1 --------------------------------------------------------

def file_sha1bin(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha1()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return bytes(sha.digest())    # a binary value


def file_sha1hex(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha1()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return sha.hexdigest()    # a string, of course!


def file_sha2bin(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha256()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return bytes(sha.digest())   # a binary value


def file_sha2hex(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha256()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return sha.hexdigest()    # a string, of course!


def file_sha3bin(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha3_256()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return bytes(sha.digest())   # a binary value


def file_sha3hex(path):
    if path is None or not os.path.exists(path):
        return None

    sha = hashlib.sha3_256()
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        sha.update(byte_str)
    reader.close()
    return sha.hexdigest()    # a string, of course!


def file_blake2b_bin(path):
    if path is None or not os.path.exists(path):
        return None

    hash = hashlib.blake2b(digest_size=32)
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        hash.update(byte_str)
    reader.close()
    return bytes(hash.digest())   # a binary value


def file_blake2b_hex(path):
    if path is None or not os.path.exists(path):
        return None

    hash = hashlib.blake2b(digest_size=32)
    file = io.FileIO(path, 'rb')
    reader = io.BufferedReader(file)
    while True:
        byte_str = reader.read(io.DEFAULT_BUFFER_SIZE)
        if len(byte_str) == 0:
            break
        hash.update(byte_str)
    reader.close()
    return hash.hexdigest()    # a string, of course!

# CLASSES ===========================================================


class XLUError(RuntimeError):
    pass


class ULock(object):

    def __init__(self, u_path='/var/U'):
        self._pid = os.getpid()
        abs_path_to_u = os.path.abspath(u_path)
        self._lock_dir = '/tmp/u' + abs_path_to_u
        if not os.path.exists(self.lock_dir):
            os.makedirs(self._lock_dir)
            # KNOWN PROBLEM: we may have created several directories
            # but only the bottom one is 0777
            os.chmod(self.lock_dir, 0o777)
        self._lock_file = "%s/%d" % (self._lock_dir, self._pid)

    @property
    def lock_dir(self):
        return self._lock_dir

    @property
    def lock_file(self):
        return self._lock_file

    @property
    def pid(self):
        return self._pid

    # - get_lock ------------------------------------------
    def get_lock(self, verbose=False):
        """
        Try to get a lock on uPath, returning True if successful, False
        otherwise.
        """
        if os.path.exists(self.lock_file):
            with open(self.lock_file, 'r') as file:
                old_pid = int(file.read())
            if verbose:
                print('%s is already locked by process %d' % (self.lock_dir,
                                                              old_pid))
            return False
        else:
            with open(self.lock_file, 'w') as file:
                file.write(str(self._pid))
            return True

    # - release_lock -------------------------------------
    def release_lock(self):
        if os.path.exists(self.lock_file):
            os.remove(self.lock_file)


class DirStruc(IntEnum):
    DIR_FLAT = 0
    DIR16x16 = 1
    DIR256x256 = 2

    @classmethod
    def valid(cls, val):
        return val in [_.value for _ in cls]


class UDir(object):

    HEX_FILE_NAME_1_PAT = r'^[0-9a-fA-F]{40}$'
    HEX_FILE_NAME_2_PAT = r'^[0-9a-fA-F]{64}$'

    HEX_DIR_NAME_16_PAT = r'^[0-9a-fA-F]{1}$'    # single hex digit
    HEX_DIR_NAME_256_PAT = r'^[0-9a-fA-F]{2}$'   # two hex digits

    HEX_FILE_NAME_1_RE = re.compile(HEX_FILE_NAME_1_PAT)
    HEX_FILE_NAME_2_RE = re.compile(HEX_FILE_NAME_2_PAT)

    HEX_DIR_NAME_16_RE = re.compile(HEX_DIR_NAME_16_PAT)
    HEX_DIR_NAME_256_RE = re.compile(HEX_DIR_NAME_256_PAT)

    def dir_struc_sig(self, u_path, dir_struc, hashtype):
        """ signatures differentiating different types of directories """
        if hashtype == HashTypes.SHA1:
            none = SHA1_HEX_NONE
        elif hashtype == HashTypes.SHA2:
            none = SHA2_HEX_NONE
        elif hashtype == HashTypes.SHA3:
            none = SHA3_HEX_NONE
        elif hashtype == HashTypes.BLAKE2B:
            none = BLAKE2B_HEX_NONE
        else:
            raise NotImplementedError
        if dir_struc == DirStruc.DIR_FLAT:
            sig = os.path.join(u_path, none)
        elif dir_struc == DirStruc.DIR16x16:
            sig = os.path.join(u_path, none[0], none[1], none)
        elif dir_struc == DirStruc.DIR256x256:
            sig = os.path.join(u_path, none[0:2], none[2:4], none)
        else:
            raise XLUError('invalid dir_struc %d' % dir_struc)

        return sig

    def __init__(self, u_path, dir_struc=DirStruc.DIR_FLAT,
                 hashtype=HashTypes.SHA2, mode=0o755):

        self._u_path = u_path
        self._dir_struc = dir_struc
        self._hashtype = hashtype

        os.makedirs(self._u_path, mode=mode, exist_ok=True)

        # simplistic aids to discovery: we write the appropriate kind
        # of hex NONE into the directory.  The value is determined by
        # hashtype.  The level at which it is written is determined
        # by dir_struc.

        if hashtype == HashTypes.SHA1:
            path_to_sig = self.get_path_for_key(SHA1_HEX_NONE)
        elif hashtype == HashTypes.SHA2:
            path_to_sig = self.get_path_for_key(SHA2_HEX_NONE)
        elif hashtype == HashTypes.SHA3:
            path_to_sig = self.get_path_for_key(SHA3_HEX_NONE)
        elif hashtype == HashTypes.BLAKE2B:
            path_to_sig = self.get_path_for_key(BLAKE2B_HEX_NONE)
        else:
            raise XLUError('unexpected HashTypes.SHAx value %d' % hashtype)
        sig_base = os.path.dirname(path_to_sig)
        os.makedirs(sig_base, exist_ok=True)
        open(path_to_sig, 'a').close()                # touch

        self._in_dir = os.path.join(u_path, 'in')
        os.makedirs(self._in_dir, mode=mode, exist_ok=True)
        self._tmp_dir = os.path.join(u_path, 'tmp')
        os.makedirs(self._tmp_dir, mode=mode, exist_ok=True)

    @property
    def dir_struc(self):
        """ Returns DirStruc member. """
        return self._dir_struc

    @property
    def u_path(self):
        return self._u_path

    @property
    def hashtype(self):
        return self._hashtype

    def __eq__(self, other):
        """ Return whether two UDirs are equal. """
        return isinstance(other, UDir) and \
            self._u_path == other.u_path and \
            self._dir_struc == other.dir_struc and \
            self._hashtype == other.hashtype

    @classmethod
    def discover(cls, u_path, dir_struc=DirStruc.DIR_FLAT,
                 hashtype=HashTypes.SHA2, mode=0o755):
        """
        If there is a directory at the expected path, return an
        appropriate tree with the directory structure found.  Otherwise
        create a directory with the characteristics suggested by the
        parameters.

        When a directory tree is created we write NONE into the tree
        as an aid to discovery.  If this is SHA1_HEX_NONE, for example,
        we discover that hashtype is True.  If NONE is in the top
        directory, the directory structure is DIR_FLAT.  If its first
        byte is in the top directory, dir_struc is DIR16x16.  If its
        first two bytes are there, it is DIR256x256.
        """

        check_hashtype(hashtype)
        if os.path.exists(u_path):
            found = False

            # check for flat directory structure --------------------
            if not found:
                flat_sha1_path = os.path.join(u_path, SHA1_HEX_NONE)
                if os.path.exists(flat_sha1_path):
                    found = True
                    dir_struc = DirStruc.DIR_FLAT
                    hashtype = HashTypes.SHA1
            if not found:
                flat_sha2_path = os.path.join(u_path, SHA2_HEX_NONE)
                if os.path.exists(flat_sha2_path):
                    found = True
                    dir_struc = DirStruc.DIR_FLAT
                    hashtype = HashTypes.SHA2
            if not found:
                flat_sha3_path = os.path.join(u_path, SHA3_HEX_NONE)
                if os.path.exists(flat_sha3_path):
                    found = True
                    dir_struc = DirStruc.DIR_FLAT
                    hashtype = HashTypes.SHA3
            if not found:
                flat_blake2b_path = os.path.join(u_path, BLAKE2B_HEX_NONE)
                if os.path.exists(flat_blake2b_path):
                    found = True
                    dir_struc = DirStruc.DIR_FLAT
                    hashtype = HashTypes.BLAKE2B

            # check for 16x16 directory structure -------------------
            if not found:
                dir16_sha1_path = os.path.join(u_path,
                                               SHA1_HEX_NONE[0],
                                               SHA1_HEX_NONE[1],
                                               SHA1_HEX_NONE)
                if os.path.exists(dir16_sha1_path):
                    found = True
                    dir_struc = DirStruc.DIR16x16
                    hashtype = HashTypes.SHA1
            if not found:
                dir16_sha2_path = os.path.join(u_path,
                                               SHA2_HEX_NONE[0],
                                               SHA2_HEX_NONE[1],
                                               SHA2_HEX_NONE)
                if os.path.exists(dir16_sha2_path):
                    found = True
                    dir_struc = DirStruc.DIR16x16
                    hashtype = HashTypes.SHA2
            if not found:
                dir16_sha3_path = os.path.join(u_path,
                                               SHA3_HEX_NONE[0],
                                               SHA3_HEX_NONE[1],
                                               SHA3_HEX_NONE)
                if os.path.exists(dir16_sha3_path):
                    found = True
                    dir_struc = DirStruc.DIR16x16
                    hashtype = HashTypes.SHA3
            if not found:
                dir16_blake2b_path = os.path.join(u_path,
                                                  BLAKE2B_HEX_NONE[0],
                                                  BLAKE2B_HEX_NONE[1],
                                                  BLAKE2B_HEX_NONE)
                if os.path.exists(dir16_blake2b_path):
                    found = True
                    dir_struc = DirStruc.DIR16x16
                    hashtype = HashTypes.BLAKE2B

            # check for 256x256 directory structure -----------------
            if not found:
                dir256_sha1_path = os.path.join(u_path,
                                                SHA1_HEX_NONE[0:2],
                                                SHA1_HEX_NONE[2:4],
                                                SHA1_HEX_NONE)
                if os.path.exists(dir256_sha1_path):
                    found = True
                    dir_struc = DirStruc.DIR256x256
                    hashtype = HashTypes.SHA1
            if not found:
                dir256_sha2_path = os.path.join(u_path,
                                                SHA2_HEX_NONE[0:2],
                                                SHA2_HEX_NONE[2:4],
                                                SHA2_HEX_NONE)
                if os.path.exists(dir256_sha2_path):
                    found = True
                    dir_struc = DirStruc.DIR256x256
                    hashtype = HashTypes.SHA2
            if not found:
                dir256_sha3_path = os.path.join(u_path,
                                                SHA3_HEX_NONE[0:2],
                                                SHA3_HEX_NONE[2:4],
                                                SHA3_HEX_NONE)
                if os.path.exists(dir256_sha3_path):
                    found = True
                    dir_struc = DirStruc.DIR256x256
                    hashtype = HashTypes.SHA3

            if not found:
                dir256_blake2b_path = os.path.join(u_path,
                                                   BLAKE2B_HEX_NONE[0:2],
                                                   BLAKE2B_HEX_NONE[2:4],
                                                   BLAKE2B_HEX_NONE)
                if os.path.exists(dir256_blake2b_path):
                    found = True
                    dir_struc = DirStruc.DIR256x256
                    hashtype = HashTypes.BLAKE2B

        # if uDir does not already exist, this creates it
        obj = cls(u_path, dir_struc, hashtype, mode)
        return obj

    def copy_and_put(self, path, key):
        """
        Make a local copy of the file at path and with the content key
        specified, then move the file into U.  Return the length of the
        file and its actual content key.
        """

        # XXX we do two such stats on this file
        actual_length = os.stat(path).st_size

        # RACE CONDITION
        tmp_file_name = os.path.join(self._tmp_dir, RNG.next_file_name(16))
        while os.path.exists(tmp_file_name):
            tmp_file_name = os.path.join(self._tmp_dir, RNG.next_file_name(16))

        shutil.copyfile(path, tmp_file_name)
        length, hash_ = self.put(tmp_file_name, key)

        # integrity check
        if length != actual_length:
            print("put of %s: actual length %d, returned length %d" % (
                path, actual_length, length))

        # DEBUG - DO NOT REMOVE THIS CASUALLY =======================
        if hash_ != key or path.endswith(
                'uildList') or path.endswith('builds'):
            print('putting %s\n\tkey  %s\n\thash_ %s' % (path, key, hash_))
        # END =======================================================

        return length, hash_

    def delete(self, key):
        """
        If there is a file in the store with the hexadecimal content key
        specified, delete it and return True.  Otherwise return False.

        """
        path = self.get_path_for_key(key)
        if not os.path.exists(path):
            return False
        else:
            os.unlink(path)
            return True

    def get_data(self, key):
        """
        If there is a file in the store with the content key specified,
        return it.  Otherwise return None.

        XXX The file must fit in memory.
        """
        path = self.get_path_for_key(key)
        if not os.path.exists(path):
            return None
        else:
            with open(path, 'rb') as file:
                data = file.read()
            return data

    def put(self, in_file, key):
        """
        inFile is the path to a local file which will be renamed into U (or
        deleted if it is already present in U) key is an sha1 or sha256
        content hash.  If the operation succeeds we return a 2-tuple
        containing the length of the file, which must not be zero, and its
        hash.  Otherwise we return (0, '').
        """

        key_len = len(key)
        err_msg = ''
        if self._hashtype == HashTypes.SHA1 and key_len != SHA1_HEX_LEN:
            err_msg = "UDir.put: expected key length 40, actual %d" % key_len
        elif self._hashtype == HashTypes.SHA2 and key_len != SHA2_HEX_LEN:
            err_msg = "UDir.put: expected key length 64, actual %d" % key_len
        elif self._hashtype == HashTypes.SHA3 and key_len != SHA3_HEX_LEN:
            err_msg = "UDir.put: expected key length 64, actual %d" % key_len
        elif self._hashtype == HashTypes.BLAKE2B and key_len != BLAKE2B_HEX_LEN:
            err_msg = "UDir.put: expected key length 64, actual %d" % key_len
        # XXX BAD USING OR LEN NOT ALLOWED FOR
        if err_msg:
            raise XLUError(err_msg)

        if self._hashtype == HashTypes.SHA1:
            sha = file_sha1hex(in_file)
        elif self._hashtype == HashTypes.SHA2:
            sha = file_sha2hex(in_file)
        elif self._hashtype == HashTypes.SHA3:
            sha = file_sha3hex(in_file)
        elif self._hashtype == HashTypes.BLAKE2B:
            sha = file_blake2b_hex(in_file)
        # XXX BAD USING OR LEN NOT ALLOWED FOR
        length = os.stat(in_file).st_size

        if self.dir_struc == DirStruc.DIR_FLAT:
            fullish_path = os.path.join(self.u_path, key)
        else:
            if self.dir_struc == DirStruc.DIR16x16:
                top_sub_dir = sha[0]
                lower_dir = sha[1]
            elif self.dir_struc == DirStruc.DIR256x256:
                top_sub_dir = sha[0:2]
                lower_dir = sha[2:4]
            else:
                raise XLUError("unknown dir_struc %d" % self.dir_struc)
            target_dir = \
                self.u_path + '/' + top_sub_dir + '/' + lower_dir + '/'
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            fullish_path = target_dir + key

        if os.path.exists(fullish_path):
            os.unlink(in_file)
        else:
            shutil.move(in_file, fullish_path)
            os.chmod(fullish_path, 0o444)

        return (length, sha)

    def put_data(self, data, key):
        if self._hashtype == HashTypes.SHA1:
            sha = hashlib.sha1()
        elif self._hashtype == HashTypes.SHA2:
            sha = hashlib.sha256()
        elif self._hashtype == HashTypes.SHA3:
            sha = hashlib.sha3_256()
        elif self._hashtype == HashTypes.BLAKE2B:
            sha = hashlib.blake2b(digest_size=32)
        else:
            raise NotImplementedError
        sha.update(data)
        sha = sha.hexdigest()
        length = len(data)

        if self.dir_struc == DirStruc.DIR_FLAT:
            fullish_path = os.path.join(self.u_path, key)
        else:
            if self.dir_struc == DirStruc.DIR16x16:
                top_sub_dir = sha[0]
                lower_dir = sha[1]
            elif self.dir_struc == DirStruc.DIR256x256:
                top_sub_dir = sha[0:2]
                lower_dir = sha[2:4]
            else:
                raise XLUError("undefined dir_struc %d" % self.dir_struc)

            target_dir = \
                self.u_path + '/' + top_sub_dir + '/' + lower_dir + '/'
            if not os.path.exists(target_dir):
                os.makedirs(target_dir)
            fullish_path = target_dir + key

        if os.path.exists(fullish_path):
            # print "DEBUG: file is already present"
            pass
        else:
            with open(fullish_path, 'wb') as file:
                file.write(data)

        # XXX UNSATISFACTORY HANDLING OF THE ERROR
        if sha != key:
            err_msg = "put_data:\n\texpected key %s\n\tcontent sha %s" % (
                key, sha)
            print(err_msg)

        return (length, sha)               # GEEP2

    def exists(self, key):
        """ key is hexadecimal content key """

        # CHECK KEY LEN

        path = self.get_path_for_key(key)
        return os.path.exists(path)

    def file_len(self, key):
        """
        returns the length of the file with the given content key
        """

        # CHECK KEY LEN

        path = self.get_path_for_key(key)
        return os.stat(path).st_size

    def get_path_for_key(self, key):
        """
        returns a path to a file with the content key passed, or None if
        there is no such file
        """
        if self.dir_struc == DirStruc.DIR_FLAT:
            return os.path.join(self.u_path, key)

        if self.dir_struc == DirStruc.DIR16x16:
            top_sub_dir = key[0]
            lower_dir = key[1]
        elif self.dir_struc == DirStruc.DIR256x256:
            top_sub_dir = key[0:2]
            lower_dir = key[2:4]
        else:
            raise XLUError("unexpected dir_struc %d" % self.dir_struc)

        return self.u_path + '/' + top_sub_dir + '/' + lower_dir + '/' + key

    def re_struc(self, new_struc):
        """
        Change the structure of uDir to the new dir_struc specified,
        where newStruc is a small non-negative integer.
        """
        old_struc = self.dir_struc
        old_sig = self.dir_struc_sig(
            u_path=self._u_path,
            dir_struc=self._dir_struc,
            hashtype=self._hashtype)
        new_sig = self.dir_struc_sig(self._u_path, new_struc, self._hashtype)

        # fix signature
        if new_sig != old_sig:
            if os.path.exists(old_sig):
                os.unlink(old_sig)
            if not os.path.exists(new_sig):
                sig_base = os.path.dirname(new_sig)
                os.makedirs(sig_base, exist_ok=True)
                open(new_sig, 'a').close()                # touch
        self._dir_struc = new_struc

        self._simple_restruc(old_struc, new_struc)

    def _simple_restruc(self, old_struc, new_struc):
        """
        Scan the directory structure looking for files whose name=content hash
        of the right length for the SHA used (so 40 bytes for SHA1, 64 for
        SHA2/3) but in the wrong directory.  Out-of-place files are moved to
        the correct directory.
        """

        path_to_top = self.u_path
        # DEBUG
        # print("path_to_top: %s" % path_to_top)
        # END
        if old_struc == DirStruc.DIR_FLAT:
            for entry in scandir(path_to_top):
                if entry.is_dir():
                    continue
                key = entry.name
                if self._hashtype == HashTypes.SHA1:
                    match = self.HEX_FILE_NAME_1_RE.match(key)
                elif self._hashtype == HashTypes.SHA2 or \
                        self._hashtype == HashTypes.SHA3 or \
                        self._hashtype == HashTypes.BLAKE2B:
                    match = self.HEX_FILE_NAME_2_RE.match(key)
                if match:
                    # DEBUG
                    # print("match: %s" % key)
                    # END
                    # path_to_file = os.path.join(path_to_top, key)
                    self.put(entry.path, key)

        else:
            # old_struc == DirStruc.DIR16x16 or DirStruc.DIR256x256
            if old_struc == DirStruc.DIR16x16:
                dir_re = self.HEX_DIR_NAME_16_RE
            else:
                dir_re = self.HEX_DIR_NAME_256_RE
            for entry in scandir(path_to_top):
                if entry.is_file():
                    continue
                mid_dir = entry.name
                mid_occupied = False
                match = dir_re.match(mid_dir)
                if match:
                    path_to_mid = entry.path
                    # DEBUG
                    # print("path_to_mid: %s" % path_to_mid)
                    # END
                    # for bot_dir in os.listdir(path_to_mid):
                    for entry in scandir(path_to_mid):
                        if entry.is_file():
                            continue
                        bot_dir = entry.name
                        bot_occupied = False
                        match = dir_re.match(bot_dir)
                        if match:
                            path_to_bot = entry.path
                            # DEBUG
                            # print("path_to_bot: %s" % path_to_bot)
                            # END
                            for entry in scandir(path_to_bot):
                                if entry.is_dir():
                                    continue
                                key = entry.name
                                if self._hashtype == HashTypes.SHA1:
                                    match = self.HEX_FILE_NAME_1_RE.match(key)
                                elif self._hashtype == HashTypes.SHA2 or \
                                        self._hashtype == HashTypes.SHA3 or \
                                        self._hashtype == HashTypes.BLAKE2B:
                                    match = self.HEX_FILE_NAME_2_RE.match(key)
                                if match:
                                    # DEBUG
                                    # print("match at bottom: %s" % key)
                                    # END
                                    self.put(entry.path, key)
                                else:
                                    bot_occupied = True
                        if not bot_occupied:
                            os.rmdir(path_to_bot)
                    if not mid_occupied:
                        os.rmdir(path_to_mid)

        # remove old directories
