#!/usr/bin/python3

# ~/dev/py/xlattice_py/xlattice/stats.py

import re
import sys
import os
try:
    from os import scandir
except ImportError:
    from scandir import scandir

from xlattice import check_hashtype, HashTypes
from xlattice.u import DirStruc, UDir

HEX2_PAT = '^[0-9a-fA-F][0-9a-fA-F]$'
HEX2_RE = re.compile(HEX2_PAT)

SHA1_PAT = '^[0-9a-fA-F]{40}$'
SHA1_RE = re.compile(SHA1_PAT)


class UStats:
    """ Statistics for a content-keyed directory organized as a UDir. """

    def __init__(self):
        self._dir_struc = DirStruc.DIR_FLAT
        self._hashtype = HashTypes.SHA2

        self._subdir_count = 0
        self._sub_subdir_count = 0
        self._leaf_count = 0
        self._odd_count = 0
        self._has_l = False
        self._has_node_id = False
        self._min_leaf_bytes = sys.maxsize
        self._max_leaf_bytes = 0

        self._unexpected_at_top = []
        self._biggest_leaf_count = -1
        self._path_to_biggest_leaf_count = ''

    @property
    def dir_struc(self):
        """ Return the directory structure as a DirStruc. """
        return self._dir_struc   # an int

    @dir_struc.setter
    def dir_struc(self, value):
        # XXX NEED SOME CHECKS
        self._dir_struc = value

    @property
    def hashtype(self):
        """ Return the type of hash used to calculate content keys. """
        return self._hashtype

    @hashtype.setter
    def hashtype(self, value):
        check_hashtype(value)          # exits if bad !
        self._hashtype = value

    @property
    def subdir_count(self):
        """ Return the subdirectory count. """
        return self._subdir_count

    @property
    def sub_subdir_count(self):
        """ Return the sub-subdirectory count. """
        return self._sub_subdir_count

    @sub_subdir_count.setter
    def sub_subdir_count(self, value):
        # validate
        self._sub_subdir_count = value

    @property
    def leaf_count(self):
        return self._leaf_count

    @leaf_count.setter
    def leaf_count(self, value):
        # validate
        self._leaf_count = value

    @property
    def odd_count(self):
        """ Return the count of odd files. """
        return self._odd_count

    @odd_count.setter
    def odd_count(self, value):
        # validate
        self._odd_count = value

    @property
    def has_l(self):
        """ Return whether there is an L file in the root directory. """
        return self._has_l

    @has_l.setter
    def has_l(self, b_value):
        # validate
        self._has_l = b_value

    @property
    def has_node_id(self):
        """ Return whether there is a nodeID file in the root directsory. """
        return self._has_node_id

    @has_node_id.setter
    def has_node_id(self, b_value):
        # validate
        self._has_node_id = b_value

    @property
    def min_leaf_bytes(self):
        """ Return the number of bytes in the smallest leaf node. """
        return self._min_leaf_bytes

    @min_leaf_bytes.setter
    def min_leaf_bytes(self, value):
        # validate
        self._min_leaf_bytes = value

    @property
    def max_leaf_bytes(self):
        """ Return the number of bytes in the largest leaf node. """
        return self._max_leaf_bytes

    @max_leaf_bytes.setter
    def max_leaf_bytes(self, value):
        # validate
        self._max_leaf_bytes = value

    @property
    def unexpected_at_top(self):
        """ Return the number of unexpected files in the top directory. """
        return self._unexpected_at_top

    @unexpected_at_top.setter
    def unexpected_at_top(self, value):
        # validate
        self._unexpected_at_top = value

    @property
    def biggest_leaf_count(self):
        return self._biggest_leaf_count

    @biggest_leaf_count.setter
    def biggest_leaf_count(self, value):
        # validate
        self._biggest_leaf_count = value

    @property
    def path_to_biggest_leaf_count(self):
        return self._path_to_biggest_leaf_count

    @path_to_biggest_leaf_count.setter
    def path_to_biggest_leaf_count(self, value):
        # validate
        self._path_to_biggest_leaf_count = value


def scan_leaf_dir(path_to_dir, obj):
    """ Collect stats from leaf directory. """

    # DEBUG
    # # print("    scanning leaf directory %s" % pathToDir)
    # END
    file_count = 0
    odd_count = 0

    for entry in scandir(path_to_dir):
        # DEBUG
        # print("      leaf file: %s" % entry.name)
        # END
        if entry.is_symlink():
            # DEBUG
            # print("          SYM LINK")
            # eND
            continue
        name = entry.name
        match = SHA1_RE.match(name)
        if match:
            # DEBUG
            # print("      MATCH")
            # END
            file_count = file_count + 1
            size = entry.stat().st_size
            # DEBUG
            # print("      SIZE = %9d" % size)
            # END
            if size < obj.min_leaf_bytes:
                obj.minLeafBytes = size
            if size > obj.max_leaf_bytes:
                obj.max_leaf_bytes = size
        else:
            odd_count = odd_count + 1

    if file_count > obj.biggest_leaf_count:
        obj.biggest_leaf_count = file_count
        obj.path_to_biggest_leaf_count = path_to_dir

    obj.leaf_count += file_count
    obj.odd_count += odd_count


def collect_stats(u_path, out_path, verbose):
    """
    Drop-in replacement for collect_stats(), using scandir instead of listdir.
    """

    stats = UStats()        # we will return this

    # XXX outPath IS NOT USED
    if out_path:
        os.makedirs(out_path, exist_ok=True)
    # _ = verbose
    # END NOT USED

    u_dir = UDir.discover(u_path)
    stats.hashtype = u_dir.hashtype
    stats.dir_struc = u_dir.dir_struc

    # upper-level files / subdirectories
    for top_entry in scandir(u_path):
        top_file = top_entry.name

        # -- upper-level files ----------------------------------------

        # At this level we expect 00-ff, tmp/ and in/ subdirectories
        # plus the files L and possibly nodeID.

        match = HEX2_RE.match(top_file)
        if match:

            # -- upper-level directories ------------------------------

            stats._subdir_count += 1
            path_to_subdir = os.path.join(u_path, top_file)
            # DEBUG
            # print("SUBDIR: %s" % path_to_subdir)
            # END
            for mid_entry in scandir(path_to_subdir):
                mid_file = mid_entry.name
                match2 = HEX2_RE.match(mid_file)
                if match2:

                    stats._sub_subdir_count += 1
                    path_to_sub_subdir = os.path.join(
                        path_to_subdir, mid_file)
                    scan_leaf_dir(path_to_sub_subdir, stats)

                # -- other upper-level files ------------------------
                else:
                    path_to_oddity = os.path.join(path_to_subdir, mid_file)
                    print("unexpected: %s" % path_to_oddity)
                    stats.odd_count += 1

        # -- other upper-level files --------------------------------

        else:
            if top_file == 'L':
                stats.has_l = True
            elif top_file == 'nodeID':
                stats.has_node_id = True
            elif top_file in ['in', 'tmp']:
                # DEBUG
                # print("TOP LEVEL OTHER DIR: %s" % topFile)
                path_to_dir = os.path.join(u_path, top_file)
                scan_leaf_dir(path_to_dir, stats)
            else:
                path_to_oddity = os.path.join(u_path, top_file)
                stats.unexpected_at_top.append(path_to_oddity)
                stats.odd_count += 1

    return stats
