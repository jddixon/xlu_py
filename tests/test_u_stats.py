#!/usr/bin/env python3
# dev/py/xlu_py/tests/test_u_stats.py

""" Exercise statistical functions for content-keyed store. """

import sys
import unittest
from rnglib import SimpleRNG
from xlattice import HashTypes
from xlu.stats import UStats
from xlu import DirStruc


class TestUStats(unittest.TestCase):
    """ Exercise statistical functions for content-keyed store. """

    def setUp(self):
        self.rng = SimpleRNG()

    def test_defaults(self):
        """ Verify that defaults are as expected. """

        results = UStats()

        self.assertEqual(results.dir_struc, DirStruc.DIR_FLAT)
        self.assertEqual(results.hashtype, HashTypes.SHA2)

        self.assertEqual(results.subdir_count, 0)
        self.assertEqual(results.sub_subdir_count, 0)
        self.assertEqual(results.leaf_count, 0)
        self.assertEqual(results.odd_count, 0)
        self.assertEqual(results.has_l, False)
        self.assertEqual(results.has_node_id, False)
        self.assertEqual(results.min_leaf_bytes, sys.maxsize)
        self.assertEqual(results.max_leaf_bytes, 0)

        self.assertEqual(len(results.unexpected_at_top), 0)

#   def test_properties(self):
#       """ Verify that a UStats instance has expected properties. """
#       results = UStats()

#       # XXX STUB XXX
#       # _ = results

# subDirCount
# subSubDirCount
# leafCount
# oddCount
# hasL
# hasNodeID
# minLeafBytes
# maxLeafBytes


if __name__ == '__main__':
    unittest.main()
