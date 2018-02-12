#!/usr/bin/env python3
# dev/py/xlu_py/tests/testULock.py

"""
Test locking on content-keyed store.

We are testing three functions:
    lock = xlu.ULock(pathToU)
    lock.get_lock()
    lock.release_lock()
"""

import os
import unittest

import xlu

U_PATH = 'myU1'


class TestULock(unittest.TestCase):
    """ Test locking on content-keyed store. """

    def setUp(self):
        if not os.path.exists(U_PATH):
            os.mkdir(U_PATH)
        lock = xlu.ULock(U_PATH)
        if os.path.exists(lock.lock_file):
            os.remove(lock.lock_file)

    def tearDown(self):
        pass

    def test_constructor(self):
        """ we are testing lock = xlu.ULock(pathToU) """

        lock = xlu.ULock(U_PATH)
        self.assertTrue(lock is not None)
        lock_dir = lock.lock_dir
        lock_file = lock.lock_file
        pid = lock.pid
        self.assertTrue(os.path.exists(lock_dir))
        self.assertFalse(os.path.exists(lock_file))
        self.assertEqual(pid, os.getpid())

    def test_get_lock(self):
        """ we are testing lock.get_lock() """

        lock = xlu.ULock(U_PATH)
        success = lock.get_lock()
        self.assertTrue(success)
        lock_file = lock.lock_file
        pid = lock.pid
        self.assertTrue(os.path.exists(lock_file))
        with open(lock_file, 'r') as file:
            lock_data = file.read()
        self.assertEqual(lock_data, str(pid))

        # test that attempt to get second lock fails
        lock2 = xlu.ULock(U_PATH)
        self.assertFalse(lock2.get_lock())
        lock2.release_lock()

        lock.release_lock()

    def test_release_lock(self):
        """ we are testing lock.release_lock() """
        lock = xlu.ULock(U_PATH)
        self.assertTrue(lock.get_lock(True))
        lock_file = lock.lock_file
        lock.release_lock()
        # XXX relies on implementation knowledge
        self.assertFalse(os.path.exists(lock_file))

        lock2 = xlu.ULock(U_PATH)
        self.assertTrue(lock2.get_lock())
        lock2.release_lock()


if __name__ == '__main__':
    unittest.main()
