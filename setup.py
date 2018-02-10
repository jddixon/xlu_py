#!/usr/bin/python3
# xlu_py/setup.py

""" Setuptools project configuration for xlu_py. """

from os.path import exists
from setuptools import setup, Extension

# see http://docs.python.org/distutils/setupscript.html

LONG_DESC = None
if exists('README.md'):
    with open('README.md', 'r') as file:
        LONG_DESC = file.read()

setup(name='xlu_py',
      version='1.10.5',
      author='Jim Dixon',
      author_email='jddixon@gmail.com',
      long_description=LONG_DESC,
      packages=['xlu'],
      package_dir={'': 'src'},
      py_modules=[],
      include_package_data=False,
      zip_safe=False,
      scripts=['src/gen_node_id', 'src/u_consolidate', 'src/u_preen',
               'src/u_re_struc', 'src/u_stats', 'src/verify_content_keys'],
      ext_modules=[],
      description='xlattice content-keyed directory structure',
      url='https://jddixon.github.io/xlu_py',
      classifiers=[
          'Development Status :: 3 - Alpha',
          'Intended Audience :: Developers',
          'License :: OSI Approved :: MIT License',
          'Natural Language :: English',
          'Programming Language :: Python 2.7',
          'Programming Language :: Python 3.3',
          'Programming Language :: Python 3.4',
          'Programming Language :: Python 3.5',
          'Programming Language :: Python 3.6',
          'Programming Language :: Python 3.7',
          'Topic :: Software Development :: Libraries :: Python Modules',
      ],)
