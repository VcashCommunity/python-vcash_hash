from distutils.core import setup, Extension

vcash_hash_module = Extension('vcash_hash',
                                 sources = ['vcashmodule.c',
                                            'vcashhash.c',
                                            'sha3/blake.c',
                                            'sha3/whirlpool.c'],
                                 include_dirs=['.', './sha3'])

setup (name = 'vcash_hash',
       version = '1.0',
       description = 'Binding for Vcash proof of work hashing.',
       ext_modules = [vcash_hash_module])
