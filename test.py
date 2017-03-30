import vcash_hash
from binascii import unhexlify, hexlify

import unittest

# Vcash block #1 - Algo: Whirlpoolx
#
# xcore@debian:~$ xvc -m getblockhash -p 1
# {
#   "result": "0000005944f0d20d7ee82ac4dc65cd8796dd37f6d6e0b3af05af966d6c8b63c0",
#   "id": "159"
# }
# xcore@debian:~$ xvc -m getblock -p 0000005944f0d20d7ee82ac4dc65cd8796dd37f6d6e0b3af05af966d6c8b63c0
# {
#   "result": {
#     "hash": "0000005944f0d20d7ee82ac4dc65cd8796dd37f6d6e0b3af05af966d6c8b63c0",
#     "confirmations": 442356,
#     "size": 287,
#     "height": 1,
#     "version": 4,
#     "merkleroot": "fd737007e5ba3194fcb5bd8268c8f73edf4f28a855bb9b2615699e782c7a2a6c",
#     "mint": 128,
#     "time": 1419310875,
#     "nonce": 8997,
#     "bits": "1e01011c",
#     "difficulty": 0.003889335973108478,
#     "previousblockhash": "15e96604fbcf7cd7e93d072a06f07ccfe1f8fd0099270a075c761c447403a783",
#     "nextblockhash": "0000005ddbd3184936b7177901f481483dfa166724cf8bbe59afaa27ef4bdbcd",
#     "flags": "proof-of-work",
#     "proofhash": "0000005944f0d20d7ee82ac4dc65cd8796dd37f6d6e0b3af05af966d6c8b63c0",
#     "entropybit": 0,
#     "modifier": 0,
#     "modifierchecksum": 1367984010,
#     "tx": [
#       "fd737007e5ba3194fcb5bd8268c8f73edf4f28a855bb9b2615699e782c7a2a6c"
#     ],
#     "signature": "30450220585770ce6bf5b28a91e9976473fdef7b98b0b60af214bd391e436c8da5dd0c07022100b057b09d6c25b9d463ee11f694a9f7962284d902fbf51b801671431839feaaf5"
#   },
#   "id": "244"
# }

whirlpoolx_header_hex = ("04000000" +
 "83a70374441c765c070a279900fdf8e1cf7cf0062a073de9d77ccffb0466e915" +
 "6c2a7a2c789e6915269bbb55a8284fdf3ef7c86882bdb5fc9431bae5077073fd" +
 "1bf79854" +
 "1c01011e" +
 "25230000")

whirlpoolx_best_hash = "c0638b6c6d96af05afb3e0d6f637dd9687cd65dcc42ae87e0dd2f04459000000"

# Vcash block #442480 - Algo: Blake256 - 8rounds
#
# xcore@debian:~$ xvc -m getblockhash -p 442480
# }
#   "result": "00000000000181f6ed1b02f44fdcb3eba413bc63fe1950460d9fa3a10c26ca4e",
#   "id": "9"
# }
# xcore@debian:~$ xvc -m getblock -p 00000000000181f6ed1b02f44fdcb3eba413bc63fe1950460d9fa3a10c26ca4e
# }
#   "result": {
#     "hash": "00000000000181f6ed1b02f44fdcb3eba413bc63fe1950460d9fa3a10c26ca4e",
#     "confirmations": 2,
#     "size": 359,
#     "height": 442480,
#     "version": 5,
#     "merkleroot": "a0172e9d1075ed07cd0a31d463f8ec4b55288e46db5bd9fb6d375adf5e653985",
#     "mint": 9.380375,
#     "time": 1468878545,
#     "nonce": 1663513222,
#     "bits": "1b023924",
#     "difficulty": 29477.70597117364,
#     "previousblockhash": "d2e039eb79927df521f5a824b2642f5da1c61eed03f6bbc2689a7837b8d69538",
#     "nextblockhash": "390c8a7e18b1e46f6e3c8e37c9ac3639cfb67ddcbdb567c7199ca28d667d430b",
#     "flags": "proof-of-work",
#     "proofhash": "00000000000181f6ed1b02f44fdcb3eba413bc63fe1950460d9fa3a10c26ca4e",
#     "entropybit": 0,
#     "modifier": 1642639979002873600,
#     "modifierchecksum": 2252043859,
#     "tx": [
#       "a0172e9d1075ed07cd0a31d463f8ec4b55288e46db5bd9fb6d375adf5e653985"
#     ],
#     "signature": "3045022030466a8399f40a2c55d3f3aadaa15f48c93542dbe4544a80585922839376bbe6022100d65cc91886b43b83bc66eb9553905eb31b9a2a2f4adab50f54f0e4f19d0e1bde"
#   },
#   "id": "216"
# }

blake_header_hex = ("05000000" +
 "3895d6b837789a68c2bbf603ed1ec6a15d2f64b224a8f521f57d9279eb39e0d2" +
 "8539655edf5a376dfbd95bdb468e28554becf863d4310acd07ed75109d2e17a0" +
 "d14e8d57" +
 "2439021b" +
 "86322763")

blake_best_hash = "4eca260ca1a39f0d465019fe63bc13a4ebb3dc4ff4021bedf681010000000000"


class TestSequenceFunctions(unittest.TestCase):

    def setUp(self):
        self.whirlpoolx_block_header = unhexlify(whirlpoolx_header_hex)
        self.whirlpoolx_best_hash = str.encode(whirlpoolx_best_hash)
        self.blake_block_header = unhexlify(blake_header_hex)
        self.blake_best_hash = str.encode(blake_best_hash)

    def test_whirlpoolx_vcash_hash(self):
        self.whirlpoolx_pow_hash = hexlify(vcash_hash.getWhirlpoolxPoWHash(self.whirlpoolx_block_header))
        self.assertEqual(self.whirlpoolx_pow_hash, self.whirlpoolx_best_hash)

    def test_blake_vcash_hash(self):
        self.blake_pow_hash = hexlify(vcash_hash.getBlakePoWHash(self.blake_block_header))
        self.assertEqual(self.blake_pow_hash, self.blake_best_hash)

if __name__ == '__main__':
    unittest.main()

