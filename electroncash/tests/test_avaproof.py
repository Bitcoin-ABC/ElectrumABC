import unittest

from ..avaproof import Key, ProofBuilder
from ..bitcoin import deserialize_privkey
from ..uint256 import UInt256

privkey_wif = "Kwr371tjA9u2rFSMZjTNun2PXXP3WPZu2afRHTcta6KxEUdm1vEw"
_, privkey, compressed = deserialize_privkey(privkey_wif)
master = Key(privkey, compressed)
# prove that this is the same key as before
pubkey_hex = "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744"
assert master.get_pubkey().keydata.hex() == pubkey_hex
utxos = [
    {
        "txid": UInt256.from_hex(
            "24ae50f5d4e81e340b29708ab11cab48364e2ae2c53f8439cbe983257919fcb7",
        ),
        "vout": 0,
        "amount": 0.0001,
        "height": 672828,
        "privatekey": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ",
        "iscoinbase": False,
    },
]

# data from Bitcoin ABC's proof_tests.cpp
sequence2 = 5502932407561118921
expiration2 = 5658701220890886376
master_wif2 = "L4J6gEE4wL9ji2EQbzS5dPMTTsw8LRvcMst1Utij4e3X5ccUSdqW"
_, privkey, compressed = deserialize_privkey(master_wif2)
master2 = Key(privkey, compressed)
# master_pub2 = "023beefdde700a6bc02036335b4df141c8bc67bb05a971f5ac2745fd683797dde3"
utxos2 = [
    {
        "txid": UInt256.from_hex(
            "37424bda9a405b59e7d4f61a4c154cea5ee34e445f3daa6033b64c70355f1e0b"
        ),
        "vout": 2322162807,
        "amount": 32.91110545,
        "height": 426611719,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
    {
        "txid": UInt256.from_hex(
            "300cbba81ef40a6d269be1e931ccb58c074ace4a9b06cc0f2a2c9bf1e176ede4"
        ),
        "vout": 2507977928,
        "amount": 28.66370216,
        "height": 1298955966,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
    {
        "txid": UInt256.from_hex(
            "2313cb59b19774df1f0b86e079ddac61c5846021324e4a36db154741868c09ac"
        ),
        "vout": 35672324,
        "amount": 39.93160086,
        "height": 484677071,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
]
expected_proof2 = (
    "c964aa6fde575e4ce8404581c7be874e21023beefdde700a6bc02036335b4df141c8bc67"
    "bb05a971f5ac2745fd683797dde3030b1e5f35704cb63360aa3d5f444ee35eea4c154c1a"
    "f6d4e7595b409ada4b42377764698a915c2ac4000000000f28db322102449fb5237efe8f"
    "647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce68051427f8d544dd19f94420f"
    "c2ffd0e7e63897f5ad4a7b6fee1fdda590da4c1f04bb3117ebaa8b1440376751f63c0d21"
    "6efabeae800c6a120fdaff853c99a2aeade4ed76e1f19b2c2a0fcc069b4ace4a078cb5cc"
    "31e9e19b266d0af41ea8bb0c30c8b47c95a856d9aa000000007dfdd89a2102449fb5237e"
    "fe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6802113ed79acb8f947d9"
    "b795ac2123bba19a48f167cbd7a7686f1beb956dd78e9c6a2fdd4111cd2091fa8008ecb5"
    "e56dd814c0cf15a9f09bddc81d4a5baac912bfac098c86414715db364a4e32216084c561"
    "acdd79e0860b1fdf7497b159cb13230451200296c902ee000000009f2bc7392102449fb5"
    "237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6807011a7918d8d5d"
    "719f9e5b5ec8f6d312d62069f7e53488d363716cacc13c45f8aa6023a2a014a48bff25f0"
    "d165e18d10181303777b1528d88b43eb5a53b52342"
)
expected_limited_id2 = UInt256.from_hex(
    "add6745f25ee94be52d0bc0e7d059fc5fa0234b0f10025909573983cae7e1038",
)
expected_proofid2 = UInt256.from_hex(
    "6e58a564c82b26633991fa9225dc781ff5b731455e436a21303c09149f465ea1",
)


class TestAvalancheProof(unittest.TestCase):
    def _test(
        self,
        master_key,
        sequence,
        expiration,
        utxos,
        expected_proof_hex,
        expected_limited_proofid,
        expected_proofid,
    ):
        proofbuilder = ProofBuilder(
            sequence=sequence,
            expiration_time=expiration,
            master=master_key,
        )
        for utxo in utxos:
            proofbuilder.add_utxo(
                txid=utxo["txid"],
                vout=utxo["vout"],
                value=utxo["amount"],
                height=utxo["height"],
                wif_privkey=utxo["privatekey"],
                is_coinbase=utxo["iscoinbase"],
            )
        proof = proofbuilder.build()
        self.assertEqual(proof.serialize().hex(), expected_proof_hex)

        self.assertEqual(proof.limitedid, expected_limited_proofid)
        self.assertEqual(proof.proofid, expected_proofid)

    def test_1_stake(self):
        self._test(
            master,
            42,
            1699999999,
            utxos,
            "2a00000000000000fff053650000000021030b4c866585dd868a9d62348a9cd008d6a31"
            "2937048fff31670e7e920cfc7a74401b7fc19792583e9cb39843fc5e22a4e3648ab1cb1"
            "8a70290b341ee8d4f550ae24000000001027000000000000788814004104d0de0aaeaef"
            "ad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e85"
            "8e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a28f28f73b40ba29c2d65c5e26"
            "5d86667c8f9c9c097684a95d672cbae2e1e3e538bf3bf23d97911baca379efbd55f7eeb"
            "1110b7b69a62a3e770a5a0a8ead73727",
            # The following proofid and limited id were obtained by passing
            # the previous serialized proof to `bitcoin-cli decodeavalancheproof`
            UInt256.from_hex(
                "9857a02ac4499b7d0ba81be3318a01a9a2230c22187b24d0038f30fc33bb9961",
            ),
            UInt256.from_hex(
                "cb33d7fac9092089f0d473c13befa012e6ee4d19abf9a42248f731d5e59e74a2",
            ),
        )

    def test_3_stakes(self):
        self._test(
            master2,
            sequence2,
            expiration2,
            utxos2,
            expected_proof2,
            expected_limited_id2,
            expected_proofid2,
        )
        # Change the order of UTXOS to test that the stakes have a unique order inside
        # a proof.
        self._test(
            master2,
            sequence2,
            expiration2,
            utxos2[::-1],
            expected_proof2,
            expected_limited_id2,
            expected_proofid2,
        )


if __name__ == "__main__":
    unittest.main()
