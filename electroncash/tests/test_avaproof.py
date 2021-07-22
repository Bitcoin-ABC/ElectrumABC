
import unittest
from ..avaproof import ProofBuilder


class TestAvalancheProof(unittest.TestCase):
    def _test(self, pubkey_hex, sequence, expiration, utxos, expected_proof_hex,
              expected_limited_proofid, expected_proofid):
        proofbuilder = ProofBuilder(sequence=sequence,
                                    expiration_time=expiration,
                                    master=pubkey_hex)
        for utxo in utxos:
            proofbuilder.add_utxo(
                txid=utxo['txid'],
                vout=utxo['vout'],
                value=utxo['amount'],
                height=utxo['height'],
                wif_privkey=utxo['privatekey'])
        proof = proofbuilder.build()
        self.assertEqual(proof.serialize().hex(), expected_proof_hex)

        # We need to reverse the bytestring before converting a proofid to hex,
        # because of the way the node software serializes uint256.
        self.assertEqual(proof.limitedid[::-1].hex(),
                         expected_limited_proofid)
        self.assertEqual(proof.proofid[::-1].hex(),
                         expected_proofid)

    def test_single_stake(self):
        self._test(
            "030b4c866585dd868a9d62348a9cd008d6a312937048fff31670e7e920cfc7a744",
            42,
            1699999999,
            [{
                "txid": "24ae50f5d4e81e340b29708ab11cab48364e2ae2c53f8439cbe983257919fcb7",
                "vout": 0,
                "amount": 0.0001,
                "height": 672828,
                "privatekey": "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
            }],
            "2a00000000000000fff053650000000021030b4c866585dd868a9d62348a9cd008d6a31"
            "2937048fff31670e7e920cfc7a74401b7fc19792583e9cb39843fc5e22a4e3648ab1cb1"
            "8a70290b341ee8d4f550ae24000000001027000000000000788814004104d0de0aaeaef"
            "ad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e85"
            "8e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a28f28f73b40ba29c2d65c5e26"
            "5d86667c8f9c9c097684a95d672cbae2e1e3e538bf3bf23d97911baca379efbd55f7eeb"
            "1110b7b69a62a3e770a5a0a8ead73727",
            "9857a02ac4499b7d0ba81be3318a01a9a2230c22187b24d0038f30fc33bb9961",
            "cb33d7fac9092089f0d473c13befa012e6ee4d19abf9a42248f731d5e59e74a2"
        )


if __name__ == '__main__':
    unittest.main()
