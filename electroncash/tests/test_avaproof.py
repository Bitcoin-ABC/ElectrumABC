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
payout_script_pubkey_hex = (
    "21038439233261789dd340bdc1450172d9c671b72ee8c0b2736ed2a3a250760897fdac"
)
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
    "647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce68048f14d2d4824e6741f5d89"
    "a6a291d22865ce12f3c2ac3d0e1bc103135aea264d259eddf0b58107f672efbbc280dbd4"
    "6ba74f76bccd72f7ac2408732d99b406a6e4ed76e1f19b2c2a0fcc069b4ace4a078cb5cc"
    "31e9e19b266d0af41ea8bb0c30c8b47c95a856d9aa000000007dfdd89a2102449fb5237e"
    "fe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6802f536d62d32d76efe2"
    "1a92665ed64bbafd3b8c882d0fc98fa5b7237b48c597a9d6763dfcb6574fe6123b1a8162"
    "e8611398c552655f90bbc7af3b284df06fadf0ac098c86414715db364a4e32216084c561"
    "acdd79e0860b1fdf7497b159cb13230451200296c902ee000000009f2bc7392102449fb5"
    "237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6802a01496963b4ca"
    "0153743e958dff3a09d0d34bfa68c21fc189afb9f6dec802a88200b7b9a7efe917cc8a0c"
    "d899c25097e900eb3b4d54f1fa3addd55d0f875a4f2321038439233261789dd340bdc145"
    "0172d9c671b72ee8c0b2736ed2a3a250760897fdac"
)
expected_limited_id2 = UInt256.from_hex(
    "7223b8cc572bdf8f123ee7dd0316962f0367b0be8bce9b6e9465d1f413d95616",
)
expected_proofid2 = UInt256.from_hex(
    "95c9673bc14f3c36e9310297e8df81867b42dd1a7bb7944aeb6c1797fbd2a6d5",
)


class TestAvalancheProof(unittest.TestCase):
    def setUp(self) -> None:
        # Print the entire serialized proofs on assertEqual failure
        self.maxDiff = None

    def _test(
        self,
        master_key,
        sequence,
        expiration,
        utxos,
        payout_script_pubkey,
        expected_proof_hex,
        expected_limited_proofid,
        expected_proofid,
    ):
        proofbuilder = ProofBuilder(
            sequence=sequence,
            expiration_time=expiration,
            master=master_key,
            payout_script_pubkey=payout_script_pubkey,
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
            b"",
            "2a00000000000000fff053650000000021030b4c866585dd868a9d62348a9cd008d6a31"
            "2937048fff31670e7e920cfc7a74401b7fc19792583e9cb39843fc5e22a4e3648ab1cb1"
            "8a70290b341ee8d4f550ae24000000001027000000000000788814004104d0de0aaeaef"
            "ad02b8bdc8a01a1b8b11c696bd3d66a2c5f10780d95b7df42645cd85228a6fb29940e85"
            "8e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0a43fc49f4fb5383ea6f91254f7"
            "792a0fd33e10b0ddc6cccd102fc26be67518f111efc0ec49718d330e091735ae39e5479"
            "791f12f5a8c573a817025c82fa5d95ab00",
            # The following proofid and limited id were obtained by passing
            # the previous serialized proof to `bitcoin-cli decodeavalancheproof`
            UInt256.from_hex(
                "e5845c13b93a1c207bd72033c185a2f833eef1748ee62fd49161119ac2c22864",
            ),
            UInt256.from_hex(
                "74c91491e5d6730ea1701817ed6c34e9627904fc3117647cc7d4bce73f56e45a",
            ),
        )

    def test_3_stakes(self):
        self._test(
            master2,
            sequence2,
            expiration2,
            utxos2,
            bytes.fromhex(payout_script_pubkey_hex),
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
            bytes.fromhex(payout_script_pubkey_hex),
            expected_proof2,
            expected_limited_id2,
            expected_proofid2,
        )


if __name__ == "__main__":
    unittest.main()
