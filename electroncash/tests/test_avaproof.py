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
        "amount": 10000,
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
        "amount": 3291110545,
        "height": 426611719,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
    {
        "txid": UInt256.from_hex(
            "300cbba81ef40a6d269be1e931ccb58c074ace4a9b06cc0f2a2c9bf1e176ede4"
        ),
        "vout": 2507977928,
        "amount": 2866370216,
        "height": 1298955966,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
    {
        "txid": UInt256.from_hex(
            "2313cb59b19774df1f0b86e079ddac61c5846021324e4a36db154741868c09ac"
        ),
        "vout": 35672324,
        "amount": 3993160086,
        "height": 484677071,
        "iscoinbase": True,
        "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
    },
]
expected_proof2 = (
    "c964aa6fde575e4ce8404581c7be874e21023beefdde700a6bc02036335b4df141c8bc67"
    "bb05a971f5ac2745fd683797dde3030b1e5f35704cb63360aa3d5f444ee35eea4c154c1a"
    "f6d4e7595b409ada4b42377764698a915c2ac4000000000f28db322102449fb5237efe8f"
    "647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce680da44b13031186044cd54f0"
    "084dcbe703bdb74058a1ddd3efffb347c04d45ced339a41eecedad05f8380a4115016404"
    "a2787f51e27165171976d1925944df0231e4ed76e1f19b2c2a0fcc069b4ace4a078cb5cc"
    "31e9e19b266d0af41ea8bb0c30c8b47c95a856d9aa000000007dfdd89a2102449fb5237e"
    "fe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce68019201c99059772f645"
    "2efb50579edc11370a94ea0b7fc61f22cbacc1339a22a04a41b20066c617138d715d9562"
    "9a837e4f74633f823dddda0a0a40d0f37b59a4ac098c86414715db364a4e32216084c561"
    "acdd79e0860b1fdf7497b159cb13230451200296c902ee000000009f2bc7392102449fb5"
    "237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce6800eb604ecae881c"
    "e1eb68dcc1f94725f70aedec1e60077b59eb4ce4b44d5475ba16b8b0b370cad583eaf342"
    "b4442bc0f09001f1cb1074526c58f2047892f79c252321038439233261789dd340bdc145"
    "0172d9c671b72ee8c0b2736ed2a3a250760897fdacd6bf9c0c881001dc5749966a2f6562"
    "f291339521b3894326c0740de880565549fc6838933c95fbee05ff547ae89bad63e92f55"
    "2ca3ea4cc01ac3e4869d0dc61b"
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
                amount=utxo["amount"],
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
            "8e7e55842ae2bd115d1ed7cc0e82d934e929c97648cb0abd9740c85a05a7d543c3d3012"
            "73d79ff7054758579e30cc05cdfe1aca3374adfe55104b409ffce4a2f19d8a5981d5f0c"
            "79b23edac73352ab2898aca89270282500788bac77505ca17d6d0dcc946ced3990c2857"
            "c73743cd74d881fcbcbc8eaaa8d72812ebb9a556610687ca592fe907a4af024390e0a92"
            "60c4f5ea59e7ac426cc5",
            # The following proofid and limited id were obtained by passing
            # the previous serialized proof to `bitcoin-cli decodeavalancheproof`
            UInt256.from_hex(
                "e5845c13b93a1c207bd72033c185a2f833eef1748ee62fd49161119ac2c22864",
            ),
            UInt256.from_hex(
                "74c91491e5d6730ea1701817ed6c34e9627904fc3117647cc7d4bce73f56e45a",
            ),
        )

        # A test similar to Bitcoin ABC's  "Properly signed 1 UTXO proof, P2PKH payout
        # script" (proof_tests.cpp), except that I rebuild it with the node's
        # buildavalancheproof RPC to get the same signatures, as the test proof was
        # generated with a random nonce.
        # RPC command used (Bitcoin ABC commit bdee6e2):
        #  src/bitcoin-cli buildavalancheproof 6296457553413371353 -4129334692075929194 "L4J6gEE4wL9ji2EQbzS5dPMTTsw8LRvcMst1Utij4e3X5ccUSdqW"  '[{"txid":"915d9cc742b46b77c52f69eb6be16739e5ff1cd82ad4fa4ac6581d3ef29fa769","vout":567214302,"amount":4446386380000.00,"height":1370779804,"iscoinbase":false,"privatekey":"KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM"}]'  "ecash:qrupwtz3a7lngsf6xz9qxr75k9jvt07d3uexmwmpqy"
        # Proof ID and limited ID verified with node RPC decodeavalancheproof.
        self._test(
            master2,
            6296457553413371353,
            -4129334692075929194,
            [
                {
                    "txid": UInt256.from_hex(
                        "915d9cc742b46b77c52f69eb6be16739e5ff1cd82ad4fa4ac6581d3ef29fa769"
                    ),
                    "vout": 567214302,
                    "amount": 444638638000000,
                    "height": 1370779804,
                    "iscoinbase": False,
                    "privatekey": "KydYrKDNsVnY5uhpLyC4UmazuJvUjNoKJhEEv9f1mdK1D5zcnMSM",
                },
            ],
            bytes.fromhex("76a914f8172c51efbf34413a308a030fd4b164c5bfcd8f88ac"),
            "d97587e6c882615796011ec8f9a7b1c621023beefdde700a6bc02036335b4df141c8b"
            "c67bb05a971f5ac2745fd683797dde30169a79ff23e1d58c64afad42ad81cffe53967"
            "e16beb692fc5776bb442c79c5d91de00cf21804712806594010038e168a32102449fb"
            "5237efe8f647d32e8b64f06c22d1d40368eaca2a71ffc6a13ecc8bce680e6569b4412"
            "fbb651e44282419f62e9b3face655d3a96e286f70dd616592d6837ccf55cadd71eb53"
            "50a4c46f23ca69230c27f6c0a7c1ed15aee38ab4cbc6f8d031976a914f8172c51efbf"
            "34413a308a030fd4b164c5bfcd8f88ac2fe2dbc2d5d28ed70f4bf9e3e7e76db091570"
            "8100f048a17f6347d95e1135d6403241db4f4b42aa170919bd0847d158d087d9b0d9b"
            "92ad41114cf03a3d44ec84",
            UInt256.from_hex(
                "199bd28f711413cf2cf04a2520f3ccadbff296d9be231c00cb6308528a0b51ca",
            ),
            UInt256.from_hex(
                "8a2fcc5700a89f37a3726cdf3202353bf61f280815a9df744e3c9de6215a745a",
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
