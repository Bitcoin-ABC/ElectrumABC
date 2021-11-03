import unittest

from ..uint256 import BaseBlob, UInt256


class TestBlob(BaseBlob):
    BITS = 3 * 8


class TestBaseBlob(unittest.TestCase):
    def test_is_null(self):
        self.assertTrue(TestBlob().is_null())

        data = b"\x00" * 3
        self.assertTrue(TestBlob(data).is_null())

        self.assertFalse(BaseBlob(b"\xde\xad\x00").is_null())

    def test_set_null(self):
        bb = TestBlob(b"abc")
        self.assertFalse(bb.is_null())

        bb.set_null()
        self.assertTrue(bb.is_null())

    def test_compare(self):
        self.assertTrue(TestBlob(b"\xde\xad\xbe") == TestBlob(b"\xde\xad\xbe"))
        self.assertTrue(TestBlob(b"\xde\xad\xbe") <= TestBlob(b"\xde\xad\xbe"))
        self.assertTrue(TestBlob(b"\xde\xad\xbe") >= TestBlob(b"\xde\xad\xbe"))
        self.assertFalse(TestBlob(b"\xde\xad\xbe") < TestBlob(b"\xde\xad\xbe"))
        self.assertFalse(TestBlob(b"\xde\xad\xbe") > TestBlob(b"\xde\xad\xbe"))

        self.assertTrue(TestBlob(b"\x00\x00\x01") < TestBlob(b"\x00\x00\x02"))
        self.assertTrue(TestBlob(b"\x00\x00\x01") <= TestBlob(b"\x00\x00\x02"))
        self.assertFalse(TestBlob(b"\x00\x00\x01") == TestBlob(b"\x00\x00\x02"))
        self.assertFalse(TestBlob(b"\x00\x00\x01") > TestBlob(b"\x00\x00\x02"))
        self.assertFalse(TestBlob(b"\x00\x00\x01") >= TestBlob(b"\x00\x00\x02"))

        # The bytes are compared backwards
        a = TestBlob(b"\x02\x01\x03")
        b = TestBlob(b"\x03\x01\x02")
        self.assertTrue(a > b)
        self.assertTrue(a >= b)
        self.assertFalse(a < b)
        self.assertFalse(a <= b)
        self.assertFalse(a == b)

    def test_serialize(self):
        bb = TestBlob()
        self.assertEqual(bb.serialize(), b"\x00\x00\x00")

        bb = TestBlob(b"\x00\x01\x03")
        self.assertEqual(bb.serialize(), b"\x00\x01\x03")

        bbu = TestBlob()
        bbu.unserialize(b"\x00\x01\x03")
        self.assertEqual(bbu, TestBlob(b"\x00\x01\x03"))

    def test_hex(self):
        bb = TestBlob(b"\x00\x01\x03")
        self.assertEqual(bb.get_hex(), "030100")

        bb.set_hex("dead00")
        self.assertEqual(bb.serialize(), b"\x00\xad\xde")


class TestUInt256(unittest.TestCase):
    def test_unitialized(self):
        a = UInt256()
        self.assertEqual(a.WIDTH, 32)
        self.assertTrue(a.is_null())
        self.assertEqual(a.serialize(), b"\x00" * 32)
        self.assertEqual(a.get_hex(), "00" * 32)

        data = b"\x01" + 30 * b"\x00" + b"\02"
        a.unserialize(data)
        self.assertEqual(a.serialize(), data)
        self.assertEqual(a.get_hex(), "02" + "00" * 30 + "01")

    def test_initialized(self):
        data = b"\x01" + 30 * b"\x00" + b"\02"
        a = UInt256(data)
        self.assertEqual(a.serialize(), data)
        self.assertEqual(a.get_hex(), "02" + "00" * 30 + "01")

        a.set_null()
        self.assertEqual(a.serialize(), b"\x00" * 32)

        a.set_hex("aa" + "00" * 30 + "bb")
        self.assertEqual(a.serialize(), b"\xbb" + b"\x00" * 30 + b"\xaa")


def suite():
    test_suite = unittest.TestSuite()
    loadTests = unittest.defaultTestLoader.loadTestsFromTestCase
    test_suite.addTest(loadTests(TestBaseBlob))
    test_suite.addTest(loadTests(TestUInt256))
    return test_suite


if __name__ == "__main__":
    unittest.main(defaultTest="suite")
