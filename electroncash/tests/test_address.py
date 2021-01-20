# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Reference tests for Address objects"""

import unittest
from ..address import Address, AddressError

LEGACY_ADDRESS = "1F6UYGAwkzZKqFwyiwc54b7SNvHsNgcZ6h"
BCH_CASHADDR_NO_PREFIX = "qzdf44zy632zk4etztvmaqav0y2cest4evjvrwf70z"
BCH_CASHADDR_WITH_PREFIX = "bitcoincash:" + BCH_CASHADDR_NO_PREFIX
ECASH_CASHADDR_NO_PREFIX = "qzdf44zy632zk4etztvmaqav0y2cest4evtph9jyf4"
ECASH_CASHADDR_WITH_PREFIX = "ecash:" + ECASH_CASHADDR_NO_PREFIX


class TestAddressFromString(unittest.TestCase):
    """Unit test class for parsing addressess from string."""
    def _test_addr(self, addr: Address):
        self.assertEqual(addr.to_full_string(fmt=Address.FMT_LEGACY),
                         LEGACY_ADDRESS)
        self.assertEqual(addr.to_full_string(fmt=Address.FMT_CASHADDR_BCH),
                         BCH_CASHADDR_WITH_PREFIX)

    def test_from_legacy(self):
        self._test_addr(Address.from_string(LEGACY_ADDRESS))

    def test_from_bch_cashaddr(self):
        self._test_addr(Address.from_string(BCH_CASHADDR_WITH_PREFIX))
        self._test_addr(Address.from_string(BCH_CASHADDR_NO_PREFIX))
        self._test_addr(Address.from_string(BCH_CASHADDR_WITH_PREFIX.upper()))
        self._test_addr(Address.from_string(BCH_CASHADDR_NO_PREFIX.upper()))

    def test_from_cashaddr_arbitrary_prefix(self):
        self._test_addr(Address.from_string(ECASH_CASHADDR_WITH_PREFIX,
                                            support_arbitrary_prefix=True))
        with self.assertRaises(AddressError):
            # default (support_arbitrary_prefix=False) is to not support
            # unusual prefixes
            Address.from_string(ECASH_CASHADDR_WITH_PREFIX)
        with self.assertRaises(AddressError):
            # unusual prefixes are only supported if the prefix is specified
            Address.from_string(ECASH_CASHADDR_NO_PREFIX,
                                support_arbitrary_prefix=True)


if __name__ == '__main__':
    unittest.main()
