from __future__ import annotations

from typing import Optional


class BaseBlob:
    """Base class for fixed-size opaque blobs.
    This attempts to reproduce the exact same behavior as the class from the bitcoin
    code base.
    """

    BITS: int = 0

    def __init__(self, data: Optional[bytes] = None):
        assert self.BITS % 8 == 0
        self.WIDTH: int = self.BITS // 8
        self.data = data or b"\x00" * self.WIDTH

    def is_null(self) -> bool:
        return not self.data or all(b == 0 for b in self.data)

    def set_null(self):
        self.data = b"\x00" * self.WIDTH

    def compare(self, other: BaseBlob) -> int:
        """Return 0 if the blobs are identical, else 1 if self > other else -1.
        The bytes are compared backwards.
        """
        if self.WIDTH != other.WIDTH:
            raise TypeError("Cannot compare blobs with different sizes")
        if self.data[::-1] < other.data[::-1]:
            return -1
        if self.data[::-1] > other.data[::-1]:
            return 1
        return 0

    def __eq__(self, other):
        return self.compare(other) == 0

    def __lt__(self, other):
        return self.compare(other) < 0

    def __gt__(self, other):
        return self.compare(other) > 0

    def __ge__(self, other):
        return self.compare(other) >= 0

    def __le__(self, other):
        return self.compare(other) <= 0

    def serialize(self) -> bytes:
        return self.data

    def unserialize(self, data: bytes):
        if len(data) != self.WIDTH:
            raise TypeError(
                f"Wrong data size, expected {self.WIDTH} bytes but received "
                f"{len(data)}"
            )
        self.data = data

    def get_hex(self) -> str:
        return self.data[::-1].hex()

    def to_string(self) -> str:
        return self.get_hex()

    def set_hex(self, hex_str: str):
        hex_str = hex_str.strip()
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]

        if len(hex_str) // 2 != self.WIDTH:
            raise TypeError(
                f"Wrong data size, expected {self.WIDTH} bytes but received "
                f"{len(hex_str) // 2}"
            )

        self.data = bytes.fromhex(hex_str)[::-1]


class UInt256(BaseBlob):
    BITS = 256
