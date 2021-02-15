# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
#
# Electrum ABC - lightweight BCHA client
# Copyright (C) 2020 The Electrum ABC developers
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation files
# (the "Software"), to deal in the Software without restriction,
# including without limitation the rights to use, copy, modify, merge,
# publish, distribute, sublicense, and/or sell copies of the Software,
# and to permit persons to whom the Software is furnished to do so,
# subject to the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
"""This module deals with building avalanche proofs.

This requires serializing some keys and UTXO metadata (stakes), and signing
the hash of the stakes to prove ownership of the UTXO.
"""


import struct
from typing import List

from . import schnorr
from .bitcoin import public_key_from_private_key, deserialize_privkey
from .bitcoin import Hash as sha256d


def write_compact_size(nsize: int) -> bytes:
    """Serialize a size. Values lower than 253 are serialized using 1 byte.
    For larger values, the first byte indicates how many additional bytes to
    read when decoding (253: 2 bytes, 254: 4 bytes, 255: 8 bytes)

    :param nsize: value to serialize
    :return:
    """
    assert nsize >= 0
    if nsize < 253:
        return struct.pack("B", nsize)
    if nsize < 0x10000:
        return struct.pack("BH", 253, nsize)
    if nsize < 0x100000000:
        return struct.pack("BL", 254, nsize)
    assert nsize < 0x10000000000000000
    return struct.pack("BQ", 255, nsize)


class PublicKey:
    def __init__(self, keydata):
        self.keydata: bytes = keydata

    def serialize(self) -> bytes:
        return write_compact_size(len(self.keydata)) + self.keydata


class Key:
    """A private key"""

    def __init__(self, keydata, compressed):
        self.keydata: bytes = keydata
        """32 byte raw private key (as you would get from
        deserialize_privkey, etc)"""
        self.compressed: bool = compressed

    def sign_schnorr(self, hash: bytes) -> bytes:
        """

        :param hash: should be the 32 byte sha256d hash of the tx input (or
            message) you want to sign
        :return: Returns a 64-long bytes object (the signature)
        :raise: ValueError on failure.
            Failure can occur due to an invalid private key.
        """
        return schnorr.sign(self.keydata, hash)

    def get_pubkey(self):
        pubkey = public_key_from_private_key(self.keydata,
                                             self.compressed)
        return PublicKey(bytes.fromhex(pubkey))


class COutPoint:
    """
    An outpoint - a combination of a transaction hash and an index n into its
    vout.
    """
    def __init__(self, txid, n):
        self.txid: bytes = txid
        """Transaction ID (SHA256 hash).
        This is a bytes object of length 32 ("uint256" in bitcoin ABC)"""

        self.n: int = n
        """vout index (uint32)"""

    def serialize(self) -> bytes:
        # The endianness of the txid/hash/uint256 needs to be changed, hence
        # the bytes reversal with [::-1].
        # Alternatively, I could have stored the txid as an int and used
        # ser_uint256 from https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/test/functional/test_framework/messages.py#L120
        return self.txid[::-1] + struct.pack('i', self.n)


class Stake:
    def __init__(self, utxo, amount, height, pubkey):
        self.utxo: COutPoint = utxo
        self.amount: int = amount
        """Amount in satoshis (int64)"""
        self.height: int = height
        """Block height containing this utxo (uint32)"""
        self.pubkey: PublicKey = pubkey
        """Public key"""

    def serialize(self) -> bytes:
        is_coinbase = 0
        height_ser = self.height << 1 | is_coinbase

        return self.utxo.serialize() + struct.pack('qI', self.amount, height_ser) + self.pubkey.serialize()

    def get_hash(self, proofid) -> bytes:
        """Return the bitcoin hash of the concatenation of proofid
        and the serialized stake."""
        return sha256d(proofid + self.serialize())


def compute_proof_id(sequence: int, expiration_time: int,
                     master: PublicKey, stakes: List[Stake]) -> bytes:
    """Return Bitcoin's 256-bit hash (double SHA-256) of the
    serialized proof data.

    :return: bytes of length 32
    """
    ss = struct.pack("Qq", sequence, expiration_time)
    ss += master.serialize()
    ss += write_compact_size(len(stakes))
    for s in stakes:
        ss += s.serialize()
    h = sha256d(ss)
    assert len(h) == 32
    return h


class SignedStake:
    def __init__(self, stake, sig):
        self.stake: Stake = stake
        self.sig: bytes = sig
        """Signature for this stake, bytes of length 64"""

    def serialize(self) -> bytes:
        return self.stake.serialize() + self.sig


class StakeSigner:
    def __init__(self, stake, key):
        self.stake: Stake = stake
        self.key: Key = key

    def sign(self, proofid: bytes) -> SignedStake:
        return SignedStake(self.stake,
                           self.key.sign_schnorr(self.stake.get_hash(proofid)))


class Proof:
    def __init__(self, sequence: int, expiration_time: int,
                 master: PublicKey, signed_stakes: List[SignedStake]):
        self.sequence = sequence
        """uint64"""
        self.expiration_time = expiration_time
        """int64"""
        self.master: PublicKey = master
        """Master public key"""

        self.stakes: List[SignedStake] = signed_stakes

        self.proofid: bytes = compute_proof_id(
            sequence, expiration_time, master,
            [ss.stake for ss in signed_stakes]
        )

    def serialize(self) -> bytes:
        p = struct.pack("Qq", self.sequence, self.expiration_time)
        p += self.master.serialize()

        # The following serialization for the length of the SignedStake vector
        # only works for low number of stakes (presumably < 253).
        p += write_compact_size(len(self.stakes))

        for signed_stake in self.stakes:
            p += signed_stake.serialize()
        return p


class ProofBuilder(object):
    def __init__(self, sequence: int, expiration_time: int,
                 master: str):
        """

        :param sequence:
        :param expiration_time:
        :param master: hex string
        """
        self.sequence = sequence
        """uint64"""
        self.expiration_time = expiration_time
        """int64"""
        self.master: PublicKey = PublicKey(bytes.fromhex(master))
        """Master public key"""

        self.stake_signers: List[StakeSigner] = []

    def add_utxo(self, txid, vout, value, height, wif_privkey):
        """

        :param str txid: Transaction hash (hex str)
        :param int vout: Output index for this utxo in the transaction.
        :param float value: Amount in bitcoins
        :param int height: Block height containing this transaction
        :param str wif_privkey: Private key unlocking this UTXO (in WIF format)
        :return:
        """
        _txin_type, deser_privkey, compressed = deserialize_privkey(wif_privkey)
        privkey = Key(deser_privkey, compressed)

        utxo = COutPoint(bytes.fromhex(txid), vout)
        amount = int(10 ** 8 * value)
        stake = Stake(utxo, amount, height, privkey.get_pubkey())

        self.stake_signers.append(StakeSigner(stake, privkey))

    def build(self):
        proofid = compute_proof_id(
            self.sequence, self.expiration_time, self.master,
            [signer.stake for signer in self.stake_signers])
        signed_stakes = [signer.sign(proofid) for signer in self.stake_signers]
        return Proof(self.sequence, self.expiration_time, self.master,
                     signed_stakes)
