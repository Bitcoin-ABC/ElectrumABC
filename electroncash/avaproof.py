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
from typing import Any, List, Sequence, Tuple

from . import schnorr
from .bitcoin import Hash as sha256d
from .bitcoin import deserialize_privkey, public_key_from_private_key
from .uint256 import UInt256


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
        return struct.pack("<BH", 253, nsize)
    if nsize < 0x100000000:
        return struct.pack("<BL", 254, nsize)
    assert nsize < 0x10000000000000000
    return struct.pack("<BQ", 255, nsize)


def serialize_sequence(seq: Sequence[Any]) -> bytes:
    """Serialize a variable length sequence (list...) of serializable constant size
    objects. The length of the sequence is encoded as a VarInt.
    """
    b = write_compact_size(len(seq))
    for obj in seq:
        b += obj.serialize()
    return b


def serialize_blob(blob: bytes) -> bytes:
    """Serialize a variable length bytestring. The length of the sequence is encoded as
    a VarInt.
    """
    return write_compact_size(len(blob)) + blob


class PublicKey:
    def __init__(self, keydata):
        self.keydata: bytes = keydata

    def serialize(self) -> bytes:
        return serialize_blob(self.keydata)


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
        pubkey = public_key_from_private_key(self.keydata, self.compressed)
        return PublicKey(bytes.fromhex(pubkey))


class COutPoint:
    """
    An outpoint - a combination of a transaction hash and an index n into its
    vout.
    """

    def __init__(self, txid, n):
        self.txid: UInt256 = txid
        """Transaction ID (SHA256 hash)."""

        self.n: int = n
        """vout index (uint32)"""

    def serialize(self) -> bytes:
        return self.txid.serialize() + struct.pack("<I", self.n)


class Stake:
    def __init__(self, utxo, amount, height, pubkey, is_coinbase):
        self.utxo: COutPoint = utxo
        self.amount: int = amount
        """Amount in satoshis (int64)"""
        self.height: int = height
        """Block height containing this utxo (uint32)"""
        self.pubkey: PublicKey = pubkey
        """Public key"""
        self.is_coinbase: bool = is_coinbase

        self.stake_id = UInt256(sha256d(self.serialize()))
        """Stake id used for sorting stakes in a proof"""

    def serialize(self) -> bytes:
        is_coinbase = int(self.is_coinbase)
        height_ser = self.height << 1 | is_coinbase

        return (
            self.utxo.serialize()
            + struct.pack("qI", self.amount, height_ser)
            + self.pubkey.serialize()
        )

    def get_hash(self, commitment: bytes) -> bytes:
        """Return the bitcoin hash of the concatenation of proofid
        and the serialized stake."""
        return sha256d(commitment + self.serialize())


def compute_limited_proof_id(
    sequence: int,
    expiration_time: int,
    stakes: List[Stake],
    payout_script_pubkey: bytes,
) -> UInt256:
    ss = struct.pack("<Qq", sequence, expiration_time)
    ss += serialize_blob(payout_script_pubkey)
    ss += serialize_sequence(stakes)
    return UInt256(sha256d(ss))


def compute_proof_id(
    sequence: int,
    expiration_time: int,
    stakes: List[Stake],
    master: PublicKey,
    payout_script_pubkey: bytes,
) -> Tuple[UInt256, UInt256]:
    """
    Return a 2-tuple with the limited proof ID and the proof ID.

    Note that it is the caller's responsibility to sort the list of stakes by
    their stake ID (this is done in ProofBuilder.add_utxo).
    """
    ltd_id = compute_limited_proof_id(
        sequence, expiration_time, stakes, payout_script_pubkey
    )
    ss = ltd_id.serialize()
    ss += master.serialize()
    proofid = sha256d(ss)
    return ltd_id, UInt256(proofid)


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

    def sign(self, commitment: bytes) -> SignedStake:
        return SignedStake(
            self.stake, self.key.sign_schnorr(self.stake.get_hash(commitment))
        )


class Proof:
    def __init__(
        self,
        sequence: int,
        expiration_time: int,
        master_pub: PublicKey,
        signed_stakes: List[SignedStake],
        payout_script_pubkey: bytes,
        signature: bytes,
    ):
        self.sequence = sequence
        """uint64"""
        self.expiration_time = expiration_time
        """int64"""
        self.master_pub: PublicKey = master_pub
        """Master public key"""
        self.stakes: List[SignedStake] = signed_stakes
        """List of signed stakes sorted by their stake ID."""
        self.payout_script_pubkey: bytes = payout_script_pubkey
        self.signature: bytes = signature
        """Schnorr signature of some of the proof's data by the master key."""

        self.limitedid, self.proofid = compute_proof_id(
            sequence,
            expiration_time,
            [ss.stake for ss in signed_stakes],
            master_pub,
            self.payout_script_pubkey,
        )

    def serialize(self) -> bytes:
        p = struct.pack("<Qq", self.sequence, self.expiration_time)
        p += self.master_pub.serialize()
        p += serialize_sequence(self.stakes)
        p += serialize_blob(self.payout_script_pubkey)
        p += self.signature
        return p


class ProofBuilder:
    def __init__(
        self,
        sequence: int,
        expiration_time: int,
        master: Key,
        payout_script_pubkey: bytes = b"",
    ):
        self.sequence = sequence
        """uint64"""
        self.expiration_time = expiration_time
        """int64"""
        self.master: Key = master
        """Master public key"""
        self.master_pub = master.get_pubkey()
        self.payout_script_pubkey = payout_script_pubkey

        self.stake_signers: List[StakeSigner] = []
        """List of stake signers sorted by stake ID.
        Adding stakes through :meth:`add_utxo` takes care of the sorting.
        """

    def add_utxo(self, txid: UInt256, vout, amount, height, wif_privkey, is_coinbase):
        """

        :param str txid: Transaction hash (hex str)
        :param int vout: Output index for this utxo in the transaction.
        :param float amount: Amount in satoshis
        :param int height: Block height containing this transaction
        :param str wif_privkey: Private key unlocking this UTXO (in WIF format)
        :param bool is_coinbase: Is the coin UTXO a coinbase UTXO
        :return:
        """
        _txin_type, deser_privkey, compressed = deserialize_privkey(wif_privkey)
        privkey = Key(deser_privkey, compressed)

        utxo = COutPoint(txid, vout)
        stake = Stake(utxo, amount, height, privkey.get_pubkey(), is_coinbase)

        self.stake_signers.append(StakeSigner(stake, privkey))

        # Enforce a unique sorting for stakes in a proof. The sorting key is a UInt256.
        # See UInt256.compare for the specifics about sorting these objects.
        self.stake_signers.sort(key=lambda ss: ss.stake.stake_id)

    def build(self):
        ltd_id, proofid = compute_proof_id(
            self.sequence,
            self.expiration_time,
            [signer.stake for signer in self.stake_signers],
            self.master_pub,
            self.payout_script_pubkey,
        )
        signature = self.master.sign_schnorr(ltd_id.serialize())

        stake_commitment_data = (
            struct.pack("<q", self.expiration_time) + self.master_pub.serialize()
        )
        stake_commitment = sha256d(stake_commitment_data)
        signed_stakes = [signer.sign(stake_commitment) for signer in self.stake_signers]

        return Proof(
            self.sequence,
            self.expiration_time,
            self.master_pub,
            signed_stakes,
            self.payout_script_pubkey,
            signature,
        )
