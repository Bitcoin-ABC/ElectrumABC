# -*- coding: utf-8 -*-
# -*- mode: python3 -*-
#
# Electrum ABC - lightweight eCash client
# Copyright (C) 2020-2022 The Electrum ABC developers
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
from __future__ import annotations

import struct
from io import BytesIO
from typing import List

from ..bitcoin import Hash as sha256d
from ..bitcoin import deserialize_privkey
from ..uint256 import UInt256
from .serialize import (
    COutPoint,
    Key,
    PublicKey,
    SerializableObject,
    deserialize_blob,
    deserialize_sequence,
    serialize_blob,
    serialize_sequence,
)


class Stake(SerializableObject):
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

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Stake:
        utxo = COutPoint.deserialize(stream)
        amount = struct.unpack("q", stream.read(8))[0]
        height_ser = struct.unpack("I", stream.read(4))[0]
        pubkey = PublicKey.deserialize(stream)
        return Stake(utxo, amount, height_ser >> 1, pubkey, height_ser & 1)


class ProofId(UInt256):
    pass


class LimitedProofId(UInt256):
    @classmethod
    def build(
        cls,
        sequence: int,
        expiration_time: int,
        stakes: List[Stake],
        payout_script_pubkey: bytes,
    ) -> LimitedProofId:
        """Build a limited proofid from the Proof parameters"""
        ss = struct.pack("<Qq", sequence, expiration_time)
        ss += serialize_blob(payout_script_pubkey)
        ss += serialize_sequence(stakes)
        return cls(sha256d(ss))

    def compute_proof_id(self, master: PublicKey) -> ProofId:
        ss = self.serialize()
        ss += master.serialize()
        return ProofId(sha256d(ss))


class SignedStake(SerializableObject):
    def __init__(self, stake, sig):
        self.stake: Stake = stake
        self.sig: bytes = sig
        """Signature for this stake, bytes of length 64"""

    def serialize(self) -> bytes:
        return self.stake.serialize() + self.sig

    @classmethod
    def deserialize(cls, stream: BytesIO) -> SignedStake:
        stake = Stake.deserialize(stream)
        sig = stream.read(64)
        return SignedStake(stake, sig)


class StakeSigner:
    def __init__(self, stake, key):
        self.stake: Stake = stake
        self.key: Key = key

    def sign(self, commitment: bytes) -> SignedStake:
        return SignedStake(
            self.stake, self.key.sign_schnorr(self.stake.get_hash(commitment))
        )


class Proof(SerializableObject):
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

        self.limitedid = LimitedProofId.build(
            sequence,
            expiration_time,
            [ss.stake for ss in signed_stakes],
            payout_script_pubkey,
        )
        self.proofid = self.limitedid.compute_proof_id(master_pub)

    def serialize(self) -> bytes:
        p = struct.pack("<Qq", self.sequence, self.expiration_time)
        p += self.master_pub.serialize()
        p += serialize_sequence(self.stakes)
        p += serialize_blob(self.payout_script_pubkey)
        p += self.signature
        return p

    @classmethod
    def deserialize(cls, stream: BytesIO) -> Proof:
        sequence, expiration_time = struct.unpack("<Qq", stream.read(16))
        master_pub = PublicKey.deserialize(stream)
        signed_stakes = deserialize_sequence(stream, SignedStake)
        payout_pubkey = deserialize_blob(stream)
        signature = stream.read(64)
        return Proof(
            sequence,
            expiration_time,
            master_pub,
            signed_stakes,
            payout_pubkey,
            signature,
        )


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

    def build(self) -> Proof:
        ltd_id = LimitedProofId.build(
            self.sequence,
            self.expiration_time,
            [signer.stake for signer in self.stake_signers],
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
