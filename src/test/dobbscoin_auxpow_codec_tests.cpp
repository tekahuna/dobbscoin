// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Copyright (c) 2014-2024 The Dogecoin Core developers
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/dobbscoin_auxpow.h>
#include <test/data/dobbscoin_auxpow_vectors.h>

#include <crypto/sha256.h>
#include <util/strencodings.h>

#include <array>
#include <cstdint>
#include <initializer_list>
#include <ios>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dobbscoin_auxpow_codec_tests)

namespace {
using dobbscoin::CAuxPow;
using dobbscoin::CBlockHeader;
using dobbscoin::CPureBlockHeader;

void Fill(uint256& value, unsigned int seed)
{
    for (unsigned int i = 0; i < 32; ++i) value.begin()[i] = static_cast<unsigned char>(seed + i);
}

uint256 Filled(unsigned int seed)
{
    uint256 value;
    Fill(value, seed);
    return value;
}

CScript MakeScript(std::initializer_list<unsigned char> bytes)
{
    CScript script;
    for (const unsigned char byte : bytes) script.push_back(byte);
    return script;
}

std::vector<unsigned char> Bytes(const DataStream& stream)
{
    const std::string raw{stream.str()};
    return {raw.begin(), raw.end()};
}

template <typename T>
std::vector<unsigned char> SerializeBytes(const T& value)
{
    DataStream stream{};
    stream << value;
    return Bytes(stream);
}

std::string RawSha256Hex(std::span<const unsigned char> bytes)
{
    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest{};
    CSHA256{}.Write(bytes.data(), bytes.size()).Finalize(digest.data());
    return HexStr(digest);
}

CTransactionRef MakeParentCoinbase(bool with_witness = false)
{
    CMutableTransaction transaction;
    transaction.version = 2;
    transaction.vin.resize(1);
    transaction.vin[0].prevout.hash = Txid::FromUint256(Filled(0x10));
    transaction.vin[0].prevout.n = 0x01020304;
    transaction.vin[0].scriptSig = MakeScript({0x03, 0x51, 0x52});
    transaction.vin[0].nSequence = 0xa1b2c3d4;
    if (with_witness) {
        transaction.vin[0].prevout.SetNull();
        transaction.vin[0].scriptSig = MakeScript({0x03, 0x51, 0x52, 0x53});
        transaction.vin[0].scriptWitness.stack.push_back({0x91, 0x92, 0x93});
    }
    transaction.vout.emplace_back(123456789, MakeScript({0x51, 0xac}));
    transaction.nLockTime = 0x11223344;
    return MakeTransactionRef(std::move(transaction));
}

CAuxPow MakeProof(unsigned int parent_count, unsigned int chain_count, bool with_witness = false)
{
    CAuxPow proof{MakeParentCoinbase(with_witness)};
    Fill(proof.hashBlock, 0x20);
    for (unsigned int i = 0; i < parent_count; ++i) proof.vMerkleBranch.push_back(Filled(i + 0x30));
    proof.nIndex = 0x12345678;
    for (unsigned int i = 0; i < chain_count; ++i) proof.vChainMerkleBranch.push_back(Filled(i + 0x60));
    proof.nChainIndex = -7;
    proof.parentBlock.nVersion = 0x10203040;
    Fill(proof.parentBlock.hashPrevBlock, 0x80);
    Fill(proof.parentBlock.hashMerkleRoot, 0xa0);
    proof.parentBlock.nTime = 0x11223344;
    proof.parentBlock.nBits = 0x1e0ffff0;
    proof.parentBlock.nNonce = 0xa1b2c3d4;
    return proof;
}

CBlockHeader MakeChild(bool with_proof = true)
{
    CBlockHeader child;
    child.nVersion = with_proof ? 0x00b00103 : 0x00b00003;
    Fill(child.hashPrevBlock, 0x11);
    Fill(child.hashMerkleRoot, 0x44);
    child.nTime = 0x55667788;
    child.nBits = 0x1e0ffff0;
    child.nNonce = 0x12345678;
    if (with_proof) child.SetAuxpow(MakeProof(2, 3));
    return child;
}

std::vector<unsigned char> SerializeWithWitnessParams(const CBlockHeader& header, bool allow_witness)
{
    DataStream stream{};
    if (allow_witness) {
        stream << TX_WITH_WITNESS(header);
    } else {
        stream << TX_NO_WITNESS(header);
    }
    return Bytes(stream);
}
} // namespace

BOOST_AUTO_TEST_CASE(source_golden_rich_proof_roundtrip_and_fields)
{
    const auto expected = ParseHex(std::string{dobbscoin_test_vectors::RICH_PROOF_HEX});
    const auto encoded = SerializeBytes(MakeProof(2, 3));
    BOOST_REQUIRE_EQUAL(encoded.size(), 347);
    BOOST_CHECK(encoded == expected);
    BOOST_CHECK_EQUAL(RawSha256Hex(encoded), dobbscoin_test_vectors::RICH_PROOF_SHA256);

    DataStream input{std::span<const unsigned char>{expected}};
    CAuxPow decoded;
    input >> decoded;
    BOOST_CHECK(input.empty());
    BOOST_CHECK(SerializeBytes(decoded) == expected);

    BOOST_REQUIRE(decoded.tx);
    BOOST_CHECK_EQUAL(decoded.tx->version, 2U);
    BOOST_REQUIRE_EQUAL(decoded.tx->vin.size(), 1U);
    BOOST_CHECK(decoded.tx->vin[0].prevout.hash.ToUint256() == Filled(0x10));
    BOOST_CHECK_EQUAL(decoded.tx->vin[0].prevout.n, 0x01020304U);
    BOOST_CHECK(decoded.tx->vin[0].scriptSig == MakeScript({0x03, 0x51, 0x52}));
    BOOST_CHECK_EQUAL(decoded.tx->vin[0].nSequence, 0xa1b2c3d4U);
    BOOST_REQUIRE_EQUAL(decoded.tx->vout.size(), 1U);
    BOOST_CHECK_EQUAL(decoded.tx->vout[0].nValue, 123456789);
    BOOST_CHECK(decoded.tx->vout[0].scriptPubKey == MakeScript({0x51, 0xac}));
    BOOST_CHECK_EQUAL(decoded.tx->nLockTime, 0x11223344U);

    BOOST_CHECK(decoded.hashBlock == Filled(0x20));
    BOOST_REQUIRE_EQUAL(decoded.vMerkleBranch.size(), 2U);
    BOOST_CHECK(decoded.vMerkleBranch[0] == Filled(0x30));
    BOOST_CHECK(decoded.vMerkleBranch[1] == Filled(0x31));
    BOOST_CHECK_EQUAL(decoded.nIndex, 0x12345678);
    BOOST_REQUIRE_EQUAL(decoded.vChainMerkleBranch.size(), 3U);
    BOOST_CHECK(decoded.vChainMerkleBranch[0] == Filled(0x60));
    BOOST_CHECK(decoded.vChainMerkleBranch[1] == Filled(0x61));
    BOOST_CHECK(decoded.vChainMerkleBranch[2] == Filled(0x62));
    BOOST_CHECK_EQUAL(decoded.nChainIndex, -7);
    BOOST_CHECK_EQUAL(decoded.parentBlock.nVersion, 0x10203040);
    BOOST_CHECK(decoded.parentBlock.hashPrevBlock == Filled(0x80));
    BOOST_CHECK(decoded.parentBlock.hashMerkleRoot == Filled(0xa0));
    BOOST_CHECK_EQUAL(decoded.parentBlock.nTime, 0x11223344U);
    BOOST_CHECK_EQUAL(decoded.parentBlock.nBits, 0x1e0ffff0U);
    BOOST_CHECK_EQUAL(decoded.parentBlock.nNonce, 0xa1b2c3d4U);
}

BOOST_AUTO_TEST_CASE(source_compactsize_boundary_proof)
{
    const auto encoded = SerializeBytes(MakeProof(253, 31));
    BOOST_REQUIRE_EQUAL(encoded.size(), 9277);
    BOOST_CHECK_EQUAL(RawSha256Hex(encoded), dobbscoin_test_vectors::COMPACT_BOUNDARY_SHA256);

    // Parent branch size 253 uses canonical fd fd 00; the 31-node chain
    // branch is accepted by the codec. The 30-node rule belongs to proof
    // validation and is intentionally not applied by this serializer.
    BOOST_CHECK_EQUAL(encoded[97], 0xfd);
    BOOST_CHECK_EQUAL(encoded[98], 0xfd);
    BOOST_CHECK_EQUAL(encoded[99], 0x00);
    BOOST_CHECK_EQUAL(encoded[8200], 31);

    DataStream input{std::span<const unsigned char>{encoded}};
    CAuxPow decoded;
    input >> decoded;
    BOOST_CHECK(input.empty());
    BOOST_CHECK_EQUAL(decoded.vMerkleBranch.size(), 253U);
    BOOST_CHECK_EQUAL(decoded.vChainMerkleBranch.size(), 31U);
    BOOST_CHECK(SerializeBytes(decoded) == encoded);
}

BOOST_AUTO_TEST_CASE(source_child_header_gate_and_pure_hashes)
{
    CPureBlockHeader pure_default;
    CBlockHeader full_default;
    BOOST_CHECK_EQUAL(pure_default.nVersion, 0);
    BOOST_CHECK_EQUAL(full_default.nVersion, CBlockHeader::CURRENT_VERSION);

    const auto expected_flagged = ParseHex(std::string{dobbscoin_test_vectors::FLAGGED_CHILD_HEX});
    CBlockHeader child = MakeChild();
    const auto encoded = SerializeBytes(child);
    BOOST_REQUIRE_EQUAL(encoded.size(), 427);
    BOOST_CHECK(encoded == expected_flagged);
    BOOST_CHECK_EQUAL(child.GetHash().GetHex(), dobbscoin_test_vectors::FLAGGED_CHILD_ID);

    BOOST_REQUIRE(child.GetAuxpow());
    BOOST_CHECK_EQUAL(child.GetAuxpow()->parentBlock.GetHash().GetHex(), dobbscoin_test_vectors::PARENT_HEADER_ID);
    BOOST_CHECK_EQUAL(child.GetAuxpow()->parentBlock.GetPoWHash().GetHex(), dobbscoin_test_vectors::PARENT_SCRYPT_ID);

    auto changed_proof = MakeProof(2, 3);
    changed_proof.nIndex++;
    CBlockHeader same_child = child;
    same_child.SetAuxpow(std::move(changed_proof));
    BOOST_CHECK_EQUAL(same_child.GetHash().GetHex(), child.GetHash().GetHex());
    BOOST_CHECK(SerializeBytes(same_child) != encoded);

    // A stale proof pointer is ignored when the bit is clear, matching the
    // source's version-bit-gated wire layout.
    CBlockHeader unflagged = child;
    unflagged.nVersion &= ~CPureBlockHeader::VERSION_AUXPOW;
    const auto expected_unflagged = ParseHex(std::string{dobbscoin_test_vectors::UNFLAGGED_CHILD_HEX});
    const auto unflagged_bytes = SerializeBytes(unflagged);
    BOOST_REQUIRE_EQUAL(unflagged_bytes.size(), 80);
    BOOST_CHECK(unflagged_bytes == expected_unflagged);
    BOOST_CHECK_EQUAL(unflagged.GetHash().GetHex(), dobbscoin_test_vectors::UNFLAGGED_CHILD_ID);

    CBlockHeader decoded = dobbscoin::DecodeHeaderWithBudget(expected_unflagged, 80);
    BOOST_CHECK(!decoded.GetAuxpow());
}

BOOST_AUTO_TEST_CASE(parent_coinbase_stays_legacy_under_witness_stream)
{
    CBlockHeader child = MakeChild(false);
    child.SetAuxpow(MakeProof(2, 3, true));
    BOOST_REQUIRE(child.GetAuxpow());
    BOOST_REQUIRE(child.GetAuxpow()->tx->HasWitness());
    BOOST_CHECK(child.GetAuxpow()->tx->IsCoinBase());

    const auto witness_mode = SerializeWithWitnessParams(child, true);
    const auto legacy_mode = SerializeWithWitnessParams(child, false);
    BOOST_CHECK(witness_mode == legacy_mode);
    BOOST_CHECK_EQUAL(witness_mode.size(), 428);

    CBlockHeader decoded;
    DataStream input{std::span<const unsigned char>{witness_mode}};
    input >> TX_WITH_WITNESS(decoded);
    BOOST_CHECK(input.empty());
    BOOST_REQUIRE(decoded.GetAuxpow());
    BOOST_REQUIRE(decoded.GetAuxpow()->tx);
    BOOST_CHECK(!decoded.GetAuxpow()->tx->HasWitness());
    BOOST_CHECK(decoded.GetAuxpow()->tx->GetHash() == child.GetAuxpow()->tx->GetHash());
    BOOST_CHECK(SerializeWithWitnessParams(decoded, true) == witness_mode);
}

BOOST_AUTO_TEST_CASE(bounded_decode_malformed_inputs_and_failure_atomic_destination)
{
    const auto flagged = ParseHex(std::string{dobbscoin_test_vectors::FLAGGED_CHILD_HEX});
    const std::span<const unsigned char> full_input{flagged};
    BOOST_CHECK_THROW(dobbscoin::DecodeHeaderWithBudget(full_input, flagged.size() - 1), std::ios_base::failure);
    BOOST_CHECK(dobbscoin::DecodeHeaderWithBudget(full_input, flagged.size()).GetAuxpow());

    // Every strict prefix of this flagged header truncates a required field.
    for (size_t prefix = 0; prefix < flagged.size(); ++prefix) {
        const std::span<const unsigned char> truncated{flagged.data(), prefix};
        BOOST_CHECK_THROW(dobbscoin::DecodeHeaderWithBudget(truncated, flagged.size()), std::ios_base::failure);
    }

    CBlockHeader destination = MakeChild();
    const int32_t old_version = destination.nVersion;
    const uint256 old_hash = destination.GetHash();
    const auto old_proof = destination.GetAuxpow();
    const std::span<const unsigned char> truncated{flagged.data(), flagged.size() - 1};
    BOOST_CHECK_THROW(dobbscoin::DecodeHeaderWithBudget(truncated, flagged.size(), destination), std::ios_base::failure);
    BOOST_CHECK_EQUAL(destination.nVersion, old_version);
    BOOST_CHECK(destination.GetHash() == old_hash);
    BOOST_CHECK(destination.GetAuxpow() == old_proof);

    // Non-canonical CompactSize for the parent transaction's vin count.
    CBlockHeader flagged_header = MakeChild();
    DataStream pure_stream{};
    pure_stream << AsBase<CPureBlockHeader>(flagged_header);
    auto noncanonical = Bytes(pure_stream);
    noncanonical.insert(noncanonical.end(), {0x02, 0x00, 0x00, 0x00, 0xfd, 0x01, 0x00});
    BOOST_CHECK_THROW(dobbscoin::DecodeHeaderWithBudget(noncanonical, 1024), std::ios_base::failure);

    // Raw stream parsing leaves trailing bytes for its caller, as in source;
    // the explicit local boundary wrapper rejects them.
    auto trailing = flagged;
    trailing.push_back(0x00);
    DataStream raw_stream{std::span<const unsigned char>{trailing}};
    CBlockHeader raw_decoded;
    raw_stream >> raw_decoded;
    BOOST_CHECK(!raw_stream.empty());
    BOOST_CHECK_THROW(dobbscoin::DecodeHeaderWithBudget(trailing, 1024), std::ios_base::failure);

    // A successful unflagged read clears a prior in-memory proof.
    const auto unflagged = ParseHex(std::string{dobbscoin_test_vectors::UNFLAGGED_CHILD_HEX});
    BOOST_CHECK(destination.GetAuxpow());
    dobbscoin::DecodeHeaderWithBudget(std::span<const unsigned char>{unflagged}, unflagged.size(), destination);
    BOOST_CHECK(!destination.GetAuxpow());
}

BOOST_AUTO_TEST_CASE(flagged_serialization_requires_complete_immutable_proof)
{
    CBlockHeader missing_proof = MakeChild(false);
    missing_proof.nVersion |= CPureBlockHeader::VERSION_AUXPOW;
    BOOST_CHECK_THROW(SerializeBytes(missing_proof), std::ios_base::failure);

    CAuxPow missing_transaction = MakeProof(0, 0);
    missing_transaction.tx.reset();
    CBlockHeader missing_tx_header = MakeChild(false);
    missing_tx_header.SetAuxpow(std::move(missing_transaction));
    BOOST_CHECK_THROW(SerializeBytes(missing_tx_header), std::ios_base::failure);

    CAuxPow mutable_proof = MakeProof(2, 3);
    uint256* retained_vector_alias = mutable_proof.vChainMerkleBranch.data();
    CBlockHeader frozen = MakeChild(false);
    frozen.SetAuxpow(std::move(mutable_proof));
    const auto before = SerializeBytes(frozen);
    const auto frozen_proof = frozen.GetAuxpow();
    CBlockHeader frozen_copy = frozen;
    retained_vector_alias[0] = Filled(0xe0);
    BOOST_CHECK(frozen.GetAuxpow() == frozen_proof);
    BOOST_CHECK(frozen_copy.GetAuxpow() == frozen_proof);
    BOOST_CHECK_EQUAL(frozen.GetAuxpow()->nIndex, 0x12345678);
    BOOST_CHECK_EQUAL(frozen.GetAuxpow()->vChainMerkleBranch.size(), 3U);
    BOOST_CHECK(frozen.GetAuxpow()->vChainMerkleBranch[0] == Filled(0x60));
    BOOST_CHECK(SerializeBytes(frozen) == before);

    CBlockHeader moved = std::move(frozen);
    BOOST_CHECK(moved.GetAuxpow() == frozen_copy.GetAuxpow());
    BOOST_CHECK(SerializeBytes(moved) == before);
}

BOOST_AUTO_TEST_SUITE_END()
