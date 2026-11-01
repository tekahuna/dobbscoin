// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 Vince Durham
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/dobbscoin_auxpow_commitment.h>
#include <test/data/dobbscoin_auxpow_commitment_vectors.h>

#include <streams.h>
#include <util/strencodings.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dobbscoin_auxpow_commitment_tests)

namespace {
using dobbscoin::AuxPowCommitmentFailure;
using dobbscoin::CAuxPow;

constexpr int CHILD_CHAIN_ID{176};
constexpr std::array<unsigned char, 4> MERGED_MINING_HEADER{
    0xfa, 0xbe, static_cast<unsigned char>('m'), static_cast<unsigned char>('m')};

uint256 SmallUint256(uint32_t value)
{
    uint256 result;
    for (unsigned int i = 0; i < 4; ++i) result.begin()[i] = static_cast<unsigned char>(value >> (8 * i));
    return result;
}

const uint256 CHILD_HASH{SmallUint256(12345)};

CAuxPow DecodeProof(std::string_view hex)
{
    const std::vector<unsigned char> bytes{ParseHex(std::string{hex})};
    DataStream stream{std::span<const unsigned char>{bytes}};
    CAuxPow proof;
    stream >> proof;
    if (!stream.empty()) throw std::ios_base::failure("Trailing bytes in source AuxPoW test fixture");
    return proof;
}

std::vector<unsigned char> SerializeProof(const CAuxPow& proof)
{
    DataStream stream{};
    stream << proof;
    const std::string raw{stream.str()};
    return {raw.begin(), raw.end()};
}

CAuxPow H3Proof()
{
    return DecodeProof(dobbscoin_test_vectors::AUXPOW_H3_WIRE_HEX);
}

CAuxPow H30Proof()
{
    return DecodeProof(dobbscoin_test_vectors::AUXPOW_H30_WIRE_HEX);
}

void RecomputeParentMerkleRoot(CAuxPow& proof)
{
    BOOST_REQUIRE(proof.tx);
    proof.parentBlock.hashMerkleRoot = dobbscoin::CheckAuxPowMerkleBranch(
        proof.tx->GetHash().ToUint256(), proof.vMerkleBranch, proof.nIndex);
}

std::vector<unsigned char> ScriptBytes(const CAuxPow& proof)
{
    BOOST_REQUIRE(proof.tx);
    BOOST_REQUIRE(!proof.tx->vin.empty());
    const CScript& script{proof.tx->vin[0].scriptSig};
    return {script.begin(), script.end()};
}

void ReplaceCoinbaseScript(CAuxPow& proof, const std::vector<unsigned char>& bytes)
{
    BOOST_REQUIRE(proof.tx);
    BOOST_REQUIRE(!proof.tx->vin.empty());
    CMutableTransaction transaction{*proof.tx};
    CScript& script{transaction.vin[0].scriptSig};
    script.clear();
    for (const unsigned char byte : bytes) script.push_back(byte);
    proof.tx = MakeTransactionRef(std::move(transaction));
    RecomputeParentMerkleRoot(proof);
}

std::vector<unsigned char> ChainRootBytes(const CAuxPow& proof)
{
    uint256 root{dobbscoin::CheckAuxPowMerkleBranch(CHILD_HASH,
                                                   proof.vChainMerkleBranch,
                                                   proof.nChainIndex)};
    std::vector<unsigned char> bytes{root.begin(), root.end()};
    std::reverse(bytes.begin(), bytes.end());
    return bytes;
}

size_t FindSequence(const std::vector<unsigned char>& bytes,
                    const std::vector<unsigned char>& needle)
{
    const auto position{std::search(bytes.begin(), bytes.end(), needle.begin(), needle.end())};
    return position == bytes.end() ? bytes.size() : static_cast<size_t>(position - bytes.begin());
}

size_t FindChainRoot(const CAuxPow& proof, const std::vector<unsigned char>& script)
{
    return FindSequence(script, ChainRootBytes(proof));
}

void WriteLE32(std::vector<unsigned char>& bytes, size_t offset, uint32_t value)
{
    BOOST_REQUIRE_LE(offset + 4, bytes.size());
    for (unsigned int i = 0; i < 4; ++i) {
        bytes[offset + i] = static_cast<unsigned char>(value >> (8 * i));
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(source_h3_and_h30_proofs_pass_commitment_only)
{
    const auto h3_wire{ParseHex(std::string{dobbscoin_test_vectors::AUXPOW_H3_WIRE_HEX})};
    const auto h30_wire{ParseHex(std::string{dobbscoin_test_vectors::AUXPOW_H30_WIRE_HEX})};
    CAuxPow h3{H3Proof()};
    CAuxPow h30{H30Proof()};

    BOOST_CHECK_EQUAL(SerializeProof(h3).size(), h3_wire.size());
    BOOST_CHECK(SerializeProof(h3) == h3_wire);
    BOOST_CHECK_EQUAL(SerializeProof(h30).size(), h30_wire.size());
    BOOST_CHECK(SerializeProof(h30) == h30_wire);
    BOOST_CHECK_EQUAL(h3.vChainMerkleBranch.size(), 3U);
    BOOST_CHECK_EQUAL(h3.nChainIndex, 5);
    BOOST_CHECK_EQUAL(h30.vChainMerkleBranch.size(), 30U);
    BOOST_CHECK_EQUAL(h30.nChainIndex, 514079309);
    BOOST_CHECK_EQUAL(dobbscoin::GetAuxPowExpectedIndex(7, CHILD_CHAIN_ID, 3), 5);
    BOOST_CHECK_EQUAL(dobbscoin::GetAuxPowExpectedIndex(7, CHILD_CHAIN_ID, 30), 514079309);

    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(h3, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(h30, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);
}

BOOST_AUTO_TEST_CASE(source_failure_order_and_accepted_unchecked_parent_fields)
{
    CAuxPow proof{H3Proof()};

    // Source rejects a nonzero parent-transaction index before later failures.
    proof.nIndex = 1;
    proof.parentBlock.nVersion = (proof.parentBlock.nVersion & 0x0000ffff) | (CHILD_CHAIN_ID << 16);
    proof.vChainMerkleBranch.resize(31, uint256{9});
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NOT_A_GENERATE);

    proof.nIndex = 0;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::PARENT_HAS_SAME_CHAIN_ID);

    proof.parentBlock.nVersion = 5 | (42 << 16);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::CHAIN_MERKLE_BRANCH_TOO_LONG);

    // v0.14 check() does not compare hashBlock, validate coinbase semantics,
    // or cap the parent-transaction Merkle branch. Keep those facts explicit.
    proof = H3Proof();
    proof.hashBlock = SmallUint256(999);
    CMutableTransaction non_coinbase{*proof.tx};
    non_coinbase.vin[0].prevout.hash = Txid::FromUint256(SmallUint256(1));
    non_coinbase.vin[0].prevout.n = 0;
    proof.tx = MakeTransactionRef(std::move(non_coinbase));
    for (unsigned int i = 0; i < 31; ++i) proof.vMerkleBranch.emplace_back(i + 1);
    RecomputeParentMerkleRoot(proof);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);
}

BOOST_AUTO_TEST_CASE(parent_and_chain_merkle_commitments)
{
    CAuxPow proof{H3Proof()};
    proof.parentBlock.hashMerkleRoot.begin()[0] ^= 0x01;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::PARENT_MERKLE_ROOT_INCORRECT);

    proof = H30Proof();
    proof.vMerkleBranch[0].begin()[0] ^= 0x01;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::PARENT_MERKLE_ROOT_INCORRECT);

    proof = H3Proof();
    proof.vChainMerkleBranch[0].begin()[0] ^= 0x01;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MISSING_CHAIN_MERKLE_ROOT);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(H3Proof(), SmallUint256(12346), CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MISSING_CHAIN_MERKLE_ROOT);

    proof = H3Proof();
    proof.vChainMerkleBranch.resize(31, uint256{7});
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::CHAIN_MERKLE_BRANCH_TOO_LONG);
}

BOOST_AUTO_TEST_CASE(coinbase_input_and_magic_header_rules)
{
    CAuxPow proof{H3Proof()};
    CMutableTransaction no_inputs{*proof.tx};
    no_inputs.vin.clear();
    proof.tx = MakeTransactionRef(std::move(no_inputs));
    RecomputeParentMerkleRoot(proof);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::COINBASE_HAS_NO_INPUTS);

    proof = H3Proof();
    std::vector<unsigned char> script{ScriptBytes(proof)};
    const auto header{std::search(script.begin(), script.end(), MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end())};
    BOOST_REQUIRE(header != script.end());
    script.erase(header, header + MERGED_MINING_HEADER.size());
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);

    script = ScriptBytes(proof);
    script.insert(script.begin(), 21, 0xaa);
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::LEGACY_ROOT_STARTS_TOO_LATE);

    proof = H3Proof();
    script = ScriptBytes(proof);
    const std::vector<unsigned char> header_bytes{MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end()};
    const size_t header_position{FindSequence(script, header_bytes)};
    BOOST_REQUIRE_LT(header_position, script.size());
    script.insert(script.begin() + header_position + MERGED_MINING_HEADER.size(), 0x00);
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MERGED_MINING_HEADER_NOT_IMMEDIATELY_BEFORE_ROOT);

    proof = H3Proof();
    script = ScriptBytes(proof);
    script.insert(script.end(), MERGED_MINING_HEADER.begin(), MERGED_MINING_HEADER.end());
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MULTIPLE_MERGED_MINING_HEADERS);

    proof = H3Proof();
    script = ScriptBytes(proof);
    const size_t root_position{FindChainRoot(proof, script)};
    BOOST_REQUIRE_LT(root_position, script.size());
    script[root_position] ^= 0x01;
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MISSING_CHAIN_MERKLE_ROOT);
}

BOOST_AUTO_TEST_CASE(tree_size_nonce_index_and_truncated_commitment)
{
    CAuxPow proof{H3Proof()};
    std::vector<unsigned char> script{ScriptBytes(proof)};
    size_t root_position{FindChainRoot(proof, script)};
    BOOST_REQUIRE_LT(root_position, script.size());

    auto truncated{script};
    truncated.resize(root_position + 32 + 7);
    ReplaceCoinbaseScript(proof, truncated);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MISSING_TREE_SIZE_AND_NONCE);

    proof = H3Proof();
    script = ScriptBytes(proof);
    root_position = FindChainRoot(proof, script);
    WriteLE32(script, root_position + 32, 7);
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::CHAIN_MERKLE_BRANCH_SIZE_MISMATCH);

    proof = H3Proof();
    script = ScriptBytes(proof);
    root_position = FindChainRoot(proof, script);
    WriteLE32(script, root_position + 32 + 4, 10);
    ReplaceCoinbaseScript(proof, script);
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::WRONG_CHAIN_INDEX);

    proof = H3Proof();
    ++proof.nChainIndex;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::MISSING_CHAIN_MERKLE_ROOT);
}

BOOST_AUTO_TEST_CASE(parent_and_child_pow_are_outside_commitment_check)
{
    const CAuxPow proof{H3Proof()};
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(proof, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);

    // Mutating parent nBits/nonce does not change commitment validity. The
    // caller must separately compare the parent's Scrypt hash with child nBits.
    CAuxPow changed_parent_work{proof};
    changed_parent_work.parentBlock.nBits ^= 1;
    changed_parent_work.parentBlock.nNonce += 1;
    BOOST_CHECK(dobbscoin::CheckAuxPowCommitment(changed_parent_work, CHILD_HASH, CHILD_CHAIN_ID) == AuxPowCommitmentFailure::NONE);
}

BOOST_AUTO_TEST_SUITE_END()
