// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2011 Vince Durham
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_COMMITMENT_H
#define BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_COMMITMENT_H

#include <hash.h>
#include <primitives/dobbscoin_auxpow.h>
#include <script/script.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <vector>

namespace dobbscoin {

/** First failure from the v0.14 CAuxPow::check commitment algorithm.
 *
 * MISSING_PARENT_COINBASE_REFERENCE describes an incomplete in-memory host
 * object, which cannot be produced by decoding the source wire format. All
 * other values correspond to checks in the pinned source implementation.
 */
enum class AuxPowCommitmentFailure : uint8_t {
    NONE,
    MISSING_PARENT_COINBASE_REFERENCE,
    NOT_A_GENERATE,
    PARENT_HAS_SAME_CHAIN_ID,
    CHAIN_MERKLE_BRANCH_TOO_LONG,
    PARENT_MERKLE_ROOT_INCORRECT,
    COINBASE_HAS_NO_INPUTS,
    MISSING_CHAIN_MERKLE_ROOT,
    MULTIPLE_MERGED_MINING_HEADERS,
    MERGED_MINING_HEADER_NOT_IMMEDIATELY_BEFORE_ROOT,
    LEGACY_ROOT_STARTS_TOO_LATE,
    MISSING_TREE_SIZE_AND_NONCE,
    CHAIN_MERKLE_BRANCH_SIZE_MISMATCH,
    WRONG_CHAIN_INDEX,
};

/** Source getExpectedIndex() arithmetic. Call with h <= 30 as check() does. */
inline int GetAuxPowExpectedIndex(uint32_t nonce, int chain_id, unsigned int height)
{
    uint32_t random{nonce};
    random = random * 1103515245U + 12345U;
    random += static_cast<uint32_t>(chain_id);
    random = random * 1103515245U + 12345U;
    return random % (1U << height);
}

/** Source CheckMerkleBranch() byte ordering and index walk. */
inline uint256 CheckAuxPowMerkleBranch(uint256 hash,
                                      const std::vector<uint256>& branch,
                                      int index)
{
    if (index == -1) return uint256{};

    for (const uint256& sibling : branch) {
        hash = (index & 1) ? Hash(sibling, hash) : Hash(hash, sibling);
        index >>= 1;
    }
    return hash;
}

namespace detail {

template <typename Iterator>
inline uint32_t ReadAuxPowLE32(Iterator bytes)
{
    return uint32_t(bytes[0]) |
           (uint32_t(bytes[1]) << 8) |
           (uint32_t(bytes[2]) << 16) |
           (uint32_t(bytes[3]) << 24);
}

} // namespace detail

/** Check only the v0.14 AuxPoW merkle/coinbase commitment.
 *
 * This mirrors source CAuxPow::check() and deliberately does not check the
 * parent's Scrypt PoW against the child target. It also does not validate the
 * parent block hash, transaction coinbase semantics, or any chain context;
 * callers must keep those checks separate. The source checks the child-chain
 * branch limit here, but does not impose a parent-branch length rule.
 */
inline AuxPowCommitmentFailure CheckAuxPowCommitment(const CAuxPow& proof,
                                                     const uint256& child_hash,
                                                     int child_chain_id)
{
    // Preserve the source's failure order for all wire-representable proofs.
    if (proof.nIndex != 0) return AuxPowCommitmentFailure::NOT_A_GENERATE;
    if (proof.parentBlock.GetChainId() == child_chain_id) {
        return AuxPowCommitmentFailure::PARENT_HAS_SAME_CHAIN_ID;
    }
    if (proof.vChainMerkleBranch.size() > 30) {
        return AuxPowCommitmentFailure::CHAIN_MERKLE_BRANCH_TOO_LONG;
    }
    // A null CTransactionRef is a host representation state absent from the
    // source value-type CAuxPow; fail safely after the source's early guards.
    if (!proof.tx) return AuxPowCommitmentFailure::MISSING_PARENT_COINBASE_REFERENCE;

    const uint256 chain_root = CheckAuxPowMerkleBranch(child_hash,
                                                       proof.vChainMerkleBranch,
                                                       proof.nChainIndex);
    std::array<unsigned char, 32> root_bytes{};
    std::reverse_copy(chain_root.begin(), chain_root.end(), root_bytes.begin());

    // The source carries hashBlock but does not compare it in check().
    if (CheckAuxPowMerkleBranch(proof.tx->GetHash().ToUint256(),
                                proof.vMerkleBranch,
                                proof.nIndex) != proof.parentBlock.hashMerkleRoot) {
        return AuxPowCommitmentFailure::PARENT_MERKLE_ROOT_INCORRECT;
    }

    if (proof.tx->vin.empty()) return AuxPowCommitmentFailure::COINBASE_HAS_NO_INPUTS;

    const CScript& script = proof.tx->vin[0].scriptSig;
    constexpr std::array<unsigned char, 4> merged_mining_header{
        0xfa, 0xbe, static_cast<unsigned char>('m'), static_cast<unsigned char>('m')};

    const auto header = std::search(script.begin(), script.end(),
                                    merged_mining_header.begin(), merged_mining_header.end());
    const auto root = std::search(script.begin(), script.end(), root_bytes.begin(), root_bytes.end());
    if (root == script.end()) return AuxPowCommitmentFailure::MISSING_CHAIN_MERKLE_ROOT;

    if (header != script.end()) {
        if (std::search(header + 1, script.end(),
                        merged_mining_header.begin(), merged_mining_header.end()) != script.end()) {
            return AuxPowCommitmentFailure::MULTIPLE_MERGED_MINING_HEADERS;
        }
        if (header + merged_mining_header.size() != root) {
            return AuxPowCommitmentFailure::MERGED_MINING_HEADER_NOT_IMMEDIATELY_BEFORE_ROOT;
        }
    } else if (root - script.begin() > 20) {
        return AuxPowCommitmentFailure::LEGACY_ROOT_STARTS_TOO_LATE;
    }

    const auto tail = root + root_bytes.size();
    if (script.end() - tail < 8) return AuxPowCommitmentFailure::MISSING_TREE_SIZE_AND_NONCE;

    const uint32_t tree_size = detail::ReadAuxPowLE32(tail);
    const unsigned int height = proof.vChainMerkleBranch.size();
    if (tree_size != (1U << height)) {
        return AuxPowCommitmentFailure::CHAIN_MERKLE_BRANCH_SIZE_MISMATCH;
    }

    const uint32_t nonce = detail::ReadAuxPowLE32(tail + 4);
    if (proof.nChainIndex != GetAuxPowExpectedIndex(nonce, child_chain_id, height)) {
        return AuxPowCommitmentFailure::WRONG_CHAIN_INDEX;
    }

    return AuxPowCommitmentFailure::NONE;
}

} // namespace dobbscoin

#endif // BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_COMMITMENT_H
