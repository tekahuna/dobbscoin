// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2024 The Dogecoin Core developers
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DOBBSCOIN_HEADER_VERSION_H
#define BITCOIN_CONSENSUS_DOBBSCOIN_HEADER_VERSION_H

#include <cstdint>

namespace consensus {

/** Dobbscoin's source header layout: [chain ID:16][reserved:7][auxpow:1][base:8]. */
static constexpr int32_t DOBBSCOIN_VERSION_AUXPOW{1 << 8};
static constexpr int32_t DOBBSCOIN_VERSION_CHAIN_START{1 << 16};
static constexpr int32_t DOBBSCOIN_AUXPOW_CHAIN_ID{0x00B0};

/** Match CPureBlockHeader::GetBaseVersion, including signed remainder semantics. */
constexpr int32_t GetDobbscoinBaseVersion(int32_t version)
{
    return version % DOBBSCOIN_VERSION_AUXPOW;
}

/** Match CPureBlockHeader::GetChainId, including signed right-shift behavior. */
constexpr int32_t GetDobbscoinChainId(int32_t version)
{
    return version >> 16;
}

/** Match CPureBlockHeader::IsAuxpow. Reserved bits have no meaning here. */
constexpr bool IsDobbscoinAuxpow(int32_t version)
{
    return (version & DOBBSCOIN_VERSION_AUXPOW) != 0;
}

enum class DobbscoinHeaderVersionResult {
    CONTEXT_RULES_OK,
    PREMATURE_AUXPOW,
    PREMATURE_CHAIN_ID,
    BAD_CHAIN_ID,
};

/** Evaluate only the contextual AuxPoW activation guard in Dobbscoin v0.14.0
 * ContextualCheckBlockHeader (main.cpp:2713-29).
 *
 * This does not perform stateless PoW, the preceding contextual difficulty
 * check, or any timestamp/checkpoint rules. The caller must also preserve the
 * source's exact-genesis bypass before invoking this guard. CONTEXT_RULES_OK
 * means only that this guard accepts the version at this height; it is not a
 * statement that the header or block is valid.
 */
constexpr DobbscoinHeaderVersionResult CheckDobbscoinHeaderVersion(
    int32_t version, int height, int auxpow_activation_height)
{
    if (height < auxpow_activation_height) {
        if (IsDobbscoinAuxpow(version)) {
            return DobbscoinHeaderVersionResult::PREMATURE_AUXPOW;
        }
        if (GetDobbscoinChainId(version) != 0) {
            return DobbscoinHeaderVersionResult::PREMATURE_CHAIN_ID;
        }
    } else if (GetDobbscoinChainId(version) != DOBBSCOIN_AUXPOW_CHAIN_ID) {
        return DobbscoinHeaderVersionResult::BAD_CHAIN_ID;
    }
    return DobbscoinHeaderVersionResult::CONTEXT_RULES_OK;
}

} // namespace consensus

#endif // BITCOIN_CONSENSUS_DOBBSCOIN_HEADER_VERSION_H
