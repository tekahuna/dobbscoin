// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_DOBBSCOIN_SUBSIDY_H
#define BITCOIN_CONSENSUS_DOBBSCOIN_SUBSIDY_H

#include <consensus/amount.h>

namespace consensus {

/** Return the source-derived Dobbscoin coinbase ceiling for a block height.
 *
 * This helper follows the branch order and exceptions in Dobbscoin v0.14.0
 * GetBlockValue. The caller supplies the network's AllowMinDifficultyBlocks
 * value so this calculation stays standalone and testable. It is not yet
 * connected to runtime block validation.
 */
inline CAmount GetDobbscoinBlockValue(int height, CAmount fees, bool allow_min_difficulty_blocks)
{
    CAmount subsidy{50 * COIN};
    if (allow_min_difficulty_blocks && height >= 350) {
        subsidy = 10 * COIN;
    }
    if (allow_min_difficulty_blocks && height == 205) {
        subsidy = 9 * COIN;
    }
    if (!allow_min_difficulty_blocks && height == 68425) {
        subsidy = 10 * COIN;
    }
    if (!allow_min_difficulty_blocks && height >= 69791) {
        subsidy = 10 * COIN;
    }

    // The source's fixed-subsidy rule takes effect after this inclusive
    // halving range; preserve its integer right-shift behavior exactly.
    if (!allow_min_difficulty_blocks && height <= 951752) {
        subsidy >>= (height / 210000);
    }
    if (!allow_min_difficulty_blocks && height >= 951753) {
        subsidy = 3 * COIN / 2;
    }

    // Preserve the source's final minimum-reward fallback and fee addition.
    if (subsidy <= COIN / 2) {
        subsidy = 3 * COIN / 2;
    }
    return subsidy + fees;
}

} // namespace consensus

#endif // BITCOIN_CONSENSUS_DOBBSCOIN_SUBSIDY_H
