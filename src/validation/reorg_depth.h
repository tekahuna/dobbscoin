// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_VALIDATION_REORG_DEPTH_H
#define BITCOIN_VALIDATION_REORG_DEPTH_H

#include <chain.h>

namespace validation {

/** Return whether switching from old_tip back to common_fork exceeds the
 * source-derived depth limit. The guard is inactive if either index is null
 * or the old active tip is below the supplied activation height. Callers
 * should evaluate it after selecting the most-work chain; it does not change
 * chain-work ordering. */
inline bool ReorgDepthExceeded(const CBlockIndex* old_tip,
                              const CBlockIndex* common_fork,
                              int activation_height,
                              int max_depth)
{
    return old_tip != nullptr && common_fork != nullptr &&
           old_tip->nHeight >= activation_height &&
           old_tip->nHeight - common_fork->nHeight > max_depth;
}

} // namespace validation

#endif // BITCOIN_VALIDATION_REORG_DEPTH_H
