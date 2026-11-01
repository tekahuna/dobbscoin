// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <validation/reorg_depth.h>

#include <boost/test/unit_test.hpp>

#include <array>

BOOST_AUTO_TEST_SUITE(reorg_depth_tests)

namespace {
constexpr int MAIN_LWMA3_HEIGHT{1'888'808};
constexpr int TESTLIKE_LWMA3_HEIGHT{100};
constexpr int MAX_REORG_DEPTH{100};

struct ReorgDepthVector {
    const char* label;
    int old_tip_height;
    int fork_height;
    int candidate_height;
    bool expected_exceeded;
};

bool ExceedsForHeights(int old_tip_height, int fork_height, int activation_height)
{
    CBlockHeader header;
    CBlockIndex old_tip{header};
    CBlockIndex common_fork{header};
    old_tip.nHeight = old_tip_height;
    common_fork.nHeight = fork_height;
    return validation::ReorgDepthExceeded(&old_tip, &common_fork, activation_height, MAX_REORG_DEPTH);
}

void CheckVector(const ReorgDepthVector& vector)
{
    BOOST_CHECK_MESSAGE(ExceedsForHeights(vector.old_tip_height, vector.fork_height, MAIN_LWMA3_HEIGHT) == vector.expected_exceeded,
                        vector.label << " (candidate height " << vector.candidate_height << ')');
}
} // namespace

BOOST_AUTO_TEST_CASE(source_mainnet_boundary_vectors)
{
    CBlockHeader header;
    CBlockIndex old_tip{header};
    CBlockIndex common_fork{header};

    // The source skips the depth guard if either pointer is null.
    old_tip.nHeight = MAIN_LWMA3_HEIGHT + 101;
    common_fork.nHeight = 0;
    BOOST_CHECK(!validation::ReorgDepthExceeded(nullptr, &common_fork, MAIN_LWMA3_HEIGHT, MAX_REORG_DEPTH));
    BOOST_CHECK(!validation::ReorgDepthExceeded(&old_tip, nullptr, MAIN_LWMA3_HEIGHT, MAX_REORG_DEPTH));

    // Activation is based on the old active tip. The candidate height is
    // recorded in each vector to make clear that it is not part of the rule.
    constexpr std::array<ReorgDepthVector, 5> vectors{{
        {"old tip below activation with depth 101", MAIN_LWMA3_HEIGHT - 1, MAIN_LWMA3_HEIGHT - 102, MAIN_LWMA3_HEIGHT + 1, false},
        {"old tip at activation with depth 101", MAIN_LWMA3_HEIGHT, MAIN_LWMA3_HEIGHT - 101, MAIN_LWMA3_HEIGHT + 1, true},
        {"exactly 100 blocks", MAIN_LWMA3_HEIGHT + 100, MAIN_LWMA3_HEIGHT, MAIN_LWMA3_HEIGHT + 101, false},
        {"exactly 101 blocks", MAIN_LWMA3_HEIGHT + 101, MAIN_LWMA3_HEIGHT, MAIN_LWMA3_HEIGHT + 102, true},
        {"candidate below activation, old tip at activation", MAIN_LWMA3_HEIGHT, MAIN_LWMA3_HEIGHT - 101, MAIN_LWMA3_HEIGHT - 1, true},
    }};

    for (const auto& vector : vectors) {
        CheckVector(vector);
    }
}

BOOST_AUTO_TEST_CASE(source_testlike_activation_boundary)
{
    // At activation, genesis is exactly 100 blocks deep and remains allowed.
    BOOST_CHECK(!ExceedsForHeights(TESTLIKE_LWMA3_HEIGHT, 0, TESTLIKE_LWMA3_HEIGHT));

    // Depth 101 first becomes possible one height after activation.
    BOOST_CHECK(ExceedsForHeights(TESTLIKE_LWMA3_HEIGHT + 1, 0, TESTLIKE_LWMA3_HEIGHT));
}

BOOST_AUTO_TEST_SUITE_END()
