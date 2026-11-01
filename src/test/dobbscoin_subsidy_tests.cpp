// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/amount.h>
#include <consensus/dobbscoin_subsidy.h>

#include <array>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dobbscoin_subsidy_tests)

namespace {
struct SubsidyVector {
    int height;
    CAmount expected;
};

constexpr bool MAINNET_ALLOW_MIN_DIFFICULTY{false};
constexpr bool TESTLIKE_ALLOW_MIN_DIFFICULTY{true};
} // namespace

BOOST_AUTO_TEST_CASE(source_mainnet_subsidy_boundaries)
{
    // Source-derived vectors cover the 68,425 one-block exception, the
    // 68,426-69,790 return to 50 coins, the sustained 69,791 reward, each
    // halving boundary, and the later fixed 1.5-coin reward.
    constexpr std::array<SubsidyVector, 24> vectors{{
        {0, 50 * COIN},
        {68424, 50 * COIN},
        {68425, 10 * COIN},
        {68426, 50 * COIN},
        {69790, 50 * COIN},
        {69791, 10 * COIN},
        {69792, 10 * COIN},
        {209999, 10 * COIN},
        {210000, 5 * COIN},
        {210001, 5 * COIN},
        {419999, 5 * COIN},
        {420000, 5 * COIN / 2},
        {420001, 5 * COIN / 2},
        {629999, 5 * COIN / 2},
        {630000, 5 * COIN / 4},
        {630001, 5 * COIN / 4},
        {839999, 5 * COIN / 4},
        {840000, 5 * COIN / 8},
        {840001, 5 * COIN / 8},
        {951752, 5 * COIN / 8},
        {951753, 3 * COIN / 2},
        {951754, 3 * COIN / 2},
        {1050000, 3 * COIN / 2},
        {2100000, 3 * COIN / 2},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(consensus::GetDobbscoinBlockValue(vector.height, 0, MAINNET_ALLOW_MIN_DIFFICULTY), vector.expected);
    }
}

BOOST_AUTO_TEST_CASE(source_testlike_subsidy_boundaries)
{
    constexpr std::array<SubsidyVector, 7> vectors{{
        {0, 50 * COIN},
        {204, 50 * COIN},
        {205, 9 * COIN},
        {206, 50 * COIN},
        {349, 50 * COIN},
        {350, 10 * COIN},
        {351, 10 * COIN},
    }};

    for (const auto& vector : vectors) {
        BOOST_CHECK_EQUAL(consensus::GetDobbscoinBlockValue(vector.height, 0, TESTLIKE_ALLOW_MIN_DIFFICULTY), vector.expected);
    }
}

BOOST_AUTO_TEST_CASE(source_fees_are_added_after_subsidy)
{
    constexpr CAmount fees{12345678};
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBlockValue(68425, fees, MAINNET_ALLOW_MIN_DIFFICULTY), 10 * COIN + fees);
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBlockValue(205, fees, TESTLIKE_ALLOW_MIN_DIFFICULTY), 9 * COIN + fees);
}

BOOST_AUTO_TEST_SUITE_END()
