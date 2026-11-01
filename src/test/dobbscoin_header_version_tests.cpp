// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2024 The Dogecoin Core developers
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/dobbscoin_header_version.h>

#include <array>
#include <limits>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(dobbscoin_header_version_tests)

namespace {
using Result = consensus::DobbscoinHeaderVersionResult;

constexpr int MAINNET_AUXPOW_ACTIVATION{2'000'000};
constexpr int TESTLIKE_AUXPOW_ACTIVATION{10};

constexpr int32_t Version(int32_t chain_id, bool auxpow, int32_t base_version, int32_t reserved_bits = 0)
{
    return (chain_id * consensus::DOBBSCOIN_VERSION_CHAIN_START) |
           (auxpow ? consensus::DOBBSCOIN_VERSION_AUXPOW : 0) |
           reserved_bits | base_version;
}
} // namespace

BOOST_AUTO_TEST_CASE(source_activation_height_boundaries)
{
    constexpr std::array<int, 2> activation_heights{{MAINNET_AUXPOW_ACTIVATION, TESTLIKE_AUXPOW_ACTIVATION}};
    for (const int activation_height : activation_heights) {
        // One block before activation, chain ID zero and no flag are required.
        BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(2, activation_height - 1, activation_height) == Result::CONTEXT_RULES_OK);

        // Activation itself requires chain ID 0x00b0 but does not require the
        // AuxPoW flag; a native block can carry the required chain ID.
        BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(
                        Version(consensus::DOBBSCOIN_AUXPOW_CHAIN_ID, false, 2), activation_height, activation_height) ==
                    Result::CONTEXT_RULES_OK);

        // The next block accepts an AuxPoW-marked header with that same ID.
        BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(
                        Version(consensus::DOBBSCOIN_AUXPOW_CHAIN_ID, true, 2), activation_height + 1, activation_height) ==
                    Result::CONTEXT_RULES_OK);
    }
}

BOOST_AUTO_TEST_CASE(source_failure_order_and_optional_postfork_flag)
{
    // Both violations are present, but source checks VERSION_AUXPOW first.
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(Version(1, true, 2), 9, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::PREMATURE_AUXPOW);
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(Version(1, false, 2), 9, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::PREMATURE_CHAIN_ID);

    // After activation either flag state is allowed when the chain ID matches.
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(
                    Version(consensus::DOBBSCOIN_AUXPOW_CHAIN_ID, false, 1), 10, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::CONTEXT_RULES_OK);
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(
                    Version(consensus::DOBBSCOIN_AUXPOW_CHAIN_ID, true, 1), 10, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::CONTEXT_RULES_OK);

    // A correct flag cannot repair the wrong post-fork chain ID.
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(Version(1, true, 2), 10, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::BAD_CHAIN_ID);
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(Version(1, false, 2), 10, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::BAD_CHAIN_ID);
}

BOOST_AUTO_TEST_CASE(source_does_not_reject_reserved_bits)
{
    constexpr int32_t RESERVED_BITS{0x0000FE00};

    // The source guard inspects only the AuxPoW flag and chain ID.
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(Version(0, false, 2, RESERVED_BITS), 9, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::CONTEXT_RULES_OK);
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(
                    Version(consensus::DOBBSCOIN_AUXPOW_CHAIN_ID, false, 2, RESERVED_BITS), 10, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::CONTEXT_RULES_OK);
}

BOOST_AUTO_TEST_CASE(source_signed_version_accessors)
{
    // GetBaseVersion is signed remainder, not a low-byte mask.
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBaseVersion(-1), -1);
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBaseVersion(-257), -1);
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBaseVersion(-255), -255);
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinBaseVersion(Version(0x00B0, true, 2)), 2);

    // GetChainId uses a signed right shift, so negative versions have a
    // negative chain ID under the source's compiler semantics.
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinChainId(-1), -1);
    BOOST_CHECK_EQUAL(consensus::GetDobbscoinChainId(std::numeric_limits<int32_t>::min()), -32768);
    BOOST_CHECK(consensus::IsDobbscoinAuxpow(-1));
    BOOST_CHECK(!consensus::IsDobbscoinAuxpow(2));
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(-1, 9, TESTLIKE_AUXPOW_ACTIVATION) ==
                Result::PREMATURE_AUXPOW);
    BOOST_CHECK(consensus::CheckDobbscoinHeaderVersion(-1, 10, TESTLIKE_AUXPOW_ACTIVATION) == Result::BAD_CHAIN_ID);
}

BOOST_AUTO_TEST_SUITE_END()
