// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/scrypt.h>
#include <primitives/block.h>
#include <streams.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <numeric>
#include <string_view>
#include <vector>

BOOST_AUTO_TEST_SUITE(scrypt_tests)

namespace {
using HeaderBytes = std::array<unsigned char, 80>;

void CheckHeaderVector(const HeaderBytes& bytes,
                       std::string_view expected_id,
                       std::string_view expected_scrypt)
{
    CBlockHeader header;
    SpanReader reader{bytes};
    reader >> header;
    BOOST_CHECK(reader.empty());

    BOOST_CHECK_EQUAL(header.GetHash().GetHex(), expected_id);
    BOOST_CHECK_EQUAL(header.GetPoWHash().GetHex(), expected_scrypt);

    std::vector<unsigned char> serialized;
    VectorWriter{serialized, 0, header};
    BOOST_REQUIRE_EQUAL(serialized.size(), bytes.size());
    BOOST_CHECK(std::equal(bytes.begin(), bytes.end(), serialized.begin()));
}

HeaderBytes HeaderBytesFromHex(std::string_view hex)
{
    const auto parsed{ParseHex(hex)};
    BOOST_REQUIRE_EQUAL(parsed.size(), HeaderBytes{}.size());
    HeaderBytes bytes{};
    std::copy(parsed.begin(), parsed.end(), bytes.begin());
    return bytes;
}
} // namespace

BOOST_AUTO_TEST_CASE(dobbscoin_historical_header_13581)
{
    // Source-declared Dobbscoin mainnet header at height 13,581.
    const auto header{HeaderBytesFromHex(
        "020000002076c7b5b0e228d4db4482408b9871c6ffaad98058e6508a4960b17277bc1e64"
        "08d1607578a4dab86ff124ac140acd509868a2ae7c472d393ace8e15b44756989a7a585"
        "3512a7e1c00ef38a4")};
    CheckHeaderVector(header,
                     "6da0ef49eb8e8db7295de58903fb89db839160df7b3dac1dfff9126f561a00d6",
                     "000000000ce83cfd13edeb976461305dea41393dfc9fde27ce49aa055d648139");
}

BOOST_AUTO_TEST_CASE(synthetic_header_hash_vectors)
{
    HeaderBytes zeroes{};
    CheckHeaderVector(zeroes,
                     "14508459b221041eab257d2baaa7459775ba748246c8403609eb708f0e57e74b",
                     "694b3a55a61339b43c01421b13f710e22e33a7eabda1cd48103bb9f376081d16");

    HeaderBytes ascending{};
    std::iota(ascending.begin(), ascending.end(), 0);
    CheckHeaderVector(ascending,
                     "e40105b4d7aff1df002bf704c28f346695527bda3bf62f120705b04f04982c85",
                     "d2a91baa45263cfd16c4fef0fb0776382d0e011ec70530496ef91d801a0a54bc");

    HeaderBytes all_ones{};
    all_ones.fill(0xff);
    CheckHeaderVector(all_ones,
                     "db5d3249b8575a6747ecf89ddd9cf6a78914d281da0b5eaa5f44f1f922bdd00d",
                     "27d13df38beeeb31aceddb5cf577e91574e35e3786547478f9edec149c065352");
}

BOOST_AUTO_TEST_SUITE_END()
