// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <crypto/common.h>
#include <crypto/scrypt.h>
#include <hash.h>
#include <tinyformat.h>

#include <algorithm>
#include <array>
#include <memory>
#include <span>
#include <sstream>

namespace {
/** Serialize only the six consensus header fields, independently of any
 * variable-length data that may later be attached to a header. */
std::array<unsigned char, 80> SerializePureBlockHeader(const CBlockHeader& header)
{
    std::array<unsigned char, 80> serialized{};
    WriteLE32(serialized.data(), static_cast<uint32_t>(header.nVersion));
    std::copy(header.hashPrevBlock.begin(), header.hashPrevBlock.end(), serialized.begin() + 4);
    std::copy(header.hashMerkleRoot.begin(), header.hashMerkleRoot.end(), serialized.begin() + 36);
    WriteLE32(serialized.data() + 68, header.nTime);
    WriteLE32(serialized.data() + 72, header.nBits);
    WriteLE32(serialized.data() + 76, header.nNonce);
    return serialized;
}
} // namespace

uint256 CBlockHeader::GetHash() const
{
    return Hash(SerializePureBlockHeader(*this));
}

uint256 CBlockHeader::GetPoWHash() const
{
    const auto serialized{SerializePureBlockHeader(*this)};
    const auto hash{Scrypt1024_1_1_256(serialized)};
    uint256 result;
    std::copy(hash.begin(), hash.end(), result.begin());
    return result;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
