// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2016 Daniel Kraft
// Copyright (c) 2014-2024 The Dogecoin Core developers
// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_H
#define BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_H

#include <consensus/dobbscoin_header_version.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ios>
#include <memory>
#include <span>
#include <utility>
#include <vector>

namespace dobbscoin {

/** The pure 80-byte six-field header used for Dobbscoin block identity and PoW. */
class CPureBlockHeader
{
public:
    static constexpr int32_t VERSION_AUXPOW{consensus::DOBBSCOIN_VERSION_AUXPOW};
    static constexpr int32_t VERSION_CHAIN_START{consensus::DOBBSCOIN_VERSION_CHAIN_START};

    int32_t nVersion{0};
    uint256 hashPrevBlock{};
    uint256 hashMerkleRoot{};
    uint32_t nTime{0};
    uint32_t nBits{0};
    uint32_t nNonce{0};

    SERIALIZE_METHODS(CPureBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }

    int32_t GetBaseVersion() const { return consensus::GetDobbscoinBaseVersion(nVersion); }
    int32_t GetChainId() const { return consensus::GetDobbscoinChainId(nVersion); }
    bool IsAuxpow() const { return consensus::IsDobbscoinAuxpow(nVersion); }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    uint256 GetHash() const
    {
        HashWriter hasher{};
        hasher << *this;
        return hasher.GetHash();
    }

    uint256 GetPoWHash() const
    {
        DataStream serialized{};
        serialized << *this;
        if (serialized.size() != 80) throw std::ios_base::failure("Dobbscoin pure header is not 80 bytes");

        std::array<unsigned char, 80> bytes{};
        std::memcpy(bytes.data(), serialized.data(), bytes.size());
        const auto digest{Scrypt1024_1_1_256(bytes)};
        uint256 hash;
        std::copy(digest.begin(), digest.end(), hash.begin());
        return hash;
    }
};

/** Source-field-order AuxPoW proof. The parent header is pure to avoid recursion. */
class CAuxPow
{
public:
    CTransactionRef tx;
    uint256 hashBlock{};
    std::vector<uint256> vMerkleBranch;
    int32_t nIndex{0};
    std::vector<uint256> vChainMerkleBranch;
    int32_t nChainIndex{0};
    CPureBlockHeader parentBlock;

    CAuxPow() = default;
    explicit CAuxPow(CTransactionRef parent_coinbase) : tx{std::move(parent_coinbase)} {}

    template <typename Stream>
    CAuxPow(deserialize_type, Stream& stream)
    {
        Unserialize(stream);
    }

    SERIALIZE_METHODS(CAuxPow, obj)
    {
        // The v0.14 source transaction serializer is legacy-only. Override an
        // enclosing witness-enabled stream for this nested parent coinbase.
        SER_READ(obj, {
            CTransactionRef parent_coinbase;
            s >> TX_NO_WITNESS(parent_coinbase);
            obj.tx = std::move(parent_coinbase);
        });
        SER_WRITE(obj, {
            if (!obj.tx) throw std::ios_base::failure("Dobbscoin AuxPoW has no parent coinbase transaction");
            s << TX_NO_WITNESS(obj.tx);
        });
        READWRITE(obj.hashBlock, obj.vMerkleBranch, obj.nIndex,
                  obj.vChainMerkleBranch, obj.nChainIndex, obj.parentBlock);
    }
};

/** Pure child header plus an immutable optional AuxPoW trailer. */
class CBlockHeader : public CPureBlockHeader
{
private:
    // Keep installation behind SetAuxpow, which deep-copies into a fresh
    // const object so callers cannot retain mutable aliases to its vectors.
    std::shared_ptr<const CAuxPow> m_auxpow;

public:
    static constexpr int32_t CURRENT_VERSION{3};

    CBlockHeader() { SetNull(); }

    void SetNull()
    {
        CPureBlockHeader::SetNull();
        nVersion = CURRENT_VERSION;
        m_auxpow.reset();
    }

    const std::shared_ptr<const CAuxPow>& GetAuxpow() const { return m_auxpow; }

    SERIALIZE_METHODS(CBlockHeader, obj)
    {
        READWRITE(AsBase<CPureBlockHeader>(obj));
        SER_READ(obj, {
            if (obj.IsAuxpow()) {
                std::shared_ptr<const CAuxPow> decoded_proof;
                s >> decoded_proof;
                if (!decoded_proof || !decoded_proof->tx) {
                    throw std::ios_base::failure("Dobbscoin AuxPoW header has no complete proof");
                }
                obj.m_auxpow = std::move(decoded_proof);
            } else {
                obj.m_auxpow.reset();
            }
        });
        SER_WRITE(obj, {
            if (obj.IsAuxpow()) {
                if (!obj.m_auxpow) throw std::ios_base::failure("Dobbscoin AuxPoW flag has no proof");
                if (!obj.m_auxpow->tx) throw std::ios_base::failure("Dobbscoin AuxPoW has no parent coinbase transaction");
                s << obj.m_auxpow;
            }
        });
    }

    void SetAuxpow(const CAuxPow& proof)
    {
        m_auxpow = std::make_shared<const CAuxPow>(proof);
        nVersion |= VERSION_AUXPOW;
    }

    void ClearAuxpow()
    {
        m_auxpow.reset();
        nVersion &= ~VERSION_AUXPOW;
    }
};

/** Decode at an explicit local boundary: cap the complete byte string and require EOF.
 *
 * Generic stream serialization deliberately has no AuxPoW-specific byte or
 * branch-count limit. This opt-in wrapper adds a caller-chosen byte budget and
 * strict trailing-byte rejection; those are local parser policy, not source
 * consensus rules or wire restrictions. The byte budget applies to the input
 * buffer size only: generic vector parsing may still reserve a 5 MiB batch
 * after reading a large CompactSize declaration. Do not treat this helper as
 * a complete memory bound or use it on untrusted network input before a
 * separately reviewed vector/allocation policy exists.
 */
inline CBlockHeader DecodeHeaderWithBudget(std::span<const uint8_t> bytes, size_t max_encoded_bytes)
{
    if (bytes.size() > max_encoded_bytes) {
        throw std::ios_base::failure("Dobbscoin header exceeds caller-provided decode budget");
    }
    DataStream stream{bytes};
    CBlockHeader decoded;
    stream >> decoded;
    if (!stream.empty()) throw std::ios_base::failure("Trailing bytes after Dobbscoin header");
    return decoded;
}

/** Commit a decoded header only after the complete bounded parse succeeds. */
inline void DecodeHeaderWithBudget(std::span<const uint8_t> bytes,
                                   size_t max_encoded_bytes,
                                   CBlockHeader& destination)
{
    CBlockHeader decoded{DecodeHeaderWithBudget(bytes, max_encoded_bytes)};
    destination = std::move(decoded);
}

} // namespace dobbscoin

#endif // BITCOIN_PRIMITIVES_DOBBSCOIN_AUXPOW_H
