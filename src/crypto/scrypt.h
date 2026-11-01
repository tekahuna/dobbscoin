// Copyright (c) 2026 The Dobbscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CRYPTO_SCRYPT_H
#define BITCOIN_CRYPTO_SCRYPT_H

#include <array>
#include <span>

/** Compute Scrypt with N=1024, r=1, p=1 and a 256-bit output. The canonical
 * 80-byte header is used as both password and salt. */
std::array<unsigned char, 32> Scrypt1024_1_1_256(std::span<const unsigned char, 80> input);

#endif // BITCOIN_CRYPTO_SCRYPT_H
