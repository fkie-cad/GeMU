/*
 * xxHash - Fast Hash algorithm
 * Copyright (C) 2012-2016, Yann Collet
 *
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * + Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * + Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * You can contact the author at :
 * - xxHash source repository : https://github.com/Cyan4973/xxHash
 */

#include "qemu/osdep.h"
#include "gemu/xxhash64.h"
#include "qemu/xxhash.h"

// xxHash64 implementation for buffers
// Implements the full algorithm from qemu/xxhash.h for standard-compliant hashes
uint64_t xxhash64_buf(const uint8_t *buf, size_t len) {
    if (buf == NULL) {
        return 0;
    }

    uint64_t h64;
    size_t i = 0;

    // Process 32-byte blocks with 4 parallel accumulators
    if (len >= 32) {
        uint64_t v1 = QEMU_XXHASH_SEED + XXH_PRIME64_1 + XXH_PRIME64_2;
        uint64_t v2 = QEMU_XXHASH_SEED + XXH_PRIME64_2;
        uint64_t v3 = QEMU_XXHASH_SEED;
        uint64_t v4 = QEMU_XXHASH_SEED - XXH_PRIME64_1;

        do {
            uint64_t k1, k2, k3, k4;
            memcpy(&k1, buf + i, 8);
            memcpy(&k2, buf + i + 8, 8);
            memcpy(&k3, buf + i + 16, 8);
            memcpy(&k4, buf + i + 24, 8);

            v1 = XXH64_round(v1, k1);
            v2 = XXH64_round(v2, k2);
            v3 = XXH64_round(v3, k3);
            v4 = XXH64_round(v4, k4);
        } while ((i += 32) <= len - 32);

        h64 = XXH64_mergerounds(v1, v2, v3, v4);
    } else {
        h64 = QEMU_XXHASH_SEED + XXH_PRIME64_5;
    }

    h64 += len;

    // Process remaining 8-byte chunks
    for (; i + 8 <= len; i += 8) {
        uint64_t k1;
        memcpy(&k1, buf + i, 8);
        h64 ^= XXH64_round(0, k1);
        h64 = rol64(h64, 27) * XXH_PRIME64_1 + XXH_PRIME64_4;
    }

    // Process remaining 4-byte chunk
    if (i + 4 <= len) {
        uint32_t k1;
        memcpy(&k1, buf + i, 4);
        h64 ^= (uint64_t)k1 * XXH_PRIME64_1;
        h64 = rol64(h64, 23) * XXH_PRIME64_2 + XXH_PRIME64_3;
        i += 4;
    }

    // Process remaining bytes
    for (; i < len; i++) {
        h64 ^= buf[i] * XXH_PRIME64_5;
        h64 = rol64(h64, 11) * XXH_PRIME64_1;
    }

    return XXH64_avalanche(h64);
}