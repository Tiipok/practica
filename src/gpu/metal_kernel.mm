#import "gpu/metal_kernel.h"
#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
#include <iostream>
#include <cstring>

namespace gpu {

static NSString* kAesKernelSource = @R"(
#include <metal_stdlib>
using namespace metal;

// --- SHA1 ---

constant uint kSHA1[4] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};

inline uint rotl32(uint x, uint n) {
    return (x << n) | (x >> (32 - n));
}

void sha1_block(thread uint* h, thread const uint* w) {
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];

    for (int i = 0; i < 80; i++) {
        uint f, k;
        if (i < 20) {
            f = (b & c) | (~b & d);
            k = kSHA1[0];
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = kSHA1[1];
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = kSHA1[2];
        } else {
            f = b ^ c ^ d;
            k = kSHA1[3];
        }
        uint temp = rotl32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = rotl32(b, 30); b = a; a = temp;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

inline uint bswap32(uint x) {
    return ((x >> 24) & 0xFF) | ((x >> 8) & 0xFF00) |
           ((x << 8) & 0xFF0000) | ((x << 24) & 0xFF000000);
}

void sha1_msg(thread uint* h, thread const uchar* msg, uint msg_len) {
    uint padded[16];
    uint total_bits = msg_len * 8;

    for (uint pos = 0; pos < msg_len; pos += 64) {
        uint chunk = min(64u, msg_len - pos);
        for (uint i = 0; i < 16; i++) padded[i] = 0;
        for (uint i = 0; i < chunk; i++) {
            padded[i / 4] |= ((uint)msg[pos + i]) << (24 - 8 * (i % 4));
        }

        if (chunk < 56) {
            padded[chunk / 4] |= 0x80u << (24 - 8 * (chunk % 4));
            if (pos + 64 >= ((msg_len + 8 + 63) / 64) * 64) {
                padded[14] = 0;
                padded[15] = total_bits;
            }
            uint w[80];
            for (int i = 0; i < 16; i++) w[i] = padded[i];
            for (int i = 16; i < 80; i++)
                w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            sha1_block(h, w);
        } else {
            uint w[80];
            for (int i = 0; i < 16; i++) w[i] = padded[i];
            for (int i = 16; i < 80; i++)
                w[i] = rotl32(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
            sha1_block(h, w);
        }
    }
}

void hmac_sha1(thread uchar* out,
               thread const uchar* key, uint key_len,
               thread const uchar* msg, uint msg_len) {
    uchar key_block[64];
    for (uint i = 0; i < 64; i++) key_block[i] = 0;

    if (key_len > 64) {
        uint h[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
        sha1_msg(h, key, key_len);
        key_block[0] = (h[0] >> 24) & 0xFF; key_block[1] = (h[0] >> 16) & 0xFF;
        key_block[2] = (h[0] >> 8) & 0xFF;  key_block[3] = h[0] & 0xFF;
        key_block[4] = (h[1] >> 24) & 0xFF; key_block[5] = (h[1] >> 16) & 0xFF;
        key_block[6] = (h[1] >> 8) & 0xFF;  key_block[7] = h[1] & 0xFF;
        key_block[8] = (h[2] >> 24) & 0xFF; key_block[9] = (h[2] >> 16) & 0xFF;
        key_block[10] = (h[2] >> 8) & 0xFF; key_block[11] = h[2] & 0xFF;
        key_block[12] = (h[3] >> 24) & 0xFF; key_block[13] = (h[3] >> 16) & 0xFF;
        key_block[14] = (h[3] >> 8) & 0xFF; key_block[15] = h[3] & 0xFF;
        key_block[16] = (h[4] >> 24) & 0xFF; key_block[17] = (h[4] >> 16) & 0xFF;
        key_block[18] = (h[4] >> 8) & 0xFF; key_block[19] = h[4] & 0xFF;
    } else {
        for (uint i = 0; i < key_len; i++) key_block[i] = key[i];
    }

    uchar ipad[64], opad[64];
    for (uint i = 0; i < 64; i++) { ipad[i] = key_block[i] ^ 0x36; opad[i] = key_block[i] ^ 0x5C; }

    uchar inner_msg[64 + 64];
    for (uint i = 0; i < 64; i++) inner_msg[i] = ipad[i];
    for (uint i = 0; i < msg_len; i++) inner_msg[64 + i] = msg[i];
    uint h_inner[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    sha1_msg(h_inner, inner_msg, 64 + msg_len);

    uchar inner_hash[20];
    for (int i = 0; i < 5; i++) {
        inner_hash[i*4]   = (h_inner[i] >> 24) & 0xFF;
        inner_hash[i*4+1] = (h_inner[i] >> 16) & 0xFF;
        inner_hash[i*4+2] = (h_inner[i] >> 8) & 0xFF;
        inner_hash[i*4+3] = h_inner[i] & 0xFF;
    }

    uchar outer_msg[64 + 20];
    for (uint i = 0; i < 64; i++) outer_msg[i] = opad[i];
    for (uint i = 0; i < 20; i++) outer_msg[64 + i] = inner_hash[i];
    uint h_outer[5] = {0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0};
    sha1_msg(h_outer, outer_msg, 64 + 20);

    for (int i = 0; i < 5; i++) {
        out[i*4]   = (h_outer[i] >> 24) & 0xFF;
        out[i*4+1] = (h_outer[i] >> 16) & 0xFF;
        out[i*4+2] = (h_outer[i] >> 8) & 0xFF;
        out[i*4+3] = h_outer[i] & 0xFF;
    }
}

void pbkdf2_hmac_sha1(thread uchar* dk, uint dk_len,
                       thread const uchar* pwd, uint pwd_len,
                       thread const uchar* salt, uint salt_len,
                       uint iterations) {
    uint hlen = 20;
    uint blocks = (dk_len + hlen - 1) / hlen;
    uchar salt_ext[64];
    for (uint i = 0; i < salt_len; i++) salt_ext[i] = salt[i];

    for (uint b = 0; b < blocks; b++) {
        salt_ext[salt_len] = ((b + 1) >> 24) & 0xFF;
        salt_ext[salt_len+1] = ((b + 1) >> 16) & 0xFF;
        salt_ext[salt_len+2] = ((b + 1) >> 8) & 0xFF;
        salt_ext[salt_len+3] = (b + 1) & 0xFF;

        uchar u[20], t[20];
        hmac_sha1(u, pwd, pwd_len, salt_ext, salt_len + 4);
        for (uint i = 0; i < hlen; i++) t[i] = u[i];

        for (uint r = 1; r < iterations; r++) {
            hmac_sha1(u, pwd, pwd_len, u, hlen);
            for (uint i = 0; i < hlen; i++) t[i] ^= u[i];
        }

        uint copy = min(hlen, dk_len - b * hlen);
        for (uint i = 0; i < copy; i++) dk[b * hlen + i] = t[i];
    }
}

// --- AES-256 ---

constant uchar sbox[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16
};

constant uchar rcon[16] = {
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
};

uchar gmul(uchar a, uchar b) {
    uchar p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi = a & 0x80;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

void mix_column(thread uchar* col) {
    uchar s0=col[0], s1=col[1], s2=col[2], s3=col[3];
    col[0] = gmul(s0,2) ^ gmul(s1,3) ^ s2 ^ s3;
    col[1] = s0 ^ gmul(s1,2) ^ gmul(s2,3) ^ s3;
    col[2] = s0 ^ s1 ^ gmul(s2,2) ^ gmul(s3,3);
    col[3] = gmul(s0,3) ^ s1 ^ s2 ^ gmul(s3,2);
}

void aes256_key_expand(thread uchar* rk, thread const uchar* key) {
    for (int i = 0; i < 32; i++) rk[i] = key[i];
    uint nk = 8, nr = 14, nb = 4;

    for (uint i = nk; i < nb * (nr + 1); i++) {
        uchar t[4];
        for (int j = 0; j < 4; j++) t[j] = rk[(i-1)*4 + j];
        if (i % nk == 0) {
            uchar tmp = t[0]; t[0] = sbox[t[1]] ^ rcon[i/nk];
            t[1] = sbox[t[2]]; t[2] = sbox[t[3]]; t[3] = sbox[tmp];
        } else if (nk > 6 && i % nk == 4) {
            t[0] = sbox[t[0]]; t[1] = sbox[t[1]];
            t[2] = sbox[t[2]]; t[3] = sbox[t[3]];
        }
        for (int j = 0; j < 4; j++)
            rk[i*4 + j] = rk[(i-nk)*4 + j] ^ t[j];
    }
}

void aes256_encrypt_block(thread uchar* out, thread const uchar* in,
                           thread const uchar* rk) {
    uchar state[16];
    for (int i = 0; i < 16; i++) state[i] = in[i] ^ rk[i];

    for (int round = 1; round <= 13; round++) {
        for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];

        uchar sr[16];
        sr[0]=state[0]; sr[1]=state[5]; sr[2]=state[10]; sr[3]=state[15];
        sr[4]=state[4]; sr[5]=state[9]; sr[6]=state[14]; sr[7]=state[3];
        sr[8]=state[8]; sr[9]=state[13]; sr[10]=state[2]; sr[11]=state[7];
        sr[12]=state[12]; sr[13]=state[1]; sr[14]=state[6]; sr[15]=state[11];

        for (int col = 0; col < 4; col++) mix_column(sr + col * 4);
        for (int i = 0; i < 16; i++) state[i] = sr[i] ^ rk[round*16 + i];
    }

    for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
    uchar sr[16];
    sr[0]=state[0]; sr[1]=state[5]; sr[2]=state[10]; sr[3]=state[15];
    sr[4]=state[4]; sr[5]=state[9]; sr[6]=state[14]; sr[7]=state[3];
    sr[8]=state[8]; sr[9]=state[13]; sr[10]=state[2]; sr[11]=state[7];
    sr[12]=state[12]; sr[13]=state[1]; sr[14]=state[6]; sr[15]=state[11];
    for (int i = 0; i < 16; i++) out[i] = sr[i] ^ rk[14*16 + i];
}

kernel void crack_aes256(
    device const uint64_t* passwords      [[buffer(0)]],
    device const uchar*    password_lens  [[buffer(1)]],
    device const uchar*    salt           [[buffer(2)]],
    device const uchar*    enc_verify     [[buffer(3)]],
    device atomic_uint&    found_flag     [[buffer(4)]],
    device uint&           found_idx      [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (atomic_load_explicit(&found_flag, memory_order_relaxed) != 0) return;

    uint64_t pwd_packed = passwords[tid];
    uchar length = password_lens[tid];

    uchar pwd[8];
    for (int i = 0; i < length; i++)
        pwd[i] = (pwd_packed >> (i * 8)) & 0xFF;

    uchar local_salt[16];
    uchar local_verify[2];
    for (int i = 0; i < 16; i++) local_salt[i] = salt[i];
    for (int i = 0; i < 2; i++) local_verify[i] = enc_verify[i];

    uchar dk[66];
    pbkdf2_hmac_sha1(dk, 66, pwd, length, local_salt, 16, 1000);

    if (dk[64] == local_verify[0] && dk[65] == local_verify[1]) {
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(
                &found_flag, &expected, 1,
                memory_order_relaxed, memory_order_relaxed)) {
            found_idx = tid;
        }
    }
}
)";

static NSString* kZipCryptoKernelSource = @R"(
#include <metal_stdlib>
using namespace metal;

constant uint kCrc32Table[256] = {
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
    0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
    0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
    0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec,
    0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
    0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940,
    0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116,
    0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
    0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a,
    0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818,
    0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
    0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c,
    0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
    0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
    0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086,
    0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4,
    0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
    0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
    0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe,
    0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
    0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252,
    0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60,
    0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
    0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb30a04,
    0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a,
    0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
    0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e,
    0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
    0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
    0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0,
    0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6,
    0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
    0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
};

inline uint crc32_update(uint crc, uchar byte) {
    return (crc >> 8) ^ kCrc32Table[(crc ^ byte) & 0xFF];
}

inline uchar decrypt_byte(thread uint3& keys) {
    ushort temp = (keys.z | 2) & 0xFFFF;
    return ((temp * (temp ^ 1)) >> 8) & 0xFF;
}

inline void update_keys_with_byte(thread uint3& keys, uchar byte) {
    keys.x = crc32_update(keys.x, byte);
    keys.y = (keys.y + (keys.x & 0xFF)) * 0x08088405 + 1;
    keys.z = crc32_update(keys.z, (keys.y >> 24) & 0xFF);
}

kernel void crack_zipcrypto(
    device const uint64_t* passwords      [[buffer(0)]],
    device const uchar*    password_lens  [[buffer(1)]],
    device const uchar*    enc_header     [[buffer(2)]],
    device const uchar*    expected_bytes [[buffer(3)]],
    device atomic_uint&    found_flag     [[buffer(4)]],
    device uint&           found_idx      [[buffer(5)]],
    uint tid [[thread_position_in_grid]]
) {
    if (atomic_load_explicit(&found_flag, memory_order_relaxed) != 0) return;

    uint64_t pwd_packed = passwords[tid];
    uchar length = password_lens[tid];
    uint3 keys = uint3(0x12345678, 0x23456789, 0x34567890);

    for (uchar i = 0; i < length; i++) {
        uchar byte = (pwd_packed >> (i * 8)) & 0xFF;
        update_keys_with_byte(keys, byte);
    }

    uchar decrypted[16];
    for (int i = 0; i < 16; i++) {
        uchar kb = decrypt_byte(keys);
        decrypted[i] = enc_header[i] ^ kb;
        update_keys_with_byte(keys, decrypted[i]);
    }

    if (decrypted[12] == expected_bytes[0] &&
        decrypted[13] == expected_bytes[1] &&
        decrypted[14] == expected_bytes[2] &&
        decrypted[15] == expected_bytes[3]) {
        uint expected = 0;
        if (atomic_compare_exchange_weak_explicit(
                &found_flag, &expected, 1,
                memory_order_relaxed, memory_order_relaxed)) {
            found_idx = tid;
        }
    }
}
)";

static id<MTLComputePipelineState> compile_kernel(id<MTLDevice> device,
                                                    NSString* source,
                                                    const std::string& name) {
    NSError* error = nil;
    id<MTLLibrary> library = [device newLibraryWithSource:source
                                                   options:nil
                                                     error:&error];
    if (!library) {
        std::cerr << "[GPU] Compile error: "
                  << (error ? [[error localizedDescription] UTF8String] : "?")
                  << std::endl;
        return nil;
    }

    NSString* nsName = [NSString stringWithUTF8String:name.c_str()];
    id<MTLFunction> func = [library newFunctionWithName:nsName];
    [library release];
    if (!func) {
        std::cerr << "[GPU] Kernel '" << name << "' not found" << std::endl;
        return nil;
    }

    id<MTLComputePipelineState> pso = [device newComputePipelineStateWithFunction:func
                                                                           error:&error];
    [func release];
    if (!pso) {
        std::cerr << "[GPU] Pipeline error: "
                  << (error ? [[error localizedDescription] UTF8String] : "?")
                  << std::endl;
    }
    return pso;
}

MetalKernel::MetalKernel()
    : device_(nullptr)
    , command_queue_(nullptr)
    , pipeline_state_(nullptr)
    , aes_pipeline_state_(nullptr)
    , available_(false)
    , aes_available_(false) {}

MetalKernel::~MetalKernel() {
    if (aes_pipeline_state_) [(__bridge id<MTLComputePipelineState>)aes_pipeline_state_ release];
    if (pipeline_state_)    [(__bridge id<MTLComputePipelineState>)pipeline_state_ release];
    if (command_queue_)     [(__bridge id<MTLCommandQueue>)command_queue_ release];
    if (device_)            [(__bridge id<MTLDevice>)device_ release];
}

bool MetalKernel::initialize_device() {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) { std::cerr << "[GPU] No Metal device" << std::endl; return false; }
    device_ = (__bridge void*)[device retain];
    command_queue_ = (__bridge void*)[[device newCommandQueue] retain];
    std::cout << "[GPU] Metal: " << [[device name] UTF8String] << std::endl;
    return true;
}

bool MetalKernel::initialize(const std::string&, const std::string& kernel_name) {
    id<MTLDevice> device = MTLCreateSystemDefaultDevice();
    if (!device) { std::cerr << "[GPU] No Metal device" << std::endl; return false; }
    device_ = (__bridge void*)[device retain];

    auto* pso = compile_kernel(device, kZipCryptoKernelSource, kernel_name);
    if (!pso) return false;
    pipeline_state_ = (__bridge void*)[pso retain];

    command_queue_ = (__bridge void*)[[device newCommandQueue] retain];
    available_ = true;
    std::cout << "[GPU] Metal: " << [[device name] UTF8String] << std::endl;
    return true;
}

bool MetalKernel::initialize_aes() {
    if (!device_) return false;
    id<MTLDevice> device = (__bridge id<MTLDevice>)device_;

    auto* pso = compile_kernel(device, kAesKernelSource, "crack_aes256");
    if (!pso) return false;
    aes_pipeline_state_ = (__bridge void*)[pso retain];
    aes_available_ = true;
    std::cout << "[GPU] AES kernel compiled" << std::endl;
    return true;
}

bool MetalKernel::is_available() const { return available_; }
bool MetalKernel::is_aes_available() const { return aes_available_; }

bool MetalKernel::check_passwords(
    const std::vector<uint64_t>& passwords_packed,
    const std::vector<uint8_t>& password_lengths,
    const uint8_t encrypted_data[16],
    const uint8_t expected_bytes[4],
    uint32_t& out_found_index) {

    if (!available_) return false;
    auto* device    = (__bridge id<MTLDevice>)device_;
    auto* queue     = (__bridge id<MTLCommandQueue>)command_queue_;
    auto* pso       = (__bridge id<MTLComputePipelineState>)pipeline_state_;

    size_t count = passwords_packed.size();
    if (count == 0) return false;

    id<MTLBuffer> bufs[6];
    bufs[0] = [device newBufferWithBytes:passwords_packed.data() length:count*sizeof(uint64_t) options:MTLResourceStorageModeShared];
    bufs[1] = [device newBufferWithBytes:password_lengths.data() length:count*sizeof(uint8_t) options:MTLResourceStorageModeShared];
    bufs[2] = [device newBufferWithBytes:encrypted_data length:16 options:MTLResourceStorageModeShared];
    bufs[3] = [device newBufferWithBytes:expected_bytes length:4 options:MTLResourceStorageModeShared];
    uint32_t z = 0;
    bufs[4] = [device newBufferWithBytes:&z length:4 options:MTLResourceStorageModeShared];
    bufs[5] = [device newBufferWithBytes:&z length:4 options:MTLResourceStorageModeShared];

    for (int i = 0; i < 6; i++) if (!bufs[i]) return false;

    auto* cmd = [queue commandBuffer];
    auto* enc = [cmd computeCommandEncoder];
    [enc setComputePipelineState:pso];
    for (int i = 0; i < 6; i++) [enc setBuffer:bufs[i] offset:0 atIndex:i];

    NSUInteger tg = MIN([pso maxTotalThreadsPerThreadgroup], count);
    [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];

    uint32_t found = 0;
    std::memcpy(&found, [bufs[4] contents], 4);
    if (found) std::memcpy(&out_found_index, [bufs[5] contents], 4);
    for (int i = 0; i < 6; i++) [bufs[i] release];
    return found != 0;
}

bool MetalKernel::check_aes_passwords(
    const std::vector<uint64_t>& passwords_packed,
    const std::vector<uint8_t>& password_lengths,
    const uint8_t salt[16],
    const uint8_t encrypted_verification[2],
    uint32_t& out_found_index) {

    if (!aes_available_) return false;
    auto* device  = (__bridge id<MTLDevice>)device_;
    auto* queue   = (__bridge id<MTLCommandQueue>)command_queue_;
    auto* pso     = (__bridge id<MTLComputePipelineState>)aes_pipeline_state_;

    size_t count = passwords_packed.size();
    if (count == 0) return false;

    id<MTLBuffer> bufs[6];
    bufs[0] = [device newBufferWithBytes:passwords_packed.data() length:count*sizeof(uint64_t) options:MTLResourceStorageModeShared];
    bufs[1] = [device newBufferWithBytes:password_lengths.data() length:count*sizeof(uint8_t) options:MTLResourceStorageModeShared];
    bufs[2] = [device newBufferWithBytes:salt length:16 options:MTLResourceStorageModeShared];
    bufs[3] = [device newBufferWithBytes:encrypted_verification length:2 options:MTLResourceStorageModeShared];
    uint32_t z = 0;
    bufs[4] = [device newBufferWithBytes:&z length:4 options:MTLResourceStorageModeShared];
    bufs[5] = [device newBufferWithBytes:&z length:4 options:MTLResourceStorageModeShared];

    for (int i = 0; i < 6; i++) if (!bufs[i]) return false;

    auto* cmd = [queue commandBuffer];
    auto* enc = [cmd computeCommandEncoder];
    [enc setComputePipelineState:pso];
    for (int i = 0; i < 6; i++) [enc setBuffer:bufs[i] offset:0 atIndex:i];

    NSUInteger tg = MIN([pso maxTotalThreadsPerThreadgroup], count);
    [enc dispatchThreads:MTLSizeMake(count,1,1) threadsPerThreadgroup:MTLSizeMake(tg,1,1)];
    [enc endEncoding];
    [cmd commit];
    [cmd waitUntilCompleted];

    uint32_t found = 0;
    std::memcpy(&found, [bufs[4] contents], 4);
    if (found) std::memcpy(&out_found_index, [bufs[5] contents], 4);
    for (int i = 0; i < 6; i++) [bufs[i] release];
    return found != 0;
}

} // namespace gpu
