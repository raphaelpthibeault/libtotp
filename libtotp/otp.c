#include "otp.h"
#include <math.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

static uint32_t truncateToDigits(uint32_t a, int digits) {
    int power = pow(10, digits);
    uint32_t res = a % power;
    return res;
}

uint8_t* hmacsha(unsigned char* key, int klen, uint64_t interval) {
    return (uint8_t*)HMAC(EVP_sha1(), key, klen, (const unsigned char*)&interval, sizeof(interval), NULL, 0);
}

static uint32_t dt(uint8_t* digest) {
    // straight from RFC4226 Section 5.4
    uint64_t offset = digest[19] & 0x0F;
    uint32_t bin_code = (digest[offset] & 0x7f) << 24 |
                        (digest[offset+1] & 0xff) << 16 |
                        (digest[offset+2] & 0xff) <<  8 |
                        (digest[offset+3] & 0xff);

    return bin_code;
}

uint32_t hotp(uint8_t* key, size_t klen, uint64_t interval, int digits) {
    // make interval big endian
    uint32_t endianness = 0xdeadbeef; // little trick to coax out memory issues
    if ((*(const uint8_t *)&endianness) == 0xef) {
        interval = ((interval & 0x00000000ffffffff) << 32) | ((interval & 0xffffffff00000000) >> 32);
        interval = ((interval & 0x0000ffff0000ffff) << 16) | ((interval & 0xffff0000ffff0000) >> 16);
        interval = ((interval & 0x00ff00ff00ff00ff) <<  8) | ((interval & 0xff00ff00ff00ff00) >>  8);
    };

    uint8_t* digest = (uint8_t*)hmacsha(key, klen, interval);
    uint32_t dt_bincode = dt(digest);
    uint32_t res = truncateToDigits(dt_bincode, digits);
    return res;
}


time_t getTime(time_t T0) {
    return floor((time(NULL) - T0)/step);
}

uint32_t totp(uint8_t* key, size_t klen, uint64_t time, int digits) {
    uint32_t totp = hotp(key, klen, time, digits);
    return totp;
}

