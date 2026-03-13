#include <stddef.h>
#include <stdint.h>
#include "esp_random.h"
#include "internal.h"

void noise_rand_bytes(void *bytes, size_t size)
{
    uint8_t *out = (uint8_t *)bytes;
    while (size >= 4) {
        uint32_t v = esp_random();
        out[0] = (uint8_t)v;
        out[1] = (uint8_t)(v >> 8);
        out[2] = (uint8_t)(v >> 16);
        out[3] = (uint8_t)(v >> 24);
        out += 4;
        size -= 4;
    }
    if (size) {
        uint32_t v = esp_random();
        while (size--) {
            *out++ = (uint8_t)v;
            v >>= 8;
        }
    }
}

#ifdef ED25519_CUSTOMRANDOM
void ed25519_randombytes_unsafe(void *p, size_t len)
{
    noise_rand_bytes(p, len);
}
#endif
