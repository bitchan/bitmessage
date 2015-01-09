#ifndef BITMESSAGE_POW_H
#define BITMESSAGE_POW_H

int pow(uint32_t pool_size,
        int64_t target,
        const uint8_t* initial_hash,
        int64_t* nonce);

#endif
