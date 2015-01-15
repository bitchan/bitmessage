#ifndef BITCHAN_BITMESSAGE_POW_H_
#define BITCHAN_BITMESSAGE_POW_H_

static const size_t MAX_POOL_SIZE = 1024;
static const size_t HASH_SIZE = 64;

int pow(size_t pool_size,
        uint64_t target,
        const uint8_t* initial_hash,
        uint64_t max_nonce,
        uint64_t* nonce);

#endif  // BITCHAN_BITMESSAGE_POW_H_
