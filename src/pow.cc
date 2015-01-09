// Based on <https://github.com/grant-olson/bitmessage-powfaster>
// fastcpu implementation.
// TODO(Kagami): Port it to WIN32 (see bitmessage-powfaster for an
// example).

#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define HASH_SIZE 64
#define NTOHLL(x) ( ( (uint64_t)(ntohl( (unsigned int)((x << 32) >> 32) )) << 32) | ntohl( ((unsigned int)(x >> 32)) ) )

int pow(size_t pool_size,
        uint64_t target,
        const uint8_t* initial_hash,
        uint64_t max_nonce,
        uint64_t* nonce) {
  uint8_t message[HASH_SIZE+sizeof(uint64_t)];
  uint8_t digest[HASH_SIZE];
  uint64_t* be_nonce;
  uint64_t* be_trial;
  uint64_t i;
  SHA512_CTX sha;

  if (!max_nonce) {
    max_nonce = UINT64_MAX;
  }
  memcpy(message+sizeof(uint64_t), initial_hash, HASH_SIZE);
  be_nonce = (uint64_t *)message;
  be_trial = (uint64_t *)digest;
  i = 0;

  while (1) {
    // This is very unlikely to be ever happen but it's better to be
    // sure anyway.
    if (i > max_nonce) {
      return -1;
    }
    *be_nonce = NTOHLL(i);
    SHA512_Init(&sha);
    SHA512_Update(&sha, message, HASH_SIZE+sizeof(uint64_t));
    SHA512_Final(digest, &sha);
    SHA512_Init(&sha);
    SHA512_Update(&sha, digest, HASH_SIZE);
    SHA512_Final(digest, &sha);
    if (NTOHLL(*be_trial) <= target) {
      break;
    }
    i++;
  }

  *nonce = i;
  return 0;
}
