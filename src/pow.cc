// Based on <https://github.com/grant-olson/bitmessage-powfaster>
// fastcpu implementation.
// TODO(Kagami): Port it to WIN32 (see bitmessage-powfaster for an
// example).

#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/sha.h>

#define HASH_SIZE 64
#define NTOHLL(x) ( ( (uint64_t)(ntohl( (unsigned int)((x << 32) >> 32) )) << 32) | ntohl( ((unsigned int)(x >> 32)) ) )
#define MAX_SAFE_JS_INTEGER 9007199254740991

int pow(uint32_t pool_size,
        int64_t target,
        const uint8_t* initial_hash,
        int64_t* nonce) {
  uint8_t message[HASH_SIZE+sizeof(uint64_t)];
  uint8_t digest[HASH_SIZE];
  uint64_t* be_nonce;
  uint64_t* be_trial;
  uint64_t i;
  SHA512_CTX sha;

  memcpy(message+sizeof(uint64_t), initial_hash, HASH_SIZE);
  be_nonce = (uint64_t *)message;
  be_trial = (uint64_t *)digest;
  i = 0;
  while (1) {
    // This is very unlikely to be ever happen but it's better to be
    // sure anyway.
    if (i > MAX_SAFE_JS_INTEGER) {
      return -1;
    }
    *be_nonce = NTOHLL(i);
    SHA512_Init(&sha);
    SHA512_Update(&sha, message, HASH_SIZE+sizeof(uint64_t));
    SHA512_Final(digest, &sha);
    SHA512_Init(&sha);
    SHA512_Update(&sha, digest, HASH_SIZE);
    SHA512_Final(digest, &sha);
    if (NTOHLL(*be_trial) <= (uint64_t)target) {
      break;
    }
    i++;
  }
  *nonce = i;
  return 0;
}
