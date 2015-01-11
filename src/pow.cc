// Based on <https://github.com/grant-olson/bitmessage-powfaster>
// fastcpu implementation.
// TODO(Kagami): Port it to WIN32 (see bitmessage-powfaster for an
// example).

#define __STDC_LIMIT_MACROS
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <openssl/sha.h>
#include "./pow.h"

enum PowResult {
  RESULT_OK = 0,
  RESULT_OVERFLOW = -1,
  RESULT_ERROR = -2,
  RESULT_BAD_INPUT = -3,
  RESULT_NOT_READY = -4
};

// Global arguments.
size_t g_pool_size;
uint64_t g_target;
uint8_t* g_initial_hash;
uint64_t g_max_nonce;

// Shared variables for threads.
pthread_mutex_t g_mutex;
PowResult g_result = RESULT_NOT_READY;
uint64_t g_nonce;

inline uint64_t ntohll(uint64_t x) {
  return (
      ((uint64_t)(ntohl( (unsigned int)((x << 32) >> 32) )) << 32) |
      ntohl( ((unsigned int)(x >> 32)) )
  );
}

// Set POW computation result in a thread-safe way.
void set_result(PowResult res, uint64_t nonce) {
  pthread_mutex_lock(&g_mutex);
  if (g_result == RESULT_NOT_READY) {
    g_result = res;
    g_nonce = nonce;
  }
  pthread_mutex_unlock(&g_mutex);
}

void* pow_thread(void* num) {
  uint64_t i = *((size_t *)num);
  uint8_t message[HASH_SIZE+sizeof(uint64_t)];
  uint8_t digest[HASH_SIZE];
  uint64_t* be_nonce;
  uint64_t* be_trial;
  SHA512_CTX sha;

  memcpy(message+sizeof(uint64_t), g_initial_hash, HASH_SIZE);
  be_nonce = (uint64_t *)message;
  be_trial = (uint64_t *)digest;

  while (g_result == RESULT_NOT_READY) {
    // This is very unlikely to be ever happen but it's better to be
    // sure anyway.
    if (i > g_max_nonce) {
      set_result(RESULT_OVERFLOW, 0);
      return NULL;
    }
    *be_nonce = ntohll(i);
    SHA512_Init(&sha);
    SHA512_Update(&sha, message, HASH_SIZE+sizeof(uint64_t));
    SHA512_Final(digest, &sha);
    SHA512_Init(&sha);
    SHA512_Update(&sha, digest, HASH_SIZE);
    SHA512_Final(digest, &sha);
    if (ntohll(*be_trial) <= g_target) {
      set_result(RESULT_OK, i);
      return NULL;
    }
    i += g_pool_size;
  }
  return NULL;
}

int pow(size_t pool_size,
        uint64_t target,
        const uint8_t* initial_hash,
        uint64_t max_nonce,
        uint64_t* nonce) {
  if (pool_size < 1 || pool_size > MAX_POOL_SIZE) {
    return RESULT_BAD_INPUT;
  }
  g_pool_size = pool_size;
  g_target = target;
  g_initial_hash = (uint8_t *)initial_hash;
  g_max_nonce = max_nonce ? max_nonce : UINT64_MAX;

  pthread_mutex_init(&g_mutex, NULL);
  pthread_t threads[pool_size];
  size_t args[pool_size];
  size_t i;
  int error;

  for (i = 0; i < pool_size; i++) {
    args[i] = i;
    error = pthread_create(&threads[i], NULL, pow_thread, &args[i]);
    if (error) {
      set_result(RESULT_ERROR, 0);
      break;
    }
  }

  // Wait for only spawned threads.
  while (i--) {
    pthread_join(threads[i], NULL);
  }

  if (g_result == RESULT_OK) {
    *nonce = g_nonce;
  }

  pthread_mutex_destroy(&g_mutex);
  return g_result;
}
