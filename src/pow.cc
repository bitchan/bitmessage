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

// Shared POW parameters.
typedef struct {
  const size_t pool_size;
  const size_t target;
  const uint8_t* initial_hash;
  const uint64_t max_nonce;
  PowResult result;
  uint64_t nonce;
  pthread_mutex_t* mutex;
} PowArgs;

// Thread-specific arguments.
typedef struct {
  size_t num;  // Thread number
  PowArgs* pow_args;
} ThreadArgs;

#ifndef ntohll
inline uint64_t ntohll(uint64_t x) {
  return (
      ((uint64_t)(ntohl( (unsigned int)((x << 32) >> 32) )) << 32) |
      ntohl( ((unsigned int)(x >> 32)) )
  );
}
#endif

// Set POW computation result in a thread-safe way.
void set_result(PowArgs* pow_args, PowResult res, uint64_t nonce) {
  pthread_mutex_lock(pow_args->mutex);
  if (pow_args->result == RESULT_NOT_READY) {
    pow_args->result = res;
    pow_args->nonce = nonce;
  }
  pthread_mutex_unlock(pow_args->mutex);
}

void* pow_thread(void* arg) {
  ThreadArgs* thread_args = (ThreadArgs *)arg;
  PowArgs* pow_args = thread_args->pow_args;

  // Copy some fixed POW args so compiler can inline them.
  const size_t pool_size = pow_args->pool_size;
  const uint64_t target = pow_args->target;
  const uint64_t max_nonce = pow_args->max_nonce;

  uint64_t i = thread_args->num;
  uint8_t message[HASH_SIZE+sizeof(uint64_t)];
  uint8_t digest[HASH_SIZE];
  uint64_t* be_nonce;
  uint64_t* be_trial;
  SHA512_CTX sha;

  memcpy(message+sizeof(uint64_t), pow_args->initial_hash, HASH_SIZE);
  be_nonce = (uint64_t *)message;
  be_trial = (uint64_t *)digest;

  while (pow_args->result == RESULT_NOT_READY) {
    // This is very unlikely to be ever happen but it's better to be
    // sure anyway.
    if (i > max_nonce) {
      set_result(pow_args, RESULT_OVERFLOW, 0);
      return NULL;
    }
    // XXX(Kagami): This and target comparision lines imply that we run
    // this code on LE architecture while this might not be true.
    *be_nonce = ntohll(i);
    SHA512_Init(&sha);
    SHA512_Update(&sha, message, HASH_SIZE+sizeof(uint64_t));
    SHA512_Final(digest, &sha);
    SHA512_Init(&sha);
    SHA512_Update(&sha, digest, HASH_SIZE);
    SHA512_Final(digest, &sha);
    if (ntohll(*be_trial) <= target) {
      set_result(pow_args, RESULT_OK, i);
      return NULL;
    }
    i += pool_size;
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

  // Initialize all structures on stack.
  pthread_mutex_t mutex;
  pthread_mutex_init(&mutex, NULL);
  PowArgs pow_args = {
    pool_size,
    target,
    initial_hash,
    max_nonce ? max_nonce : INT64_MAX,
    RESULT_NOT_READY,
    0,
    &mutex,
  };
  ThreadArgs threads_args[pool_size];
  pthread_t threads[pool_size];
  size_t i;
  int error;

  // Spawn threads.
  for (i = 0; i < pool_size; i++) {
    ThreadArgs args = {i, &pow_args};
    threads_args[i] = args;
    error = pthread_create(&threads[i], NULL, pow_thread, &threads_args[i]);
    if (error) {
      set_result(&pow_args, RESULT_ERROR, 0);
      break;
    }
  }

  // Wait for only spawned threads.
  while (i--) {
    pthread_join(threads[i], NULL);
  }

  // Set resulting nonce, cleanup and exit;
  if (pow_args.result == RESULT_OK) {
    *nonce = pow_args.nonce;
  }
  pthread_mutex_destroy(&mutex);
  return pow_args.result;
}
