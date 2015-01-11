#include <node.h>
#include <nan.h>
#include <stdlib.h>
#include "./pow.h"

#define MAX_SAFE_INTEGER 9007199254740991

using node::Buffer;
using v8::Handle;
using v8::Local;
using v8::FunctionTemplate;
using v8::Function;
using v8::Value;
using v8::Object;
using v8::String;
using v8::Integer;

class PowWorker : public NanAsyncWorker {
 public:
  PowWorker(NanCallback* callback,
            size_t pool_size,
            uint64_t target,
            uint8_t* initial_hash)
      : NanAsyncWorker(callback),
        pool_size(pool_size),
        target(target),
        initial_hash(initial_hash) {}

  ~PowWorker() {
    free(initial_hash);
  }

  // Executed inside the worker-thread.
  // It is not safe to access V8, or V8 data structures
  // here, so everything we need for input and output
  // should go on `this`.
  void Execute () {
    error = pow(pool_size, target, initial_hash, MAX_SAFE_INTEGER, &nonce);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {
    NanScope();
    if (error) {
      Local<Value> argv[1];
      if (error == -1) {
        argv[0] = NanError("Max safe integer overflow");
      } else {
        argv[0] = NanError("Internal error");
      }
      callback->Call(1, argv);
    } else {
      Local<Value> argv[] = {NanNull(), NanNew<Integer>(nonce)};
      callback->Call(2, argv);
    }
  }

 private:
  size_t pool_size;
  uint64_t target;
  uint8_t* initial_hash;
  uint64_t nonce;
  int error;
};

NAN_METHOD(PowAsync) {
  NanScope();

  if (args.Length() != 4 ||
      !args[0]->IsNumber() ||  // pool_size
      !args[1]->IsNumber() ||  // target
      !args[2]->IsObject() ||  // initial_hash
      !args[3]->IsFunction()) {  // cb
    NanThrowError("Bad input");
    NanReturnUndefined();
  }

  size_t pool_size = args[0]->Uint32Value();
  uint64_t target = args[1]->IntegerValue();
  size_t length = Buffer::Length(args[2]->ToObject());
  if (pool_size < 1 || pool_size > MAX_POOL_SIZE || length != HASH_SIZE) {
    NanThrowError("Bad input");
    NanReturnUndefined();
  }
  uint8_t* initial_hash = (uint8_t *)malloc(length);
  if (initial_hash == NULL) {
    NanThrowError("Internal error");
    NanReturnUndefined();
  }

  char* buf = Buffer::Data(args[2]->ToObject());
  memcpy(initial_hash, buf, length);
  NanCallback* callback = new NanCallback(args[3].As<Function>());
  NanAsyncQueueWorker(new PowWorker(callback, pool_size, target, initial_hash));
  NanReturnUndefined();
}

void InitAll(Handle<Object> exports) {
  exports->Set(
      NanNew<String>("powAsync"),
      NanNew<FunctionTemplate>(PowAsync)->GetFunction());
}

NODE_MODULE(worker, InitAll)
