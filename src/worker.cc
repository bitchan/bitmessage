#include <node.h>
#include <nan.h>
#include <stdlib.h>
#include "./pow.h"

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
            uint32_t pool_size,
            int64_t target,
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
    error = pow(pool_size, target, initial_hash, &nonce);
  }

  // Executed when the async work is complete
  // this function will be run inside the main event loop
  // so it is safe to use V8 again
  void HandleOKCallback () {
    NanScope();
    if (error) {
      Local<Value> argv[] = {NanError("Max safe integer overflow")};
      callback->Call(1, argv);
    } else {
      Local<Value> argv[] = {NanNull(), NanNew<Integer>(nonce)};
      callback->Call(2, argv);
    }
  }

 private:
  uint32_t pool_size;
  int64_t target;
  uint8_t* initial_hash;
  int64_t nonce;
  int error;
};

NAN_METHOD(PowAsync) {
  NanScope();

  NanCallback *callback = new NanCallback(args[3].As<Function>());
  uint32_t pool_size = args[0]->Uint32Value();
  int64_t target = args[1]->IntegerValue();
  size_t length = Buffer::Length(args[2]->ToObject());
  char* buf = Buffer::Data(args[2]->ToObject());
  uint8_t* initial_hash = (uint8_t *)malloc(length);

  if (initial_hash == NULL) {
    Local<Value> argv[] = {NanError("Cannot allocate memory")};
    callback->Call(1, argv);
  } else {
    memcpy(initial_hash, buf, length);
    NanAsyncQueueWorker(
        new PowWorker(callback, pool_size, target, initial_hash));
  }

  NanReturnUndefined();
}

// Expose synchronous and asynchronous access to our
// Estimate() function
void InitAll(Handle<Object> exports) {
  exports->Set(
      NanNew<String>("powAsync"),
      NanNew<FunctionTemplate>(PowAsync)->GetFunction());
}

NODE_MODULE(worker, InitAll)
