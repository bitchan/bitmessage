#include <node.h>
#include <nan.h>
#include "./pow.h"

using v8::Handle;
using v8::Local;
using v8::FunctionTemplate;
using v8::Function;
using v8::Value;
using v8::Object;
using v8::String;
using v8::Number;

static const uint64_t MAX_SAFE_INTEGER = 9007199254740991ULL;

class PowWorker : public Nan::AsyncWorker {
 public:
  PowWorker(Nan::Callback* callback,
            size_t pool_size,
            uint64_t target,
            uint8_t* initial_hash)
      : Nan::AsyncWorker(callback),
        pool_size(pool_size),
        target(target),
        initial_hash(initial_hash) {}

  ~PowWorker() {
    delete[] initial_hash;
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
    if (error) {
      Local<Value> argv[1];
      if (error == -1) {
        argv[0] = Nan::Error("Max safe integer overflow");
      } else {
        argv[0] = Nan::Error("Internal error");
      }
      callback->Call(1, argv);
    } else {
      Local<Value> argv[] = {Nan::Null(), Nan::New<Number>(nonce)};
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
  if (info.Length() != 4 ||
      !info[0]->IsNumber() ||  // pool_size
      !info[1]->IsNumber() ||  // target
      !node::Buffer::HasInstance(info[2]) ||  // initial_hash
      !info[3]->IsFunction()) {  // cb
    return Nan::ThrowError("Bad input");
  }

  size_t pool_size = info[0]->Uint32Value();
  uint64_t target = info[1]->IntegerValue();
  char* buf = node::Buffer::Data(info[2]);
  size_t length = node::Buffer::Length(info[2]);
  if (pool_size < 1 ||
      pool_size > MAX_POOL_SIZE ||
      buf == NULL ||
      length != HASH_SIZE) {
    return Nan::ThrowError("Bad input");
  }

  uint8_t* initial_hash = new uint8_t[length];
  memcpy(initial_hash, buf, length);
  Nan::Callback* callback = new Nan::Callback(info[3].As<Function>());
  Nan::AsyncQueueWorker(
    new PowWorker(callback, pool_size, target, initial_hash));
}

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New<String>("powAsync").ToLocalChecked(),
    Nan::GetFunction(Nan::New<FunctionTemplate>(PowAsync)).ToLocalChecked());
}

NODE_MODULE(worker, InitAll)
