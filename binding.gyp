{
  "targets": [
    {
      "target_name": "worker",
      "include_dirs": ["<!(node -e \"require('nan')\")"],
      "cflags": ["-Wall", "-O2"],
      "sources": ["src/worker.cc", "src/pow.cc"]
    }
  ]
}
