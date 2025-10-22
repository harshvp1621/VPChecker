## Obtaining Ground Truth using LLVM Recompilation

We make use of the LLVM-pass used by Lin et. al in their paper "When Function Signature Recovery Meets Compiler Optimization". Their code can be cloned from:
```
$ git clone https://github.com/ylyanlin/FSROPT.git
```
We are just concerned with the `Ground Truth Collection` part of the repository.\

### Recompilation using LLVM
In order to make use of the LLVM pass by Lin et. al, we need to first recompile our target binaries from source using the LLVM compiler. Since the pass of Lin et. al is in LLVM-7, we set-up a `debian:sid` image with LLVM-7 toolchain. The "Whole Program LLVM in Go" project enables seamless recompilation:

```
git clone https://github.com/SRI-CSL/gllvm.git
```

We download the debian sources of the binaries we want to recompile and trigger compilation using the `gclang` and `gclang++` compiler wrappers to produce bitcodes.\
The `llvm_recompiled_bins/RECOMPILED/bitcodes/` directory contains the raw bitcode files. The `llvm_recompiled_bins/RECOMPILED/bitcodes/gtruth` directory contains the ground truth files obtained running Lin et. al's LLVM pass on the bitcode files.

