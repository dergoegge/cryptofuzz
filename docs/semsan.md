# Fuzzing with SemSan

To fuzz cryptofuzz with SemSan as the driver (replacing libfuzzer, afl++ or
similar), two different crptofuzz binaries (e.g. one compiled with -O0 and the
other with -O2) need to be build.

Unless emulation is used for the secondary harness (see below), SemSan targets
(in this case cryptofuzz, it's modules and the libraries under test) need to be
build using the afl++ compiler (i.e. `afl-clang-{fast,lto,fast++,lto++}` or
`afl-{gcc,g++}-fast`).

Once the binaries have been build, SemSan can be executed as follows:

```
semsan cryptofuzz1 cryptofuzz2 fuzz --seeds <corpus> --solutions <location for solutions>
```

If SemSan finds a behavioural difference between the two binaries, it will log
and exit, e.g.:

``` 
== ERROR: Semantic Difference
primary  : [5, 199, 235, 115, 137, 87, 31, 160, 115, 135, 181, 228, 142, 16, 170, 245, 32, 61, 64, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
secondary: [47, 24, 72, 61, 7, 130, 61, 129, 114, 181, 161, 121, 23, 223, 243, 109, 63, 129, 161, 240, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
```

SemSan should be combined with other fuzz engines (especially for cryptofuzz
since SemSan does not support custom mutators at the momement) that are known
to be great at maximising coverage. SemSan's `--foreign-corpus` option can be
used for this purpose:

```
semsan cryptofuzz1 cryptofuzz2 fuzz --seeds <corpus> --solutions <location for solutions> \
  --foreign-corpus <e.g. libfuzzer corpus>
```

## Building cryptofuzz for QEMU-based Emulation with SemSan:

The library under test, the corresponding cryptofuzz module and cryptofuzz
itself need to be build with a cross compiler for the targeted architecture.

Additionally, `qemu_harness.cpp` needs to be build and linked into the
crptofuzz binary. It acts as the entry point for SemSan's qemu executor.

```
$CXX -static ../qemu_harness.cpp -c -o qemu_harness.o
$AR rcs qemu_harness.a qemu_harness.o
LIBFUZZER_LINK="./qemu_harness.a" LINK_FLAGS="-static" make -j$(nproc)
```

SemSan will need to be compiled for the corresponding architecture:

```
cargo build --release --features qemu_arm --bin semsan-arm
```

One everything is build, SemSan can be invoked as follows:

```
semsan-arm cryptofuzz-compiled-for-host cryptofuzz-compiler-for-arm32 fuzz \
  --seeds <corpus> --solutions <location for solutions>
```

Note: Only the secondary executor will run under QEMU, the primary executor
always has to be compiled (with the afl++ compiler) for the host architecture.
