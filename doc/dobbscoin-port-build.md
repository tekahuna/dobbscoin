# Dobbscoin port build and verification

**Experimental candidate only. This branch is not a working Dobbscoin node and must not be used on public networks.** Its standalone header, reorganization-depth, subsidy, version, AuxPoW codec, and commitment helpers are not wired into runtime validation, networking, storage, activation, or chain selection.

This note describes two separate build paths for the experimental port candidate. The local CMake path is for quick compile and test feedback. The Guix path is for reproducible build candidates and needs a suitable builder with Guix installed.

## Local Linux development build

For the general CMake, compiler, Boost, libevent, and other Unix build prerequisites, follow the Bitcoin Core instructions in [build-unix.md](build-unix.md). The abbreviated configuration below assumes those dependencies are already available.

From the candidate source directory, configure a headless test build:

```sh
cmake -S . -B build \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DBUILD_TESTS=ON \
  -DBUILD_GUI=OFF \
  -DENABLE_WALLET=OFF \
  -DENABLE_IPC=OFF
```

Build the unit-test binary and run a focused suite:

```sh
cmake --build build --parallel 4 --target test_bitcoin
./build/bin/test_bitcoin --run_test=scrypt_tests --log_level=test_suite
```

Use the same build directory for incremental development. Reconfigure after changing CMake options. The test target can also run a named suite such as `pow_tests` or `serialize_tests`; it does not imply full functional, wallet, GUI, or cross-platform coverage. Keep generated files in the out-of-source build directory.

Use dependencies installed or configured for the build environment. If shared libraries are outside the system loader's search path, configure the loader path for that environment before running the test binary.

## Guix reproducible candidate build

Run Guix from a clean, immutable candidate commit in an environment with a working Guix daemon, store, sandbox support, dependency access, and adequate disk space. First make sure every intended file, including new files, is committed:

```sh
git status --porcelain
git rev-parse HEAD
git rev-parse HEAD^{tree}
```

The worktree must be clean. The Guix build script checks tracked changes, and its build helper creates the source archive with `git archive HEAD`; untracked or uncommitted files therefore will not be present in the build input. Do not use `FORCE_DIRTY_WORKTREE` to stand in for a fixed source identity.

The first bounded target is x86_64 Linux:

```sh
env HOSTS=x86_64-linux-gnu ./contrib/guix/guix-build
```

For each run, retain the candidate commit and tree, target, Guix version and channel, manifest and dependency inputs, toolchain identities, build options, source timestamp, full build log, and SHA-256 for every unsigned artifact. A successful build on one machine establishes only that build result. To claim independent reproducibility, have a second builder use the same recorded inputs and compare every artifact hash.

## Current port status

The pure 80-byte header identity and generic Scrypt primitive, source-derived reorg-depth, subsidy and header-version/activation helpers, and standalone AuxPoW codec and commitment checker have isolated unit coverage. None is wired into runtime block validation. The CMake build is developer feedback only; this candidate has not established Dobbscoin consensus parity, historical chain acceptance, or network readiness.

No Guix build, unsigned artifact, or independently matched reproducibility build has been produced for this candidate. Use a suitable Guix builder and independently compare artifacts before making build-reproducibility claims.
