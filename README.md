# zip_bruteforce_research

ZIP password brute-force analysis tool for Apple Silicon M4 (CPU + Metal GPU).

## Prerequisites

- macOS on Apple Silicon
- CMake 3.20+, C++20 compiler (Xcode Command Line Tools)

```bash
brew install cmake libzip sqlite3 googletest
```

## Build

```bash
mkdir -p build && cd build
cmake ..
cmake --build .
```

## Benchmark

```bash
./build/zipbrute --benchmark
```

Key options:
- `--mode cpu|gpu|both` (default: both)
- `--repeat N` — number of experiment repetitions (default: 3)
- `--output-dir <path>` — results directory
- `--max-len N` - max len of password
- `--random-seed` - for random passoword in auto generated archives
