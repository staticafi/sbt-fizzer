# SBT-Fizzer

Experimentations with gray-box program fuzzing.

## Building the fuzzer

### Prerequisites
    - Linux 
    - LLVM (>= 12.0.1)
    - Boost (Tested on >= 1.75.0)

### Install
    - mkdir build
    - cd build
    - cmake ..
    - cmake --build . (or specify your generator of choice)

The default install directory is `${PROJECT_SOURCE_DIR}/dist`. Install directory can be configured with `-DCMAKE_INSTALL_PREFIX=/path/to/fizzer/install/prefix`. Client building requires clang/clang++; run `export CC=clang` and `export CXX=clang++` before building.

## Usage
The binaries are found in `${CMAKE_INSTALL_PREFIX}/tools`

Instrumenting the target program:

`fizzer_instrument [-h] [--output_dir OUTPUT_DIR] target_file`

Building the client:

`fizzer_build_client [-h] [--output_dir OUTPUT_DIR] [--no_instrument | --instrument FLAGS] target_file`

Instrumenting, building, and running fuzzing in one:

`fizzer [-h] [--output_dir OUTPUT_DIR] [--no_instrument | --instrument FLAGS] [--clang FLAGS] [--max_seconds SECONDS] target_file`
