# subnetooor

Sparq subnet source code.

## Requirements
* **GCC** with support for **C++17** or higher
* **CMake 3.19.0** or higher
* **Abseil (absl)**
* **Boost 1.74** or higher (components: *chrono, filesystem, program-options, system, thread, nowide*)
* **CryptoPP 8.2.0** or higher
* **gRPC** + **Protobuf 3.12** or higher + **libc-ares**
* **libscrypt**
* **OpenSSL 1.1.1**
* **zlib**

### One-liners

For **Debian 11 Bullseye or newer**:
* `sudo apt install build-essential cmake autoconf libtool pkg-config libabsl-dev libboost-{chrono,filesystem,program-options,system,thread,nowide}-dev libc-ares-dev libcrypto++-dev libgrpc-dev libgrpc++-dev libscrypt-dev libssl-dev zlib1g-dev openssl protobuf-compiler protobuf-compiler-grpc`

#### Caveats

* **Debian 11 Bullseye and older**: CMake version from repos is too old (3.18.4), has to be installed manually from [their website](https://cmake.org/download)

## Compiling
* Clone the project: `git clone https://github.com/subnetoors/subnetooor`
* Go to the project's root folder, create a "build" folder and change to it:
  * `cd subnetooor && mkdir build && cd build`
* Run `cmake` inside the build folder: `cmake ..`
  * Use `-DCMAKE_BUILD_TYPE=RelWithDebInfo` to build with debug symbols
* Build the executable: `cmake --build . -- -j$(nproc)`

