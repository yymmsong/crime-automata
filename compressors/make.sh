#!/bin/bash
set -euo pipefail


# build zlib
echo "Building zlib..."
cmake -S zlib -B zlib/build -DCMAKE_BUILD_TYPE=Release
cmake --build zlib/build --clean-first

# build cloudflare-zlib
# With CMAKE_BUILD_TYPE=Release, our queries sometimes trigger segmentation faults in the minigzip program of cloudflare-zlib.
echo "Building cloudflare-zlib..."
cmake -S cloudflare-zlib -B cloudflare-zlib/build -DCMAKE_BUILD_TYPE=Debug -DBUILD_EXAMPLES=ON -DCMAKE_POLICY_VERSION_MINIMUM=3.5
cmake --build cloudflare-zlib/build --clean-first

# build chromium-zlib
echo "Building chromium-zlib..."
cmake -S chromium-zlib -B chromium-zlib/build -DCMAKE_BUILD_TYPE=Release -DZLIB_INSTALL=OFF -DBUILD_MINIGZIP=ON
cmake --build chromium-zlib/build --clean-first

# build zlib-ng
echo "Building zlib-ng..."
cmake -S zlib-ng -B zlib-ng/build -DCMAKE_BUILD_TYPE=Release
cmake --build zlib-ng/build --clean-first

# build flate2-zpipe
echo "Building flate2-zpipe..."
cargo clean --manifest-path flate2-zpipe/Cargo.toml
cargo build --release --manifest-path flate2-zpipe/Cargo.toml

# build go-zpipe (for flate in Go)
echo "Building go-zpipe..."
go build -C zlib-go


echo "All done. Enjoy :)"
