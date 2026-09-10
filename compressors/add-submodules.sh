#!/bin/bash
set -euo pipefail

if git rev-parse --is-inside-git-dir; then
  echo "git repo already exists"
else
  git init ..
fi

echo "Removing empty directories..."
find . -maxdepth 1 -not -name "[@.]*" -type d -empty -print -delete

# zlib 1.3.2
git submodule add --force https://github.com/madler/zlib.git zlib
cd zlib
git fetch
git checkout --force v1.3.2
cd ..

# chromium-zlib 9ffe2c6
git submodule add --force https://chromium.googlesource.com/chromium/src/third_party/zlib chromium-zlib
cd chromium-zlib
git fetch
git checkout --force 9ffe2c6bfb76203167aa15b468050e3d34891562
cd ..

# cloudflare-zlib v1.2.8-181-g1252e25
git submodule add --force https://github.com/cloudflare/zlib.git cloudflare-zlib
cd cloudflare-zlib
git fetch
git checkout --force 1252e2565573fe150897c9d8b44d3453396575ff
cd ..

# zlib-ng 2.3.3
git submodule add --force https://github.com/zlib-ng/zlib-ng.git zlib-ng
cd zlib-ng
git fetch
git checkout --force 2.3.3
cd ..

# check status
git submodule status
