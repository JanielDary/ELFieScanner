#!/bin/bash
set -e

# Activate Holy Build Box environment.
source /hbb_exe/activate

set -x

# Install static ssdeep library
tar xzf /io/holy-build-box_scripts/ssdeep-2.14.1.tar.gz
cd ssdeep-2.14.1
env CFLAGS="$STATICLIB_CFLAGS" CXXFLAGS="$STATICLIB_CXXFLAGS" \
./configure --prefix=/hbb_exe --disable-shared --enable-static
make
make install
cd ..

# Compile
g++ $CFLAGS /io/**.cpp /io/**.h -o /io/ELFie_portable $LDFLAGS -lfuzzy -pthread

# Verify result
libcheck /io/ELFie_portable