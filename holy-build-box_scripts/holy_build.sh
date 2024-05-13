#!/bin/bash

# Save current path
current_path=$(pwd)

# Clear old project files and copy new ones in. 
rm -rf /root/io/*
mkdir /root/io              
cp -r $PWD/* /root/io
cd /root/io

# Execute holy build box script 'compile.sh' to compile portable code. 
docker run -t -i --rm -v `pwd`:/io phusion/holy-build-box-64:latest bash /io/holy-build-box_scripts/compile.sh

# Copy portable binary back to orignal path
cp ELFie_portable $current_path

# Clear files
rm -rf /root/io/*