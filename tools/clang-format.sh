#!/bin/bash

 find ../src ../examples ../tests -path "../src/extern" -prune -o -path "../src/tinycrypt" -prune -o -path "../src/include/tinycrypt" -prune -o \( -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.ino" \) | grep -v "../src/tinycrypt" | grep -v "../src/include/tinycrypt" | xargs -I {} clang-format -style=file -i {}

