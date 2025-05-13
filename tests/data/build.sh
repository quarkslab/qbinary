#!/bin/sh

gcc -o sample_gcc_O0_x86_g sample.c -O0 -m32 -g
gcc -o sample_gcc_O0_x86_s sample.c -O0 -m32
gcc -o sample_gcc_O2_x86_g sample.c -O2 -m32 -g
gcc -o sample_gcc_O2_x86_s sample.c -O2 -m32
gcc -o sample_gcc_O0_x64_g sample.c -O0 -g
gcc -o sample_gcc_O0_x64_s sample.c -O0
gcc -o sample_gcc_O2_x64_g sample.c -O2 -g
gcc -o sample_gcc_O2_x64_s sample.c -O2

clang -o sample_clang_O0_x86_g sample.c -O0 -m32 -g
clang -o sample_clang_O0_x86_s sample.c -O0 -m32
clang -o sample_clang_O2_x86_g sample.c -O2 -m32 -g
clang -o sample_clang_O2_x86_s sample.c -O2 -m32
clang -o sample_clang_O0_x64_g sample.c -O0 -g
clang -o sample_clang_O0_x64_s sample.c -O0
clang -o sample_clang_O2_x64_g sample.c -O2 -g
clang -o sample_clang_O2_x64_s sample.c -O2

rm *.i64 *.id0 *.id1 *.id2 *.nam *.til
ls sample_* | grep -v \\..* | while read aa; do quokka-cli -i /home/patacca/ida-pro-9.0 $aa; done
rm *.i64
ls sample_* | grep -v \\..* | while read aa; do binexporter -i /home/patacca/idapro-8.2 $aa; done
rm *.i64