import os
import sys

if len(sys.argv) == 1:
    print("Usage: python update_executables.py <naive or with_block>")
    exit(1)
elif sys.argv[1] == "naive":
    os.system("cd ../.. && make clean && make && mv transpose.out plot/local/transpose_naive.out")
elif sys.argv[1] == "with_blocks":
    os.system("cd ../.. && make clean && make && mv transpose.out plot/local/transpose_with_blocks.out")
