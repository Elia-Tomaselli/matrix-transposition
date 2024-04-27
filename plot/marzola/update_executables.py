import os
import sys

if len(sys.argv) == 1:
    print("Usage: python update_executables.py <path_to_executable>")
    exit(1)
elif sys.argv[1] == "naive":
    os.system("cd ../ && make clean && make && mv transpose.out plot/transpose_naive.out")
elif sys.argv[1] == "with_blocks":
    os.system("cd ../ && make clean && make WITH_BLOCKS=1 && mv transpose.out plot/transpose_with_blocks.out")
