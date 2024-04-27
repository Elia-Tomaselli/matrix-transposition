import os

MAX_SIZE = 16

import subprocess
import re

D1_miss_rates_naive = []
LLd_miss_rates_naive = []
D1_miss_rates_with_blocks = []
LLd_miss_rates_with_blocks = []

MAX_SIZE = 2
for i in range(MAX_SIZE):
    process = subprocess.Popen(
        f'srun --nodes=1 --ntasks=1 --cpus-per-task=1 --gres=gpu:0 --partition=edu5 "valgrind --tool=cachegrind --cachegrind-out-file=/dev/null ./transpose_naive.out {i}"',
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error for naive: {process.returncode}")
        break

    D1_miss_rate_naive = float(re.search(r"D1  miss rate: (.+)%", stdout.decode()).group(1))
    LLd_miss_rate_naive = float(re.search(r"LLd miss rate: (.+)%", stdout.decode()).group(1))

    process = subprocess.Popen(
        f"srun --nodes=1 --ntasks=1 --cpus-per-task=1 --gres=gpu:0 --partition=edu5 ./transpose_with_blocks.out {i}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error for with blocks: {process.returncode}")
        break

    D1_miss_rate_with_blocks = float(re.search(r"D1  miss rate: (.+)%", stdout.decode()).group(1))
    LLd_miss_rate_with_blocks = float(re.search(r"LLd miss rate: (.+)%", stdout.decode()).group(1))

    D1_miss_rates_naive.append(D1_miss_rate_naive)
    LLd_miss_rates_naive.append(LLd_miss_rate_naive)
    D1_miss_rates_with_blocks.append(D1_miss_rate_with_blocks)
    LLd_miss_rates_with_blocks.append(LLd_miss_rate_with_blocks)

    print(f"Done for {i}")
    print(f"Miss rates for naive: {D1_miss_rate_naive}%, {LLd_miss_rate_naive}%")
    print(f"Miss rates for with blocks: {D1_miss_rate_with_blocks}%, {LLd_miss_rate_with_blocks}%")

print(D1_miss_rates_naive)
print(LLd_miss_rate_naive)
print(D1_miss_rate_with_blocks)
print(LLd_miss_rate_with_blocks)
