import subprocess
import re

times_for_naive = []
times_for_with_blocks = []

MAX_SIZE = 16

for i in range(MAX_SIZE):
    process = subprocess.Popen(
        f"srun --nodes=1 --ntasks=1 --cpus-per-task=1 --gres=gpu:0 --partition=edu5 ./transpose_naive.out {i}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error for naive: {process.returncode}")
        break

    time_naive = float(re.search(r"Time: (.+)\n", stdout.decode()).group(1))

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

    time_with_blocks = float(re.search(r"Time: (.+)\n", stdout.decode()).group(1))

    times_for_naive.append(time_naive)
    times_for_with_blocks.append(time_with_blocks)
    print(f"{i} takes {time_naive}s for naive and {time_with_blocks}s for with blocks")

# Size of float times size of matrix squared in bytes
matrix_byte_sizes = [4 * ((1 << i) ** 2) for i in range(MAX_SIZE)]

bandwidth_for_naive = [matrix_byte_sizes[i] / max(time, 1e-6) for i, time in enumerate(times_for_naive)]
bandwidth_for_with_blocks = [matrix_byte_sizes[i] / max(time, 1e-6) for i, time in enumerate(times_for_with_blocks)]

bandwidth_for_naive = [bandwidth / 1e9 for bandwidth in bandwidth_for_naive]
bandwidth_for_with_blocks = [bandwidth / 1e9 for bandwidth in bandwidth_for_with_blocks]

print(times_for_naive)
print(times_for_with_blocks)