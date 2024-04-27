import subprocess
import re

times_for_naive = []
times_for_with_blocks = []

MAX_SIZE = 2

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

times_for_naive = [max(1e-6, time) for time in times_for_naive]
times_for_with_blocks = [max(1e-6, time) for time in times_for_with_blocks]

print(times_for_naive)
print(times_for_with_blocks)