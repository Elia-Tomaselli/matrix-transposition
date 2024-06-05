from pprint import pprint
import matplotlib.pyplot as plt
import os
import pwn
import shutil
import argparse

parser = argparse.ArgumentParser(description="Plots the benchmark results of the matrix transpose algorithm")
parser.add_argument(
    "--skip-compilation", action="store_true", help="Skips the compilation of the C code", required=False
)
parser.add_argument(
    "--max-exponent", type=int, default=20, help="The maximum exponent of the matrix size", required=False
)
parser.add_argument("--show", action="store_true", help="Shows the plots", required=False)
args = parser.parse_args()

CURR_DIR = os.path.dirname(os.path.abspath(__file__))
GPU_DIR = os.path.dirname(CURR_DIR)
EXECUTABLES_DIR = os.path.join(CURR_DIR, "executables")

def plot(
    title,
    x_label,
    y_label,
    xs,
    ys,
    labels,
    x_ticks,
    x_ticks_labels,
    y_ticks,
    y_ticks_labels,
    path,
    roofline=None,
    roofline_label="",
    show=False,
):
    assert len(xs) == len(ys) == len(labels)

    # plt.title(title, **CSFONT)
    if title != "":
        plt.title(title)

    # plt.xlabel(x_label, **HFONT)
    plt.xlabel(x_label)
    plt.ylabel(y_label)

    plt.xticks(x_ticks, x_ticks_labels, rotation=60)
    plt.yticks(y_ticks, y_ticks_labels)

    for i in range(len(xs)):
        plt.plot(xs[i], ys[i], label=labels[i])

    if roofline is not None:
        plt.axhline(y=roofline, color="gray", linestyle="--", linewidth=1)
        x_center = plt.xlim()[0] + 0.5 * (plt.xlim()[1] - plt.xlim()[0])
        plt.text(
            x_center, roofline + 1, roofline_label, color="black", verticalalignment="bottom", fontsize=8, ha="center"
        )

    plt.grid(True, color="lightgray", linestyle="--")

    plt.legend(loc="upper left")

    plt.savefig(path, dpi=300, bbox_inches="tight")

    if show:
        plt.show()

    plt.close()


# Compiles the C code and copies the executable "transpose.out" to the current directory
def compile_and_copy(naive: bool) -> None:
    # Compile the C code
    os.chdir(GPU_DIR)
    os.system("make clean")
    if naive:
        os.system("make naive")
    else:
        os.system("make optimized")

    # Copy the executable to the current directory
    executable_name = f"transpose_{'naive' if naive else 'optimized'}.out"
    shutil.copy(os.path.join(GPU_DIR, "transpose.out"), os.path.join(EXECUTABLES_DIR, executable_name))


def get_benchmark(naive: bool, exponent: int):
    LOOPS = 5

    # Run the benchmark
    os.chdir(EXECUTABLES_DIR)
    executable_name = f"./transpose_{'naive' if naive else 'optimized'}.out"
    p = pwn.process(["./run.sh", executable_name, str(exponent)])

    times = []
    for _ in range(LOOPS):
        p.recvuntil(b"Time: ")
        time = float(p.recvuntil(b"ms")[:-2].decode().strip())
        times.append(time)

    p.close()

    return times


curr_dir = os.path.dirname(os.path.abspath(__file__))

# Compile and copy the executables to the current directory
if not args.skip_compilation:
    if not os.path.exists(os.path.join(curr_dir, "executables")):
        os.makedirs(os.path.join(curr_dir, "executables"))
    compile_and_copy(naive=True)
    compile_and_copy(naive=False)

# Run the benchmarks
naive_times = {}
optimized_times = {}
exponents = list(range(5, args.max_exponent + 1))

for exponent in exponents:
    print(f"Running benchmarks for 2^{exponent}...")
    naive_time = get_benchmark(naive=True, exponent=exponent)
    optimized_time = get_benchmark(naive=False, exponent=exponent)
    naive_times[exponent] = naive_time
    optimized_times[exponent] = optimized_time

# Average the times
naive_times = [sum(times) / len(times) for times in naive_times.values()]
optimized_times = [sum(times) / len(times) for times in optimized_times.values()]

# For NVIDIA GeForce RTX 4060 Ti
# memory_clock_rate = 9001  # MHz
# memory_bus_width = 128  # bit
# theoretical_bandwidth = ((memory_clock_rate * 10**6) * (memory_bus_width / 8) * 2) / 10**9  # GB/s

# For NVIDIA A30
memory_clock_rate = 1215  # MHz
memory_bus_width = 3072  # bit
theoretical_bandwidth = ((memory_clock_rate * 10**6) * (memory_bus_width / 8) * 2) / 10**9  # GB/s

max_time = max(max(naive_times), max(optimized_times))

plot(
    "",
    "Matrix Size (2^x)",
    "Time (ms)",
    [exponents, exponents],
    [naive_times, optimized_times],
    ["Naive", "Optimized"],
    exponents,
    [f"2^{exponent}" for exponent in exponents],
    [i for i in range(0, int(max_time) + 200, 200)],
    [f"{i} ms" for i in range(0, int(max_time) + 200, 200)],
    os.path.join(curr_dir, "images", "time_vs_matrix_size.png"),
    show=args.show,
)

# Sizes of the matrices in bytes
matrix_sizes = [((2**exponent) ** 2) * 4 for exponent in exponents]
print(f"Matrix size for exponent {5}: {matrix_sizes[0]}")

# Effective bandwidth in GB/s
# The times 2 is because in order to transpose a matrix, we need to read and write each element
effective_bandwidth_naive = [
    ((matrix_sizes[index] * 2) / 10**9) / (time / 1000) for index, time in enumerate(naive_times)
]
effective_bandwidth_optimized = [
    ((matrix_sizes[index] * 2) / 10**9) / (time / 1000) for index, time in enumerate(optimized_times)
]

plot(
    "",
    "Matrix Size (2^x)",
    "Effective Bandwidth (GB/s)",
    [exponents, exponents],
    [effective_bandwidth_naive, effective_bandwidth_optimized],
    ["Naive", "Optimized"],
    exponents,
    [f"2^{exponent}" for exponent in exponents],
    [i for i in range(0, int(theoretical_bandwidth), 20)],
    [f"{i} GB/s" for i in range(0, int(theoretical_bandwidth), 20)],
    os.path.join(curr_dir, "images", "effective_bandwidth_vs_matrix_size.png"),
    roofline=theoretical_bandwidth,
    roofline_label="Theoretical Memory Bandwidth",
    show=args.show,
)
