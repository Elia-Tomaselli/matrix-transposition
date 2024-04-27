import matplotlib.pyplot as plt
import numpy as np
import pwn

pwn.context.timeout = pwn.pwnlib.timeout.Timeout.forever
pwn.context.log_level = "error"

times_for_naive = []
times_for_with_blocks = []

MAX_SIZE = 16

for i in range(MAX_SIZE):
    r_naive = pwn.process(["./transpose_naive.out", str(i)])
    r_naive.recvuntil(b"Time: ")
    time_naive = float(r_naive.recvline().strip().decode())
    r_naive.recvall()
    ret = r_naive.poll()

    if ret is not None and ret != 0:
        print(f"Error for naive: {ret}")
        break

    r_with_blocks = pwn.process(["./transpose_with_blocks.out", str(i)])
    r_with_blocks.recvuntil(b"Time: ")
    time_with_blocks = float(r_with_blocks.recvline().strip().decode())
    r_with_blocks.recvall()
    ret = r_with_blocks.poll()

    if ret is not None and ret != 0:
        print(f"Error for with blocks: {ret}")
        break

    times_for_naive.append(time_naive)
    times_for_with_blocks.append(time_with_blocks)
    print(f"{i} takes {time_naive}s for naive and {time_with_blocks}s for with blocks")

# Size of float times size of matrix squared in bytes
matrix_byte_sizes = [4 * ((1 << i) ** 2) for i in range(MAX_SIZE)]

bandwidth_for_naive = [matrix_byte_sizes[i] / max(time, 1e-6) for i, time in enumerate(times_for_naive)]
bandwidth_for_with_blocks = [matrix_byte_sizes[i] / max(time, 1e-6) for i, time in enumerate(times_for_with_blocks)]

bandwidth_for_naive = [bandwidth / 1e9 for bandwidth in bandwidth_for_naive]
bandwidth_for_with_blocks = [bandwidth / 1e9 for bandwidth in bandwidth_for_with_blocks]

plt.xlabel("Matrix size")
plt.ylabel("Memory Bandwidth (GB/s)")

plt.title("Matrix size vs Memory Bandwidth")

plt.xticks(np.arange(MAX_SIZE), [f"2^{i}" for i in range(MAX_SIZE)], rotation=60)

plt.grid(True)

plt.plot(range(len(bandwidth_for_naive)), bandwidth_for_naive, label="naive")
plt.plot(range(len(bandwidth_for_with_blocks)), bandwidth_for_with_blocks, label="With blocks")

plt.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), fancybox=True, shadow=True, ncol=2)

# Hide top and right spines
plt.gca().spines["top"].set_visible(False)
plt.gca().spines["right"].set_visible(False)

plt.savefig("images/bandwidth.png", dpi=300, bbox_inches="tight")
