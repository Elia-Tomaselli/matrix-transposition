import matplotlib.pyplot as plt
import numpy as np

MAX_SIZE = 16

# Time

times_for_naive = [
    1e-06,
    1e-06,
    1e-06,
    1e-06,
    1e-06,
    2e-06,
    4e-06,
    2.8e-05,
    0.000129,
    0.000579,
    0.004057,
    0.025616,
    0.138537,
    0.627349,
    3.010956,
    13.230228,
]
times_for_with_blocks = [
    1e-06,
    1e-06,
    1e-06,
    1e-06,
    2e-06,
    1e-06,
    5e-06,
    2.4e-05,
    9.9e-05,
    0.000514,
    0.001692,
    0.006582,
    0.027351,
    0.108269,
    0.485296,
    2.232263,
]

plt.xlabel("Matrix size")
plt.ylabel("Time (s)")

plt.title("Matrix size vs Time")

plt.xticks(np.arange(MAX_SIZE), [f"2^{i}" for i in range(MAX_SIZE)], rotation=60)

plt.grid(True)

plt.plot(range(len(times_for_naive)), times_for_naive, label="naive")
plt.plot(range(len(times_for_with_blocks)), times_for_with_blocks, label="With blocks")

plt.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), fancybox=True, shadow=True, ncol=2)

# Hide top and right spines
plt.gca().spines["top"].set_visible(False)
plt.gca().spines["right"].set_visible(False)

plt.savefig("images/time.png", dpi=300, bbox_inches="tight")
plt.clf()

# Bandwidth

bandwidth_for_naive = [
    0.004,
    0.016,
    0.064,
    0.256,
    1.024,
    2.048,
    1.6383999999999999,
    2.62144,
    2.2995087719298244,
    1.8657935943060497,
    1.044918784255107,
    0.6480942558040715,
    0.4891209667427098,
    0.4283275666740066,
    0.35731389220369264,
    0.32679900004070755,
]
bandwidth_for_with_blocks = [
    0.002,
    0.016,
    0.064,
    0.256,
    1.024,
    4.096,
    3.2767999999999997,
    2.978909090909091,
    2.759410526315789,
    2.072284584980237,
    2.2684175229853976,
    2.536621711521016,
    2.44735290470807,
    2.4777818843054544,
    2.1908582598280764,
    1.7915859873966493,
]

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
plt.clf()

# Cache

D1_miss_rates_naive = [4.5, 4.5, 4.5, 4.4, 4.1, 3.3, 2.0, 3.7, 3.6, 3.5, 3.5, 3.5, 3.9, 3.9, 3.9, 3.9]
LLd_miss_rates_naive = [3.7, 3.7, 3.7, 3.6, 3.3, 2.7, 1.6, 0.8, 0.5, 0.4, 0.4, 0.4, 3.5, 3.5, 3.5, 3.5]
D1_miss_rates_with_blocks = [4.5, 4.5, 4.5, 4.4, 4.1, 3.3, 2.0, 1.1, 0.7, 0.8, 3.5, 3.5, 3.5, 3.5, 3.5, 3.5]
LLd_miss_rates_with_blocks = [3.7, 3.7, 3.7, 3.6, 3.3, 2.7, 1.6, 0.8, 0.5, 0.4, 0.4, 0.4, 0.6, 0.6, 0.6, 0.6]

plt.xlabel("Matrix size")
plt.ylabel("Cache miss rate (%)")

plt.title("Matrix size vs Cache Miss")

plt.xticks(np.arange(MAX_SIZE), [f"2^{i}" for i in range(MAX_SIZE)], rotation=60)

plt.grid(True)

plt.plot(D1_miss_rates_naive, label="naive (D1)")
plt.plot(D1_miss_rates_with_blocks, label="with blocks (D1)")

plt.plot(LLd_miss_rates_naive, label="naive (LLd)")
plt.plot(LLd_miss_rates_with_blocks, label="with blocks (LLd)")

plt.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), fancybox=True, shadow=True, ncol=4)

# Hide top and right spines
plt.gca().spines["top"].set_visible(False)
plt.gca().spines["right"].set_visible(False)

plt.savefig("images/cache.png", dpi=300, bbox_inches="tight")
