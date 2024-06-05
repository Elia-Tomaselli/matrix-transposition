import matplotlib.pyplot as plt
import numpy as np
import pwn

pwn.context.timeout = pwn.pwnlib.timeout.Timeout.forever
pwn.context.log_level = "error"

D1_miss_rates_naive = []
LLd_miss_rates_naive = []
D1_miss_rates_with_blocks = []
LLd_miss_rates_with_blocks = []

MAX_SIZE = 16

for i in range(MAX_SIZE):
    # r_naive = pwn.process(
    #     ["valgrind", "--tool=cachegrind", "--cachegrind-out-file=/dev/null", "./transpose_naive.out", str(i)]
    # )
    # r_naive.recvuntil(b"D1  miss rate:")
    # D1_miss_rate_naive = float(r_naive.recvuntil(b"%").decode()[:-1].strip())
    # r_naive.recvuntil(b"LLd miss rate:")
    # LLd_miss_rate_naive = float(r_naive.recvuntil(b"%").decode()[:-1].strip())
    # r_naive.recvall()
    # ret = r_naive.poll()

    # if ret is not None and ret != 0:
    #     print(f"Error for naive: {ret}")
    #     break

    r_with_blocks = pwn.process(
        ["valgrind", "--tool=cachegrind", "--cachegrind-out-file=/dev/null", "./transpose_with_blocks.out", str(i)]
    )
    r_with_blocks.recvuntil(b"D1  miss rate:")
    D1_miss_rate_with_blocks = float(r_with_blocks.recvuntil(b"%").decode()[:-1].strip())
    r_with_blocks.recvuntil(b"LLd miss rate:")
    LLd_miss_rate_with_blocks = float(r_with_blocks.recvuntil(b"%").decode()[:-1].strip())
    r_with_blocks.recvall()
    ret = r_with_blocks.poll()

    if ret is not None and ret != 0:
        print(f"Error for with blocks: {ret}")
        break

    # D1_miss_rates_naive.append(D1_miss_rate_naive)
    # LLd_miss_rates_naive.append(LLd_miss_rate_naive)
    D1_miss_rates_with_blocks.append(D1_miss_rate_with_blocks)
    LLd_miss_rates_with_blocks.append(LLd_miss_rate_with_blocks)

    print(f"Done for {i}")
    # print(f"Miss rates for naive: {D1_miss_rate_naive}%, {LLd_miss_rate_naive}%")
    print(f"Miss rates for with blocks: {D1_miss_rate_with_blocks}%, {LLd_miss_rate_with_blocks}%")


plt.xlabel("Matrix size")
plt.ylabel("Cache miss rate (%)")

plt.title("Matrix size vs Cache Miss")

plt.xticks(np.arange(MAX_SIZE), [f"2^{i}" for i in range(MAX_SIZE)], rotation=60)

plt.grid(True)

# plt.plot(D1_miss_rates_naive, label="naive (D1)")
plt.plot(D1_miss_rates_with_blocks, label="with blocks (D1)")

# plt.plot(LLd_miss_rates_naive, label="naive (LLd)")
plt.plot(LLd_miss_rates_with_blocks, label="with blocks (LLd)")

plt.legend(loc="upper center", bbox_to_anchor=(0.5, -0.2), fancybox=True, shadow=True, ncol=4)

# Hide top and right spines
plt.gca().spines["top"].set_visible(False)
plt.gca().spines["right"].set_visible(False)

plt.savefig("images/cache.png", dpi=300, bbox_inches="tight")
