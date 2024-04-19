import pwn
import matplotlib.pyplot as plt

pwn.context.timeout = pwn.pwnlib.timeout.Timeout.forever

D1_miss_rates_dumb = []
LLd_miss_rates_dumb = []
D1_miss_rates_with_blocks = []
LLd_miss_rates_with_blocks = []

for i in range(13):

    r_dumb = pwn.process(
        ["valgrind", "--tool=cachegrind", "--cachegrind-out-file=/dev/null", "./transpose_dumb.out", str(i)]
    )
    try:
        # r_dumb.interactive()
        r_dumb.recvuntil(b"D1  miss rate:")
        D1_miss_rate_dumb = float(r_dumb.recvuntil("%").decode()[:-1].strip())
        r_dumb.recvuntil(b"LLd miss rate:")
        LLd_miss_rate_dumb = float(r_dumb.recvuntil("%").decode()[:-1].strip())
    except:
        pass
    ret = r_dumb.poll()

    if ret is not None and ret != 0:
        print(f"Error for dumb: {ret}")
        break

    r_with_blocks = pwn.process(
        ["valgrind", "--tool=cachegrind", "--cachegrind-out-file=/dev/null", "./transpose_with_blocks.out", str(i)]
    )
    try:
        r_with_blocks.recvuntil(b"D1  miss rate:")
        D1_miss_rate_with_blocks = float(r_with_blocks.recvuntil("%").decode()[:-1].strip())
        r_with_blocks.recvuntil(b"LLd miss rate:")
        LLd_miss_rate_with_blocks = float(r_with_blocks.recvuntil("%").decode()[:-1].strip())
    except:
        pass
    ret = r_with_blocks.poll()

    if ret is not None and ret != 0:
        print(f"Error for with blocks: {ret}")
        break

    D1_miss_rates_dumb.append(D1_miss_rate_dumb)
    LLd_miss_rates_dumb.append(LLd_miss_rate_dumb)
    D1_miss_rates_with_blocks.append(D1_miss_rate_with_blocks)
    LLd_miss_rates_with_blocks.append(LLd_miss_rate_with_blocks)

    print(f"Done for {i}")
    print(f"Miss rates for dumb: {D1_miss_rate_dumb}%, {LLd_miss_rate_dumb}%")
    print(f"Miss rates for with blocks: {D1_miss_rate_with_blocks}%, {LLd_miss_rate_with_blocks}%")


plt.plot(D1_miss_rates_dumb, label="Dumb (D1)")
plt.plot(D1_miss_rates_with_blocks, label="With blocks (D1)")
plt.plot(LLd_miss_rates_dumb, label="Dumb (LLd)")
plt.plot(LLd_miss_rates_with_blocks, label="With blocks (LLd)")
plt.xlabel("Matrix size")
plt.ylabel("D1 miss rate (%)")
plt.legend()
plt.show()
