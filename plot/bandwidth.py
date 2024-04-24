import pwn
import matplotlib.pyplot as plt

pwn.context.timeout = pwn.pwnlib.timeout.Timeout.forever

times_for_dumb = []
times_for_with_blocks = []

for i in range(25):
    r_dumb = pwn.process(["./transpose_dumb.out", str(i)])
    try:
        r_dumb.recvuntil(b"Time: ")
        time_dumb = float(r_dumb.recvline().strip().decode())
    except:
        pass
    ret = r_dumb.poll()

    if ret is not None and ret != 0:
        print(f"Error for dumb: {ret}")
        break

    r_with_blocks = pwn.process(["./transpose_with_blocks.out", str(i)])
    try:
        r_with_blocks.recvuntil(b"Time: ")
        time_with_blocks = float(r_with_blocks.recvline().strip().decode())
    except:
        pass
    ret = r_with_blocks.poll()

    if ret is not None and ret != 0:
        print(f"Error for with blocks: {ret}")
        break

    times_for_dumb.append(time_dumb)
    times_for_with_blocks.append(time_with_blocks)
    print(f"{i} takes {time_dumb}s for dumb and {time_with_blocks}s for with blocks")

bandwidth_for_dumb = [((1 << i) / time) for i, time in enumerate(times_for_dumb)]
bandwidth_for_with_blocks = [((1 << i) / time) for i, time in enumerate(times_for_with_blocks)]

bandwidth_for_dumb = map(bandwidth_for_dumb, lambda x: x * 1_000_000)
bandwidth_for_with_blocks = map(bandwidth_for_with_blocks, lambda x: x * 1_000_000)

plt.xlabel("Matrix size")
plt.ylabel("Memory Bandwidth (B/s)")
plt.title("Matrix size vs Memory Bandwidth")

plt.grid(True)

plt.plot(range(len(times_for_dumb)), times_for_dumb, label="Dumb")
plt.plot(range(len(times_for_with_blocks)), times_for_with_blocks, label="With blocks")

plt.legend()

plt.show()
