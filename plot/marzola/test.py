import re

output = b"==770164== Cachegrind, a cache and branch-prediction profiler\n==770164== Copyright (C) 2002-2017, and GNU GPL'd, by Nicholas Nethercote et al.\n==770164== Using Valgrind-3.19.0 and LibVEX; rerun with -h for copyright info\n==770164== Command: ./transpose_naive.out 0\n==770164== \n--770164-- warning: L3 cache found, using its data for the LL simulation.\n==770164== \n==770164== I   refs:      263,805\n==770164== I1  misses:      1,524\n==770164== LLi misses:      1,472\n==770164== I1  miss rate:    0.58%\n==770164== LLi miss rate:    0.56%\n==770164== \n==770164== D   refs:       79,422  (60,648 rd   + 18,774 wr)\n==770164== D1  misses:      3,283  ( 2,612 rd   +    671 wr)\n==770164== LLd misses:      2,764  ( 2,154 rd   +    610 wr)\n==770164== D1  miss rate:     4.1% (   4.3%     +    3.6%  )\n==770164== LLd miss rate:     3.5% (   3.6%     +    3.2%  )\n==770164== \n==770164== LL refs:         4,807  ( 4,136 rd   +    671 wr)\n==770164== LL misses:       4,236  ( 3,626 rd   +    610 wr)\n==770164== LL miss rate:      1.2% (   1.1%     +    3.2%  )\n"

D1_miss_rate_naive = float(re.search(r"D1  miss rate: (.+)%", output.decode()).group(1))
LLd_miss_rate_naive = float(re.search(r"LLd miss rate: (.+)%", output.decode()).group(1))

print(D1_miss_rate_naive)
print(LLd_miss_rate_naive)