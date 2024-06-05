# Matrix Tranposition

## To compile

Either `cd` into the **cpu** (deliverable 1) or **gpu** (deliverable 2) directories.

To compile the program for deliverable 2, you have two options:

- For the naive approach, run: `make naive`
- For the optimized approach, run: `make optimized`

These commands will compile all C files in the **src** directory, place the compiled object files in the **obj** directory, and create the **transpose.out** executable.

## To run

Run the compiled program with `./transpose.out <exponent>`, it will transpose a randomly generated square matrix of size 2^exponent.

## To plot and view benchmarks

To generate plots, navigate to **gpu/plot** and run the Python script from anywhere, and run `python3 main.py`.
This will create **time.png** and **bandwidth.png** image files in the **gpu/plot/images** directory.

Options:

- `--skip-compilation`: Avoid recompiling and copying the executables in the **gpu/plot/executables** directory.
- `--max-exponent`: Specify the maximum matrix size as $2^x$ for benchmarking.
- `--use-cache`: Use previously cached results to avoid rerunning benchmarks. Useful for updating plots without rerunning benchmarks.
- `--show`: Display the plots before saving them.
