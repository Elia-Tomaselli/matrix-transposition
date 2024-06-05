#include <stdint.h>
#include <stdio.h>

#include "matrix.cuh"
#include "cuda_error.cuh"

#define LOOPS 5

#ifndef TILE_SIZE
#define TILE_SIZE 32 // Default value if not defined
#endif

#define LOG2(x) (                               \
    (x) <= 0 ? -1 : ((x) & ((x) - 1)) != 0 ? -1 \
                                           : __builtin_ctz(x))

__global__ void matrix_transpose_naive(matrix_type *dst, matrix_type *src, uint64_t size)
{
  int tilesPerRow = size / TILE_SIZE;

  int tileX = blockIdx.x % tilesPerRow;
  int tileY = blockIdx.x / tilesPerRow;

  int x = tileX * TILE_SIZE + (threadIdx.x % TILE_SIZE);
  int y = tileY * TILE_SIZE + (threadIdx.x / TILE_SIZE);

  dst[x * size + y] = src[y * size + x];
}

__global__ void matrix_transpose_optimized(matrix_type *dst, matrix_type *src, uint64_t size)
{
  // Shared memory for the tile, the extra element is for bank conflict avoidance
  __shared__ matrix_type tile[TILE_SIZE][TILE_SIZE + 1];

  int tilesPerRow = size / TILE_SIZE;

  int tileX = blockIdx.x % tilesPerRow;
  int tileY = blockIdx.x / tilesPerRow;

  // Local coordinates are the coordinates of the element within the block
  // Global coordinates are the coordinates of the element within the whole matrix
  int localX = threadIdx.x % TILE_SIZE;
  int localY = threadIdx.x / TILE_SIZE;
  int globalX = tileX * TILE_SIZE + localX;
  int globalY = tileY * TILE_SIZE + localY;

  tile[localY][localX] = src[globalY * size + globalX];

  __syncthreads();

  dst[globalY * size + globalX] = tile[localX][localY];
}

inline uint8_t parse_arguments(int argc, char **argv)
{
  if (argc != 2)
  {
    fprintf(stderr, "Usage: %s <exponent>\n", argv[0]);
    exit(1);
  }

  uint8_t exponent = (uint8_t)atoi(argv[1]);
  if (exponent == 0 && argv[1][0] != '0')
  {
    fprintf(stderr, "Error: Invalid input\n");
    exit(1);
  }

  uint8_t min_exponent = LOG2(TILE_SIZE);
  if (exponent < min_exponent)
  {
    fprintf(stderr, "Error: Exponent must be greater than or equal to %d\n", min_exponent);
    exit(1);
  }

  return exponent;
}

int main(int argc, char **argv)
{
  uint8_t exponent = parse_arguments(argc, argv);
  uint64_t size = 1 << exponent;

  matrix_t matrix;
  matrix_alloc(&matrix, size);
  matrix_t matrixT;
  matrix_alloc(&matrixT, size);

  srand(time(NULL));
  matrix_init_random(&matrix, size);

  // Get max threads per block
  int device;
  gpuErrchk(cudaGetDevice(&device));

  int maxThreadsPerBlock;
  gpuErrchk(cudaDeviceGetAttribute(&maxThreadsPerBlock, cudaDevAttrMaxThreadsPerBlock, device));
  // printf("Max threads per block: %d\n", maxThreadsPerBlock);

  int sharedMemPerBlock;
  gpuErrchk(cudaDeviceGetAttribute(&sharedMemPerBlock, cudaDevAttrMaxSharedMemoryPerBlock, device));
  // printf("Max shared memory per block: %d\n", sharedMemPerBlock);

  int block_size = TILE_SIZE * TILE_SIZE;
  int grid_size = size * size / block_size;
  // printf("Block size: %d\tGrid size: %d\n", block_size, grid_size);

  cudaEvent_t start;
  gpuErrchk(cudaEventCreate(&start));
  cudaEvent_t stop;
  gpuErrchk(cudaEventCreate(&stop));

#ifdef NAIVE
  printf("Naive\n");

  // Warmup kernel
  matrix_transpose_naive<<<grid_size, block_size>>>(matrixT.d, matrix.d, size);
  gpuErrchk(cudaPeekAtLastError());
  gpuErrchk(cudaDeviceSynchronize());

  for (int i = 0; i < LOOPS; i++)
  {
    gpuErrchk(cudaEventRecord(start));

    matrix_transpose_naive<<<grid_size, block_size>>>(matrixT.d, matrix.d, size);

    gpuErrchk(cudaEventRecord(stop));
    gpuErrchk(cudaEventSynchronize(stop));
    gpuErrchk(cudaPeekAtLastError());

    float duration;
    gpuErrchk(cudaEventElapsedTime(&duration, start, stop));
    printf("Time: %f ms\n", duration);
  }

#elif OPTIMIZED
  printf("Optimized\n");
  
  // Warmup kernel
  matrix_transpose_optimized<<<grid_size, block_size>>>(matrixT.d, matrix.d, size);
  gpuErrchk(cudaPeekAtLastError());
  gpuErrchk(cudaDeviceSynchronize());

  for (int i = 0; i < LOOPS; i++)
  {
    gpuErrchk(cudaEventRecord(start));

    matrix_transpose_optimized<<<grid_size, block_size>>>(matrixT.d, matrix.d, size);

    gpuErrchk(cudaEventRecord(stop));
    gpuErrchk(cudaEventSynchronize(stop));
    gpuErrchk(cudaPeekAtLastError());

    float duration;
    gpuErrchk(cudaEventElapsedTime(&duration, start, stop));
    printf("Time: %f ms\n", duration);
  }

#endif

  gpuErrchk(cudaMemcpy(matrixT.h, matrixT.d, size * size * sizeof(matrix_type), cudaMemcpyDeviceToHost));

  // matrix_print(&matrix, size);
  // matrix_print(&matrixT, size);

  matrix_free(&matrix);
  matrix_free(&matrixT);

  gpuErrchk(cudaDeviceReset());

  return 0;
}
