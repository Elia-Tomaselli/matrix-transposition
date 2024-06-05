#include "cache_line_size.h"

size_t get_cache_line_size() {
  FILE* fp = NULL;

  fp = fopen("/sys/devices/system/cpu/cpu0/cache/index0/coherency_line_size", "r");

  if (fp == NULL)
    return 0;

  size_t cache_line_size = 0;
  uint8_t ret = fscanf(fp, "%lu", &cache_line_size);
  fclose(fp);

  if (ret == 0)
    return 0;

  return cache_line_size;
}