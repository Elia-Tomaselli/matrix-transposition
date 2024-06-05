# Usage: "make" or "make all" to compile the source files and create the executable
#				 "make optimized" or "make naive" to compile the source files and create the executable with the optimized or naive version of the transpose kernel
#				 Additionally a different TILE_SIZE can be specified with "TILE_SIZE=<your_tile_size>" before the make command, the default TILE_SIZE is 32 
# 			 "make run <args>" to run the executable with arguments
#        "make clean" to remove object files and executable

.DEFAULT_GOAL := naive

CC = nvcc
CFLAGS = -O3

# NVIDIA A30
CFLAGS += --gpu-architecture=sm_80 -m64
# NVIDIA GeForce RTX 4060 Ti
# CFLAGS += --gpu-architecture=sm_89 -m64

SRCDIR = src
OBJDIR = obj
SOURCES := $(wildcard $(SRCDIR)/*.cu)
OBJECTS := $(patsubst $(SRCDIR)/%.cu,$(OBJDIR)/%.o,$(SOURCES))

TARGET = transpose.out

naive: CFLAGS += -DNAIVE
naive: $(TARGET)

optimized: CFLAGS += -DOPTIMIZED
optimized: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

# Ensure obj directory exists before compiling any source file
$(OBJECTS): | $(OBJDIR)
$(OBJECTS): $(OBJDIR)/%.o: $(SRCDIR)/%.cu
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.cu $(SRCDIR)/%.cuh # In case the source file has a corresponding header file and it changes, the object file will be recompiled
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.cu
	$(CC) $(CFLAGS) -c $< -o $@

# Clean up object files and executable
clean:
	rm -rf $(OBJDIR)
	rm -f $(TARGET)
