# Usage: "make" or "make all" to compile the source files and create the executable
#        "make debug" to compile the source files with debug flags
# 			 "make run <args>" to run the executable with arguments
#        "make clean" to remove object files and executable

CC = gcc
CFLAGS = -O3 -Wall -Wextra
DEBUG_CFLAGS = -g

SRCDIR = src
OBJDIR = obj
SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

TARGET = transpose

# Update the target extension based on the OS
ifeq ($(OS),Windows_NT)
	TARGET := $(TARGET).exe
else
	UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Linux)
		TARGET := $(TARGET).out
	endif
	ifeq ($(UNAME_S),Darwin)
		TARGET := $(TARGET).app
	endif
endif

all: $(TARGET)

debug: CFLAGS += $(DEBUG_CFLAGS)
debug: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Ensure obj directory exists before compiling any source file
$(OBJECTS): | $(OBJDIR)
$(OBJDIR):
	mkdir -p $(OBJDIR)

# If the first argument is "run"...
ifeq (run,$(firstword $(MAKECMDGOALS)))
  # Use the rest as arguments for "run"
  ARGS := $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
  # ...and turn them into do-nothing targets
  $(eval $(ARGS):;@:)
endif

# Run the executable
run: $(TARGET)
	./$(TARGET) $(ARGS)

# Clean up object files and executable
clean:
	rm -rf $(OBJDIR)
	rm -f $(TARGET)

.PHONY: all debug run clean