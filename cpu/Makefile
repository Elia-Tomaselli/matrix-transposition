# Usage: "make" or "make all" to compile the source files and create the executable
# 			 "make run <args>" to run the executable with arguments
#        "make clean" to remove object files and executable

CC = gcc
CFLAGS = -O0 -Wall -Wextra
SRCDIR = src
OBJDIR = obj
SOURCES := $(wildcard $(SRCDIR)/*.c)
OBJECTS := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

TARGET = transpose.out

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@

# Ensure obj directory exists before compiling any source file
$(OBJECTS): | $(OBJDIR)
$(OBJECTS): $(OBJDIR)/%.o: $(SRCDIR)/%.c
$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/%.h # In case the source file has a corresponding header file and it changes, the object file will be recompiled
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

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

.PHONY: all run clean