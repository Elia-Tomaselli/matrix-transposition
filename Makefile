CC = gcc
CFLAGS = -O3 -Wall -Wextra

SRCDIR = src
OBJDIR = obj
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c, $(OBJDIR)/%.o, $(SOURCES))

EXECUTABLE = out

# Change executable extension to .exe if OS is Windows
ifeq ($(OS), Windows_NT)
    EXECUTABLE := $(EXECUTABLE).exe
endif

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(CFLAGS) $< -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Ensure obj directory exists before compiling any source file
$(OBJECTS): | $(OBJDIR)

# Create obj directory
$(OBJDIR):
	@mkdir -p $(OBJDIR)

run: $(EXECUTABLE)
	@./${EXECUTABLE}

.PHONY: clean
clean:
	rm -rf $(OBJDIR) $(EXECUTABLE)