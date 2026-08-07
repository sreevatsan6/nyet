# ============================================================================
# Compiler
# ============================================================================

CC := gcc

SRCDIR := src

# ============================================================================
# Compiler Flags
# ============================================================================

COMMON_CFLAGS := \
	-pipe \
	-Wall \
	-Wextra \
	-Wpedantic \
	-Wstrict-prototypes \
	-Wmissing-prototypes

RELEASE_CFLAGS := \
	-O2 \
	-DNDEBUG

DEBUG_CFLAGS := \
	-O0 \
	-g3 \
	-fanalyzer \
	-fstack-protector-strong \
	-Wformat=2 \
	-Wnull-dereference \
	-Wshadow \
	-Wcast-align \
	-Wcast-qual \
	-Wwrite-strings

LDLIBS := \
	-lws2_32 \
	-liphlpapi \
	-lwinhttp \
	-lkernel32

# Default to a background Windows application.
# The debug target overrides this to produce a console application.
SUBSYSTEM := -Wl,--subsystem,windows

# ============================================================================
# Target
# ============================================================================

TARGET := nyet.exe

SOURCES := \
	$(SRCDIR)/nyet.c \
	$(SRCDIR)/radix_tree.c \
	$(SRCDIR)/dns_cache.c \
	$(SRCDIR)/answer_cache.c

# ============================================================================
# Default Release Build
# ============================================================================

all: CFLAGS := $(COMMON_CFLAGS) $(RELEASE_CFLAGS)
all: $(TARGET)
	@echo [+] Built $(TARGET)

$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $^ -o $@ $(SUBSYSTEM) $(LDLIBS)

# ============================================================================
# Debug Build
# ============================================================================

debug: CFLAGS := $(COMMON_CFLAGS) $(DEBUG_CFLAGS)
debug: SUBSYSTEM :=
debug: clean $(TARGET)
	@echo [+] Built debug $(TARGET)

# ============================================================================
# Named Target
# ============================================================================

nyet: all

# ============================================================================
# Clean
# ============================================================================

clean:
	$(RM) $(TARGET)

.PHONY: all debug nyet clean
