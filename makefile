# Makefile for the High-Performance C++ Pcap Parser

# Compiler and Flags
CXX = g++

# --- Optimization Level ---
# Set the default optimization level.
# -O3 for max speed (production)
# -Og for optimized debugging
# -O2 is a standard balance
OPT_LEVEL ?= -Og

# To build for debugging, run:
#   make clean && make OPT_LEVEL=-Og
#
# To build with O2, run:
#   make clean && make OPT_LEVEL=-O2
# ---

# Use -std=c++17 or later.
# -g for debug symbols (for gdb)
# -Wall to show all warnings. -pthread is required for std::thread.
CXXFLAGS = -std=c++17 $(OPT_LEVEL) -g -Wall -pthread

# Add -DBENCHMARK_THREAD to CXXFLAGS to enable benchmarking
# CXXFLAGS += -DBENCHMARK_THREAD

# Linker Flags
# -lpcap is required for the pcap library
# -pthread is required for std::thread
LDFLAGS = -lpcap -pthread

# Executable name
TARGET = streamsift

# Source files (.cpp)
SRCS = \
    Logger.cpp \
    Benchmark.cpp \
    ConfigParser.cpp \
    consumer.cpp \
    PacketStreamEval.cpp \
    pcap_abbv_cli_parser.cpp \
    pcapparser.cpp \
    ProtoTrigger.cpp \
    pcapkey.cpp \
    main.cpp

# Object files (.o) - generated automatically from SRCS
OBJS = $(SRCS:.cpp=.o)

# Default target: Build the executable
all: $(TARGET)

# Rule to link the executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)

# Pattern rule to compile .cpp to .o
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c -o $@ $<

# Clean up build files
clean:
	rm -f $(TARGET) $(OBJS)

# Phony targets
.PHONY: all clean
