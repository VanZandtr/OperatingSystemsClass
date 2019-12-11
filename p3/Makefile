# Files for building the server: {files in server/, files in common/, file
# in server/ with main()}
SERVER_CXX = server server_storage
SERVER_COMMON = 
SERVER_PROVIDED = crypto err file net vec server_args server_commands server_parsing pool
SERVER_MAIN   = server

CLIENT_MAIN = client

# Files for building the scalability benchmark: {files in bench/, files in
# common/, file in bench/ with main()}
BENCH_CXX    = bench
BENCH_COMMON =
BENCH_MAIN   = bench

# Files for building the shared objects: {files in so/, files in common/}.
# We assume that map() and reduce() are provided in each SO_CXX file
SO_CXX    = 
SO_COMMON = 

# Default to 64 bits, but allow overriding on command line
BITS ?= 64

# Give name to output folder, and ensure it is created before any compilation
ODIR          := ./obj$(BITS)
output_folder := $(shell mkdir -p $(ODIR))

# Names of all .o files
SERVER_O = $(patsubst %, $(ODIR)/%.o, $(SERVER_CXX) $(SERVER_COMMON)) \
           $(patsubst %, ofiles/%.o, $(SERVER_PROVIDED))
BENCH_O  = $(patsubst %, $(ODIR)/%.o, $(BENCH_CXX) $(BENCH_COMMON))
SO_O     = $(patsubst %, $(ODIR)/%.o, $(SO_CXX) $(SO_COMMON))
ALL_O    = $(SERVER_O) $(BENCH_O) $(SO_O)

# .so builds require special management of SO_COMMON <=> .o mappings
SO_COMMON_O = $(patsubst %, $(ODIR)/%.o, $(SO_COMMON))

# Names of all .exe files
EXEFILES = $(patsubst %, $(ODIR)/%.exe, $(CLIENT_MAIN) $(SERVER_MAIN) $(BENCH_MAIN))

# Names of all .so files
SOFILES = $(patsubst %, $(ODIR)/%.so, $(SO_CXX))

# Names of all .d files
DFILES     = $(patsubst %.o, %.d, $(ALL_O))

# Basic tool configuration for gcc/g++
CXX      = g++
LD       = g++
CXXFLAGS = -MMD -O3 -m$(BITS) -ggdb -std=c++17 -Wall -Werror -fPIC
LDFLAGS  = -m$(BITS) -lpthread -lcrypto -ldl 
SOFLAGS  = -fPIC -shared

# Build 'all' by default, and don't clobber .o files after each build
.DEFAULT_GOAL = all
.PRECIOUS: $(ALL_O)
.PHONY: all clean

# Goal is to build all executables
all: $(EXEFILES) $(SOFILES)

# Rules for building object files
$(ODIR)/%.o: server/%.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)
$(ODIR)/%.o: common/%.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)
$(ODIR)/%.o: bench/%.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)
$(ODIR)/%.o: so/%.cc
	@echo "[CXX] $< --> $@"
	@$(CXX) $< -o $@ -c $(CXXFLAGS)

# Rules for building executables
$(ODIR)/client.exe: solutions/client.exe
	@echo "[CP] $^ --> $@"
	@cp $< $@
$(ODIR)/server.exe: $(SERVER_O)
	@echo "[LD] $^ --> $@"
	@$(CXX) $^ -o $@ $(LDFLAGS)
$(ODIR)/bench.exe: $(BENCH_O)
	@echo "[LD] $^ --> $@"
	@$(CXX) $^ -o $@ $(LDFLAGS)

# Rules for building .so files
$(ODIR)/%.so: $(ODIR)/%.o $(SO_COMMON_O)
	@echo "[LD] $^ --> $@"
	@$(CXX) $^ -o $@ $(CXXFLAGS) $(SOFLAGS)

# clean by clobbering the build folder
clean:
	@echo Cleaning up...
	@rm -rf $(ODIR)

# Include any dependencies we generated previously
-include $(DFILES)
