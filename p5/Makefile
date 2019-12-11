# Files for building the server: {files in server/, files in common/, file
# in server/ with main()}
SERVER_CXX = server server_storage_ex
SERVER_COMMON = func_table
SERVER_PROVIDED = crypto err file mru net pool quota_tracker vec server_args \
                  server_commands server_parsing server_storage
SERVER_MAIN   = server

CLIENT_MAIN = client
BENCH_MAIN = bench

# Files for building the shared objects: {files in so/, files in common/}.
# We assume that map() and reduce() are provided in each SO_CXX file
SO_CXX    = all_keys odd_key_vals
SO_PROVIDED = vec

# Default to 64 bits, but allow overriding on command line
BITS ?= 64

# Give name to output folder, and ensure it is created before any compilation
ODIR          := ./obj$(BITS)
output_folder := $(shell mkdir -p $(ODIR))

# Names of all .o files
SERVER_O = $(patsubst %, $(ODIR)/%.o, $(SERVER_CXX) $(SERVER_COMMON)) \
           $(patsubst %, ofiles/%.o, $(SERVER_PROVIDED))
SO_O     = $(patsubst %, $(ODIR)/%.o, $(SO_CXX)) \
           $(patsubst %, ofiles/%.o, $(SO_PROVIDED))
ALL_O    = $(SERVER_O) $(SO_O)

# .so files need extra linking:
SO_PROVIDED_O = $(patsubst %, ofiles/%.o, $(SO_PROVIDED))

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
$(ODIR)/bench.exe: solutions/bench.exe
	@echo "[CP] $^ --> $@"
	@cp $< $@

# Rules for building .so files
$(ODIR)/%.so: $(ODIR)/%.o $(SO_PROVIDED_O)
	@echo "[LD] $^ --> $@"
	@$(CXX) $^ -o $@ $(CXXFLAGS) $(SOFLAGS)

# clean by clobbering the build folder
clean:
	@echo Cleaning up...
	@rm -rf $(ODIR)

# Include any dependencies we generated previously
-include $(DFILES)
