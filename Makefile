SHELL := /bin/sh

CMAKE ?= cmake
BUILD_DIR ?= $(CURDIR)/build
BUILD_TYPE ?= Release
INSTALL_DIR ?= $(HOME)/.idapro/loaders
IDA_SDK_DIR ?=

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  LOADER_EXT := .dylib
else ifeq ($(UNAME_S),Linux)
  LOADER_EXT := .so
else
  $(error Unsupported host for this Makefile: $(UNAME_S))
endif

LOADER := $(BUILD_DIR)/bin/loaders/self_loader$(LOADER_EXT)
SDK_FLAG := $(if $(IDA_SDK_DIR),"-DIDA_SDK_DIR=$(IDA_SDK_DIR)",)

.PHONY: all build configure test install uninstall clean rebuild help

all: build

configure:
	$(CMAKE) -S "$(CURDIR)" -B "$(BUILD_DIR)" -G Ninja \
		-DCMAKE_BUILD_TYPE="$(BUILD_TYPE)" $(SDK_FLAG)

build: configure
	$(CMAKE) --build "$(BUILD_DIR)" --parallel

test: build
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure

install: build
	$(CMAKE) -E make_directory "$(INSTALL_DIR)"
	$(CMAKE) -E copy_if_different "$(LOADER)" "$(INSTALL_DIR)/"
	@printf 'Installed %s\n' "$(INSTALL_DIR)/$(notdir $(LOADER))"

uninstall:
	$(CMAKE) -E rm -f "$(INSTALL_DIR)/$(notdir $(LOADER))"

clean:
	$(CMAKE) -E remove_directory "$(BUILD_DIR)"

rebuild: clean build

help:
	@printf '%s\n' \
		'make build    - configure and build the loader and parser tests' \
		'make test     - build and run parser tests' \
		'make install  - install the loader to ~/.idapro/loaders/' \
		'make uninstall- remove the installed loader' \
		'make clean    - remove the build directory' \
		'make rebuild  - clean and rebuild' \
		'' \
		'Overrides: BUILD_DIR, BUILD_TYPE, INSTALL_DIR, IDA_SDK_DIR, CMAKE'
