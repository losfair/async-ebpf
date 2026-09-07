# Regenerates the Lean translation of the verified core and checks the proofs.
#
#   make setup-tools   clone and build Charon and Aeneas under tools/ (once)
#   make extract       ../src/verified/ -> AsyncEbpf/AsyncEbpfVerified.lean
#   make build         check every proof (default)
#
# The Aeneas commit is pinned in lakefile.toml; Charon is pinned by that commit's
# `charon-pin`. `setup-tools` reads both, so bumping the lakefile is the one
# edit needed to move to a newer toolchain.

TOOLS      := $(CURDIR)/tools
AENEAS_DIR ?= $(TOOLS)/aeneas
CHARON_DIR ?= $(TOOLS)/charon
AENEAS_REV := $(shell sed -n 's/^rev = "\(.*\)"/\1/p' lakefile.toml)

CHARON     ?= $(CHARON_DIR)/bin/charon
AENEAS     ?= $(AENEAS_DIR)/bin/aeneas
LAKE       ?= lake

KERNEL     := verified
LLBC       := $(KERNEL)/async_ebpf_verified.llbc
GENERATED  := AsyncEbpf/AsyncEbpfVerified.lean

.PHONY: build
build:
	$(LAKE) build

.PHONY: extract
extract: $(GENERATED)

# Charon compiles the crate with the nightly its own `rust-toolchain` names;
# `RUSTUP_TOOLCHAIN` carries that choice into a directory that has no such file.
$(LLBC): $(wildcard ../src/verified/*.rs) $(KERNEL)/Cargo.toml
	cd $(KERNEL) && RUSTUP_TOOLCHAIN=$$(sed -n 's/^channel = "\(.*\)"/\1/p' $(CHARON_DIR)/rust-toolchain) \
	  $(CHARON) cargo --preset=aeneas

$(GENERATED): $(LLBC)
	$(AENEAS) -backend lean -dest AsyncEbpf $(LLBC)

.PHONY: setup-tools
setup-tools:
	mkdir -p $(TOOLS)
	test -d $(AENEAS_DIR) || git clone https://github.com/AeneasVerif/aeneas $(AENEAS_DIR)
	cd $(AENEAS_DIR) && git fetch -q origin $(AENEAS_REV) && git checkout -q $(AENEAS_REV)
	test -d $(CHARON_DIR) || git clone https://github.com/AeneasVerif/charon $(CHARON_DIR)
	cd $(CHARON_DIR) && git fetch -q origin $$(tail -1 $(AENEAS_DIR)/charon-pin) && git checkout -q FETCH_HEAD
	cd $(CHARON_DIR)/charon && cargo build --release
	mkdir -p $(CHARON_DIR)/bin && cp -f $(CHARON_DIR)/charon/target/release/charon $(CHARON_DIR)/charon/target/release/charon-driver $(CHARON_DIR)/bin/
	cd $(CHARON_DIR) && $(MAKE) build-charon-ml
	ln -sfn $(CHARON_DIR) $(AENEAS_DIR)/charon
	cd $(AENEAS_DIR) && $(MAKE) build-bin-dir

.PHONY: clean
clean:
	rm -f $(LLBC)
	rm -rf .lake/build
