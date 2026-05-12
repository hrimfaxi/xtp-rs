.PHONY: all build release clean install test run fmt clippy check

all: build

build:
	cargo build

release:
	cargo build --release

clean:
	cargo clean

run:
	cargo run

run-with:
	cargo run -- $(ARGS)
