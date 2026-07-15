.PHONY: help setup tools fmt fmt-check check clippy test coverage test-ci build release run clean upgrade audit

help:
	@echo "Goals:"
	@echo "  make setup       Install required tools (cargo-nextest, cargo-llvm-cov, cargo-audit)"
	@echo "  make tools       Show installed tool versions"
	@echo "  make fmt         Format all Rust code"
	@echo "  make fmt-check   Check formatting (CI)"
	@echo "  make check       cargo check"
	@echo "  make clippy      Run clippy with -D warnings"
	@echo "  make test        Run tests with cargo-nextest"
	@echo "  make coverage    Run tests with LLVM coverage (html + lcov)"
	@echo "  make test-ci     Format + clippy + tests + coverage (CI)"
	@echo "                 Optional: COVERAGE_FAIL=1 COVERAGE_MIN=80"
	@echo "  make build       Debug build"
	@echo "  make release     Release build"
	@echo "  make run         Run guajara"
	@echo "  make upgrade     Update dependencies (cargo upgrade)"
	@echo "  make audit       Run cargo audit"
	@echo "  make clean       Remove build artifacts"

setup:
	@echo "==> Checking Rust toolchain…"
	rustc --version && cargo --version
	@echo "==> Ensuring rustfmt and clippy…"
	rustup component add rustfmt clippy 2>/dev/null || true
	@echo "==> Installing cargo-nextest…"
	cargo install cargo-nextest --locked 2>/dev/null || true
	@echo "==> Installing cargo-llvm-cov…"
	cargo install cargo-llvm-cov --locked 2>/dev/null || true
	@echo "==> Installing cargo-audit…"
	cargo install cargo-audit --locked 2>/dev/null || true
	@echo "==> Installing cargo-edit (cargo upgrade)…"
	cargo install cargo-edit --locked 2>/dev/null || true
	@echo "Done. Run 'make tools' to verify."

tools:
	@echo "Rust:    $$(rustc --version)"
	@echo "Cargo:   $$(cargo --version)"
	@echo "nextest: $$(cargo nextest --version 2>/dev/null || echo 'not installed')"
	@echo "llvm-cov: $$(cargo llvm-cov --version 2>/dev/null || echo 'not installed')"
	@echo "audit:   $$(cargo audit --version 2>/dev/null || echo 'not installed')"

fmt:
	cargo fmt

fmt-check:
	cargo fmt --check

check:
	cargo check

clippy:
	cargo clippy -- -D warnings

test:
	cargo nextest run

coverage:
	cargo llvm-cov nextest --workspace --all-features
	mkdir -p target/coverage/html
	cargo llvm-cov report --html --output-dir target/coverage/html
	cargo llvm-cov report --lcov --output-path target/coverage/lcov.info
	@echo ""
	@echo "Coverage reports:"
	@echo "  HTML:  target/coverage/html/index.html"
	@echo "  LCOV:  target/coverage/lcov.info"
	@echo ""
	@cargo llvm-cov report --summary-only 2>/dev/null || true

test-ci: fmt-check clippy test coverage
	@echo ""
	@echo "=== Coverage Summary ==="
	@cargo llvm-cov report --summary-only 2>/dev/null || echo "(summary unavailable)"
ifdef COVERAGE_FAIL
	@echo "==> Enforcing minimum coverage: $(COVERAGE_MIN)%"
	cargo llvm-cov report --fail-under-lines $(COVERAGE_MIN) --fail-under-functions $(COVERAGE_MIN) --fail-under-regions $(COVERAGE_MIN) 2>/dev/null || exit 1
endif

build:
	cargo build

release:
	cargo build --release

run:
	cargo run

upgrade:
	cargo upgrade

audit:
	cargo audit

clean:
	cargo clean
	rm -rf target/coverage
