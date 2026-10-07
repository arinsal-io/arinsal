# Run the demo on Arinsal or on the reference erts.
#
#   make test            mix test on Arinsal
#   make test-erts       the same on erts (reference)
#   make compile         mix compile --force on Arinsal (Elixir compiler on our VM)
#   make run EXPR='...'  evaluate an expression in the project on Arinsal
#   make iex             interactive shell on Arinsal
#   make new             mix new + mix test of a fresh project on Arinsal
#   make compare         erts, Arinsal cold, and Arinsal warm (all suites)
#   make compare QUICK=1 shorter benchee times
#   make compare SUITE=maps
#   make compare BASELINE=bench/out/compare-YYYY-MM-DD-<sha>.md
#
# PROFILE=debug uses the debug build (faster to build, slower to run).
# compare always runs the release shim. QUICK=1, SUITE, and BASELINE select
# the run; the three runtimes are sequential.

ROOT    := $(abspath ../..)
PROFILE ?= release
CARGO_FLAGS := $(if $(filter release,$(PROFILE)),--release,)
ARINSAL := $(ROOT)/target/$(PROFILE)/arinsal
SHIM    := $(ROOT)/tmp/shim-$(PROFILE)
ON_ARINSAL := PATH="$(SHIM):$$PATH"
TIMEOUT ?= 600
# mix test/compile/run below use the selected runtime.
# compare compiles once on erts so every runtime loads the same beams.
MIX_ENV ?= dev
export MIX_ENV
SEED    ?=
MIX_TEST_ARGS := $(if $(SEED),--seed $(SEED),)
EXPR    ?= IO.inspect(ArinsalDemo.Pure.module_info(:exports) |> length)
QUICK   ?= 0
SUITE   ?= all
BASELINE ?=

ifeq ($(QUICK),1)
BENCH_QUICK_ENV := BENCH_QUICK=1
SUMMARY_QUICK := --quick
else
BENCH_QUICK_ENV :=
SUMMARY_QUICK :=
endif

ifneq ($(BASELINE),)
SUMMARY_BASELINE := --baseline $(BASELINE)
else
SUMMARY_BASELINE :=
endif

.PHONY: build shim deps test test-erts compile run iex new clean compare

build:
	cd $(ROOT) && cargo build $(CARGO_FLAGS) -p arinsal-cli

# `erl` on PATH resolves to Arinsal; elixir, mix and iex are the installed scripts.
shim: build
	mkdir -p $(SHIM)
	ln -sf $(ARINSAL) $(SHIM)/erl

# Dependencies are fetched once (Hex over HTTPS); compilation happens on Arinsal.
deps:
	mix deps.get

test: shim deps
	$(ON_ARINSAL) MIX_ENV=test timeout $(TIMEOUT) mix test $(MIX_TEST_ARGS)

test-erts: deps
	MIX_ENV=test mix test $(MIX_TEST_ARGS)

compile: shim deps
	$(ON_ARINSAL) timeout $(TIMEOUT) mix compile --force

run: shim deps
	$(ON_ARINSAL) timeout $(TIMEOUT) mix run -e '$(EXPR)'

iex: shim deps
	$(ON_ARINSAL) iex -S mix

dev: shim deps
	$(ON_ARINSAL) iex -S mix

dev_erts:
	iex -S mix		

new: shim
	rm -rf $(ROOT)/tmp/newproj
	cd $(ROOT)/tmp && $(ON_ARINSAL) timeout $(TIMEOUT) mix new newproj
	cd $(ROOT)/tmp/newproj && $(ON_ARINSAL) timeout $(TIMEOUT) mix test

clean:
	rm -rf _build $(SHIM) $(ROOT)/tmp/newproj

# Same MIX_ENV=bench beams for every runtime. Arinsal runs use the release shim
# and timeout; cold is warm-up 0, warm is the normal warm-up.
compare: shim deps
	if [ -n "$(BASELINE)" ] && [ ! -e "$(BASELINE)" ]; then echo "baseline not found: $(BASELINE)" >&2; exit 1; fi
	mkdir -p bench/out
	MIX_ENV=bench mix compile
	$(BENCH_QUICK_ENV) MIX_ENV=bench RUNTIME=erts BENCH_MODE=check_and_run SUITE=$(SUITE) mix run --no-compile --no-deps-check bench/run.exs
	$(ON_ARINSAL) $(BENCH_QUICK_ENV) MIX_ENV=bench RUNTIME=arinsal BENCH_MODE=check BENCH_EXPECT=bench/out/check-erts.txt SUITE=$(SUITE) timeout $(TIMEOUT) mix run --no-compile --no-deps-check bench/run.exs
	$(ON_ARINSAL) $(BENCH_QUICK_ENV) MIX_ENV=bench RUNTIME=arinsal_cold BENCH_MODE=run SUITE=$(SUITE) timeout $(TIMEOUT) mix run --no-compile --no-deps-check bench/run.exs
	$(ON_ARINSAL) $(BENCH_QUICK_ENV) MIX_ENV=bench RUNTIME=arinsal_warm BENCH_MODE=run SUITE=$(SUITE) timeout $(TIMEOUT) mix run --no-compile --no-deps-check bench/run.exs
	python3 bench/summary.py --suite $(SUITE) $(SUMMARY_QUICK) $(SUMMARY_BASELINE)
