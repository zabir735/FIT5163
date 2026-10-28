#!/usr/bin/env bash
# macOS/Linux twin of run_all.bat; keep the two in step.
# Regenerates every test result, table and plot used in the report.
#
#   ./run_all.sh                full run: 100 timing runs per ring size (slow, over an hour)
#   ./run_all.sh quick          smoke run: a few minutes, checks every step works
#   ./run_all.sh seed 42        any mode with another seed (default 5163)
#
# Results go to eval/results (CSV and the attack tables as .txt) and eval/plots (PNG, CSV);
# quick mode writes to a quick/ subfolder of each instead.
set -euo pipefail
cd "$(dirname "$0")"

SEED=5163
MODE=full
while [ $# -gt 0 ]; do
    case "$1" in
        quick) MODE=quick; shift ;;
        seed) [ $# -ge 2 ] || { echo "Usage: ./run_all.sh [quick] [seed N]"; exit 2; }
              SEED="$2"; shift 2 ;;
        *) echo "Usage: ./run_all.sh [quick] [seed N]"; exit 2 ;;
    esac
done

export PYTHONUTF8=1    # tables print symbols such as the paper's ⊥
PY=python
[ -x .venv/bin/python ] && PY=.venv/bin/python
OUT=eval/results
PLOTS=eval/plots
if [ "$MODE" = quick ]; then
    OUT=eval/results/quick; PLOTS=eval/plots/quick
    RINGS="8 16"; TIME_REPS=2; SIZE_REPS=1; TRIALS=10; CHAIN_RINGS="8 16"
    PYTEST_ARGS="-q tests/test_skeleton.py tests/test_serialize.py tests/test_size_model.py"
else
    # Encoded sizes are fixed for a given shape, so a few size runs are enough.
    RINGS="128 256 512 1024"; TIME_REPS=100; SIZE_REPS=3; TRIALS=200; CHAIN_RINGS="8 16 32 64"
    PYTEST_ARGS="-q"
fi
mkdir -p "$OUT" "$PLOTS"
echo "Mode $MODE, seed $SEED, python $PY"

step() { echo; echo "==== $1"; }
attack() {
    local name="$1"; shift
    step "attack: $name"
    "$PY" -m "attacks.$name" --seed "$SEED" "$@" 2>&1 | tee "$OUT/$name.txt"
}

step tests
"$PY" -m pytest $PYTEST_ARGS

step "size model (paper Table 1, Figures 1 and 7)"
"$PY" -m eval.size_model --seed "$SEED" --output-dir "$PLOTS"

step "measured transaction and proof sizes"
rm -f "$OUT/bench_size_sigma_ring.csv"     # bench_size refuses to overwrite it
"$PY" -m eval.bench_size --seed "$SEED" --ring-sizes $RINGS --repetitions "$SIZE_REPS" \
    --output "$OUT/bench_size_sigma_ring.csv"

step "Spend/Verify timing"
"$PY" -m eval.bench_time --seed "$SEED" --ring-sizes $RINGS --repetitions "$TIME_REPS" \
    --quiet --output "$OUT/bench_time_sigma_ring.csv"

attack miner_privacy --trials "$TRIALS"
attack anonymity_reduction --trials "$TRIALS"
attack related_key_tag
attack q_bound_linkability
attack chain_scenario --trials "$TRIALS" --ring-sizes $CHAIN_RINGS

echo
echo "All steps finished. Results are in $OUT and $PLOTS."
