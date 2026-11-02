#!/usr/bin/env bash
# Run group tests, paper size models, and attack scenarios on macOS/Linux.
# Real sigma_ring benchmarks run only with --benchmarks.
set -euo pipefail
cd "$(dirname "$0")"

usage() {
    cat <<'EOF'
Usage: ./run_all.sh [--quick] [--seed N] [--benchmarks]

Default: run all tests, paper analytical size models, and attack scenarios.
--quick: run a small test selection and shorter attack scenarios.
--benchmarks: also measure real sigma_ring transaction sizes and Spend/Verify
              timings, then plot them. Full rings: 128, 256, 512, 1024;
              10 size and 100 timing repetitions per ring. Quick rings: 8, 16;
              10 size and 10 timing repetitions per ring.
Every run writes to new timestamped directories; existing data are retained.
The positional arguments quick and seed N are also accepted for compatibility.
EOF
}

seed=5163
benchmarks=0
quick=0
while (($#)); do
    case "$1" in
        --seed|seed)
            if (($# < 2)) || [[ ! "$2" =~ ^-?[0-9]+$ ]]; then
                echo "--seed requires an integer." >&2
                exit 2
            fi
            seed="$2"
            shift 2
            ;;
        --benchmarks)
            benchmarks=1
            shift
            ;;
        --quick|quick)
            quick=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done
export PYTHONUTF8=1
python_cmd=python
if [[ -x .venv/bin/python ]]; then
    python_cmd=.venv/bin/python
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
result_dir="eval/results/run_${run_id}"
plot_root="eval/plots/run_${run_id}"
model_dir="$plot_root/paper_models"
attack_dir="$result_dir/attacks"
if [[ -e "$result_dir" || -e "$plot_root" ]]; then
    echo "A run output path already exists; choose a new run." >&2
    exit 2
fi
mkdir -p "$attack_dir"

step() {
    echo
    echo "==== $1"
}

attack() {
    local name="$1"
    shift
    step "attack: $name"
    "$python_cmd" -m "attacks.$name" --seed "$seed" "$@" 2>&1 | tee "$attack_dir/$name.txt"
}

echo "Seed: $seed; Python: $python_cmd"
step tests
if ((quick)); then
    "$python_cmd" -m pytest -q tests/test_skeleton.py tests/test_serialize.py tests/test_size_model.py
else
    "$python_cmd" -m pytest
fi

step "paper analytical size models"
"$python_cmd" -m eval.size_model --seed "$seed" --output-dir "$model_dir"

if ((quick)); then
    attack miner_privacy --trials 10 --ring-sizes 8 16
    attack anonymity_reduction --trials 10 --ring-sizes 8 16
    attack related_key_tag --trials 10
    attack q_bound_linkability --trials 10
    attack chain_scenario --trials 10 --ring-sizes 8 16
    attack multi_self_transfer --trials 10 --ring-sizes 8 16
else
    for name in miner_privacy anonymity_reduction related_key_tag q_bound_linkability chain_scenario multi_self_transfer; do
        attack "$name"
    done
fi

if ((benchmarks)); then
    ring_sizes=(128 256 512 1024)
    time_repetitions=100
    if ((quick)); then
        ring_sizes=(8 16)
        time_repetitions=10
    fi
    plot_dir="$plot_root/benchmarks"
    size_csv="$result_dir/bench_size_sigma_ring.csv"
    time_csv="$result_dir/bench_time_sigma_ring.csv"
    step "measured transaction and proof sizes"
    "$python_cmd" -m eval.bench_size --seed "$seed" --ring-sizes "${ring_sizes[@]}" \
        --repetitions 10 --output "$size_csv"
    step "Spend/Verify timing"
    "$python_cmd" -m eval.bench_time --seed "$seed" --ring-sizes "${ring_sizes[@]}" \
        --repetitions "$time_repetitions" --output "$time_csv"
    step "benchmark plots"
    "$python_cmd" -m eval.plot_results --input "$time_csv" --size-input "$size_csv" \
        --output-dir "$plot_dir"
    if ((quick == 0)); then
        step "comparison with the paper"
        "$python_cmd" -m eval.compare --time "$time_csv" --size "$size_csv" \
            --model "$model_dir/figure7_paper_size_model.csv" \
            --results-dir "$result_dir" --plots-dir "$plot_root/paper_comparison"
    fi
fi

echo
echo "All steps finished. Results: $result_dir and $plot_root."
