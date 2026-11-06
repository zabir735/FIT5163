"""Run the group wrapper with a fake Python executable; never run app modules."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "run_all.sh"


def find_bash() -> str | None:
    """A bash that understands this machine's paths, or None.

    On Windows, plain "bash" usually resolves to the WSL launcher
    (System32 or WindowsApps). WSL bash reads C:\\Users\\... as a POSIX path,
    strips the backslashes and fails with exit 127, so use Git Bash instead.
    """
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")
    candidates = [Path(git).resolve().parents[1] / "bin" / "bash.exe"] if git else []
    candidates.append(Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
                      / "Git" / "bin" / "bash.exe")
    found = shutil.which("bash")
    if found and not any(part in found.lower() for part in ("system32", "windowsapps")):
        candidates.insert(0, Path(found))
    return next((str(c) for c in candidates if c.is_file()), None)


BASH = find_bash()
needs_bash = pytest.mark.skipif(
    BASH is None, reason="needs bash (Git Bash on Windows; WSL bash can't read Windows paths)")


def run_with_fake_python(tmp_path: Path, *arguments: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
    """Capture selected commands while preventing every Python module from starting."""
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    script = repo / "run_all.sh"
    shutil.copy2(SCRIPT, script)
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir(exist_ok=True)
    fake_python = fake_bin / "python"
    fake_python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$RUN_ALL_TEST_LOG"\n',
        encoding="utf-8",
    )
    fake_python.chmod(0o755)
    log = tmp_path / "commands.log"
    log.write_text("", encoding="utf-8")
    environment = os.environ.copy()
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment.get('PATH', '')}"
    environment["RUN_ALL_TEST_LOG"] = str(log)
    result = subprocess.run(
        [BASH, str(script), *arguments], capture_output=True, text=True,
        env=environment, check=False,
    )
    commands = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
    return result, commands


@needs_bash
def test_default_run_avoids_real_benchmarks_and_includes_all_attack_scenarios(
    tmp_path: Path,
) -> None:
    result, commands = run_with_fake_python(tmp_path, "--seed", "7")

    assert result.returncode == 0
    assert "-m pytest" in commands
    assert any(command.startswith("-m eval.size_model --seed 7 --output-dir ")
               for command in commands)
    assert not any("-m eval.bench_size" in command or "-m eval.bench_time" in command
                   for command in commands)
    assert not any("-m eval.plot_results" in command or "-m eval.compare" in command
                   for command in commands)
    for scenario in ("miner_privacy", "anonymity_reduction", "related_key_tag",
                     "q_bound_linkability", "chain_scenario", "multi_self_transfer"):
        assert f"-m attacks.{scenario} --seed 7" in commands
        assert list((tmp_path / "repo" / "eval" / "results").glob(
            f"run_*/attacks/{scenario}.txt"
        ))


@needs_bash
def test_formal_benchmarks_use_100_timing_and_10_size_repetitions(
    tmp_path: Path,
) -> None:
    result, commands = run_with_fake_python(tmp_path, "--benchmarks", "--seed", "9")

    assert result.returncode == 0
    size = next(command for command in commands if command.startswith("-m eval.bench_size "))
    timing = next(command for command in commands if command.startswith("-m eval.bench_time "))
    plots = next(command for command in commands if command.startswith("-m eval.plot_results "))
    for command, repetitions in ((size, 10), (timing, 100)):
        assert "--seed 9" in command
        assert "--ring-sizes 128 256 512 1024" in command
        assert f"--repetitions {repetitions}" in command
        assert "--output eval/results/run_" in command
    assert "--size-input eval/results/run_" in plots
    assert "/bench_size_sigma_ring.csv" in plots
    assert "--input eval/results/run_" in plots
    assert "/bench_time_sigma_ring.csv" in plots
    assert "--output-dir eval/plots/run_" in plots
    comparison = next(command for command in commands
                      if command.startswith("-m eval.compare "))
    assert "--time eval/results/run_" in comparison
    assert "/bench_time_sigma_ring.csv --size eval/results/run_" in comparison
    assert "/bench_size_sigma_ring.csv --model eval/plots/run_" in comparison
    assert "/paper_models/figure7_paper_size_model.csv" in comparison
    assert "--baseline-time" not in comparison


@needs_bash
def test_quick_mode_limits_tests_and_attacks_without_running_benchmarks(
    tmp_path: Path,
) -> None:
    result, commands = run_with_fake_python(tmp_path, "--quick", "--seed", "5")

    assert result.returncode == 0
    assert "-m pytest -q tests/test_skeleton.py tests/test_serialize.py tests/test_size_model.py" in commands
    assert "-m attacks.miner_privacy --seed 5 --trials 10 --ring-sizes 8 16" in commands
    assert "-m attacks.chain_scenario --seed 5 --trials 10 --ring-sizes 8 16" in commands
    assert "-m attacks.multi_self_transfer --seed 5 --trials 10 --ring-sizes 8 16" in commands
    assert not any("-m eval.bench_" in command for command in commands)


@needs_bash
def test_quick_benchmarks_keep_ten_repetitions_on_small_rings(tmp_path: Path) -> None:
    result, commands = run_with_fake_python(tmp_path, "quick", "seed", "6", "--benchmarks")

    assert result.returncode == 0
    for module in ("eval.bench_size", "eval.bench_time"):
        command = next(item for item in commands if item.startswith(f"-m {module} "))
        assert "--seed 6 --ring-sizes 8 16 --repetitions 10" in command
    assert any(command.startswith("-m eval.plot_results ") for command in commands)
    assert not any(command.startswith("-m eval.compare ") for command in commands)


@needs_bash
def test_repeated_runs_keep_distinct_timestamped_outputs(tmp_path: Path) -> None:
    first, first_commands = run_with_fake_python(tmp_path, "--quick")
    first_model = next(command for command in first_commands
                       if command.startswith("-m eval.size_model "))
    first_dir = first_model.split("--output-dir ", 1)[1]
    second, second_commands = run_with_fake_python(tmp_path, "--quick")
    second_model = next(command for command in second_commands
                        if command.startswith("-m eval.size_model "))
    second_dir = second_model.split("--output-dir ", 1)[1]

    assert first.returncode == second.returncode == 0
    assert first_dir != second_dir
    assert first_dir.startswith("eval/plots/run_")
    assert second_dir.startswith("eval/plots/run_")
    assert len(list((tmp_path / "repo" / "eval" / "results").glob("run_*/attacks"))) == 2


@needs_bash
def test_local_venv_python_is_selected_when_present(tmp_path: Path) -> None:
    """The fake local interpreter records calls without starting Python modules."""
    repo = tmp_path / "repo"
    repo.mkdir()
    script = repo / "run_all.sh"
    shutil.copy2(SCRIPT, script)
    local_python = repo / ".venv" / "bin" / "python"
    local_python.parent.mkdir(parents=True)
    local_python.write_text(
        '#!/bin/sh\nprintf "%s\\n" "$*" >> "$RUN_ALL_TEST_LOG"\n',
        encoding="utf-8",
    )
    local_python.chmod(0o755)
    log = tmp_path / "commands.log"
    environment = os.environ.copy()
    environment["RUN_ALL_TEST_LOG"] = str(log)

    result = subprocess.run(
        [BASH, str(script), "--quick"], capture_output=True, text=True,
        env=environment, check=False,
    )

    assert result.returncode == 0
    assert "Python: .venv/bin/python" in result.stdout
    assert "-m pytest -q tests/test_skeleton.py tests/test_serialize.py tests/test_size_model.py" in log.read_text(
        encoding="utf-8"
    ).splitlines()


@needs_bash
@pytest.mark.parametrize("arguments", [
    ("--seed",), ("--seed", "abc"), ("--unknown",),
    ("--benchmark-repetitions", "100"),
])
def test_invalid_options_stop_before_any_application_command(
    tmp_path: Path, arguments: tuple[str, ...],
) -> None:
    result, commands = run_with_fake_python(tmp_path, *arguments)

    assert result.returncode == 2
    assert commands == []
