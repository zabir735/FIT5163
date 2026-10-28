@echo off
rem Regenerates every test result, table and plot used in the report.
rem
rem   run_all.bat                 full run: 100 timing runs per ring size (slow, over an hour)
rem   run_all.bat quick           smoke run: a few minutes, checks every step works
rem   run_all.bat seed 42         any mode with another seed (default 5163)
rem
rem Results go to eval\results (CSV and the attack tables as .txt) and eval\plots (PNG, CSV);
rem quick mode writes to a quick\ subfolder of each instead.
rem Uses .venv\Scripts\python.exe when it exists, otherwise python on PATH.
setlocal enableextensions
cd /d "%~dp0"

set "SEED=5163"
set "MODE=full"
:args
if "%~1"=="" goto :start
if /i "%~1"=="quick" (set "MODE=quick" & shift & goto :args)
if /i "%~1"=="seed" (
    if "%~2"=="" goto :usage
    set "SEED=%~2"
    shift & shift & goto :args
)
goto :usage

:start
rem The attack tables print non-ASCII symbols. Without UTF-8 mode Python falls back to
rem cp1252 when output is redirected and crashes; chcp makes the console show them.
set "PYTHONUTF8=1"
chcp 65001 >nul
set "PY=python"
if exist ".venv\Scripts\python.exe" set "PY=.venv\Scripts\python.exe"
set "OUT=eval\results"
set "PLOTS=eval\plots"
rem Quick runs get their own folders so they never overwrite real results.
if "%MODE%"=="quick" (set "OUT=eval\results\quick" & set "PLOTS=eval\plots\quick")
if not exist "%OUT%" mkdir "%OUT%"
if not exist "%PLOTS%" mkdir "%PLOTS%"

if "%MODE%"=="quick" (
    set "RINGS=8 16"
    set "TIME_REPS=2"
    set "SIZE_REPS=1"
    set "TRIALS=10"
    set "CHAIN_RINGS=8 16"
    set "PYTEST_ARGS=-q tests/test_skeleton.py tests/test_serialize.py tests/test_size_model.py"
) else (
    set "RINGS=128 256 512 1024"
    set "TIME_REPS=100"
    rem Encoded sizes are fixed for a given shape, so a few runs are enough.
    set "SIZE_REPS=3"
    set "TRIALS=200"
    set "CHAIN_RINGS=8 16 32 64"
    set "PYTEST_ARGS=-q"
)
echo Mode %MODE%, seed %SEED%, python %PY%

call :run "tests" %PY% -m pytest %PYTEST_ARGS% || goto :fail

call :run "size model (paper Table 1, Figures 1 and 7)" ^
    %PY% -m eval.size_model --seed %SEED% --output-dir %PLOTS% || goto :fail

rem bench_size refuses to overwrite its CSV, so clear the previous run first.
if exist "%OUT%\bench_size_sigma_ring.csv" del "%OUT%\bench_size_sigma_ring.csv"
call :run "measured transaction and proof sizes" ^
    %PY% -m eval.bench_size --seed %SEED% --ring-sizes %RINGS% --repetitions %SIZE_REPS% ^
    --output %OUT%\bench_size_sigma_ring.csv || goto :fail

call :run "Spend/Verify timing" ^
    %PY% -m eval.bench_time --seed %SEED% --ring-sizes %RINGS% --repetitions %TIME_REPS% ^
    --quiet --output %OUT%\bench_time_sigma_ring.csv || goto :fail

call :attack miner_privacy --trials %TRIALS% || goto :fail
call :attack anonymity_reduction --trials %TRIALS% || goto :fail
call :attack related_key_tag || goto :fail
call :attack q_bound_linkability || goto :fail
call :attack chain_scenario --trials %TRIALS% --ring-sizes %CHAIN_RINGS% || goto :fail

echo.
echo All steps finished. Results are in %OUT% and %PLOTS%.
exit /b 0

rem --- helpers ---------------------------------------------------------------

:run
echo.
echo ==== %~1
shift
set "CMD="
:collect
if "%~1"=="" goto :exec
set "CMD=%CMD% %1"
shift
goto :collect
:exec
%CMD%
exit /b %errorlevel%

:attack
rem Prints the table and also saves it to eval\results\<attack>.txt.
set "NAME=%~1"
shift
set "ARGS="
:attack_args
if "%~1"=="" goto :attack_exec
set "ARGS=%ARGS% %1"
shift
goto :attack_args
:attack_exec
echo.
echo ==== attack: %NAME%
%PY% -m attacks.%NAME% --seed %SEED% %ARGS% > "%OUT%\%NAME%.txt" 2>&1
set "RC=%errorlevel%"
type "%OUT%\%NAME%.txt"
exit /b %RC%

:usage
echo Usage: run_all.bat [quick] [seed N]
exit /b 2

:fail
echo.
echo FAILED at the step above. Later steps did not run.
exit /b 1
