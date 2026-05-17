#!/usr/bin/env python3
"""
B-5-2 experiment automation with repeated runs and averaging.

Fixed workload:
  ProfileTotal = 20000
  Sigma = 0.49
  DATA_SIZE_MB = 10
  satellite bandwidth = 100 Mbps

For each run, the satellite executes UPDATE_DELTAS = 0.01,0.10,0.30,0.50,0.70,1.00.
The script repeats the whole Docker experiment N_RUNS times and averages, per delta:
  total, recompile, reencaps, publication.

Usage:
  cd poly-lock-docker
  python3 run_b5_2_update_delta_avg.py

Outputs:
  results_b5_2_update_delta_raw.csv
  results_b5_2_update_delta_avg.csv
"""

import csv
import math
import re
import shutil
import subprocess
import time
from pathlib import Path

PROFILE_TOTAL = 20000
SIGMA = 0.49
DATA_SIZE_MB = 10
BANDWIDTH = 100
DELTAS = [0.01, 0.10, 0.30, 0.50, 0.70, 1.00]
N_RUNS = 10
RAW_CSV = "results_b5_2_update_delta_raw.csv"
AVG_CSV = "results_b5_2_update_delta_avg.csv"
TIMEOUT_SEC = 1800

ROOT = Path(__file__).resolve().parent
PRECOMP_MAIN = ROOT / "precompute" / "main.go"
COMPOSE = ROOT / "docker-compose.yml"
SHARED = ROOT / "shared-data"
IPFS_DATA = ROOT / "ipfs-data"


def run(cmd, cwd=ROOT, check=True, capture=True):
    print(f"$ {' '.join(map(str, cmd))}")
    return subprocess.run(list(map(str, cmd)), cwd=str(cwd), check=check, text=True,
                          stdout=subprocess.PIPE if capture else None,
                          stderr=subprocess.STDOUT if capture else None)


def docker_compose_cmd():
    try:
        subprocess.run(["docker", "compose", "version"], cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]
DC = docker_compose_cmd()


def clean_all():
    run(DC + ["down", "-v", "--remove-orphans"], check=False)
    SHARED.mkdir(exist_ok=True); IPFS_DATA.mkdir(exist_ok=True)
    for folder in [SHARED, IPFS_DATA]:
        for p in list(folder.iterdir()):
            try:
                if p.is_dir(): shutil.rmtree(p)
                else: p.unlink()
            except Exception as e:
                print(f"[WARN] Failed to remove {p}: {e}")


def clean_runtime_keep_roots():
    run(DC + ["down", "-v", "--remove-orphans"], check=False)
    SHARED.mkdir(exist_ok=True); IPFS_DATA.mkdir(exist_ok=True)
    for p in list(SHARED.iterdir()):
        if p.name in {"validRoots.json", "auth_user.json"}:
            continue
        try:
            if p.is_dir(): shutil.rmtree(p)
            else: p.unlink()
        except Exception as e:
            print(f"[WARN] Failed to remove {p}: {e}")
    for p in list(IPFS_DATA.iterdir()):
        try:
            if p.is_dir(): shutil.rmtree(p)
            else: p.unlink()
        except Exception as e:
            print(f"[WARN] Failed to remove {p}: {e}")


def set_precompute_params(profile_total, sigma):
    text = PRECOMP_MAIN.read_text()
    text = re.sub(r"ProfileTotal\s*:=\s*\d+(\s*//[^\n]*)?", f"ProfileTotal := {profile_total} // AttrNum * 10", text)
    text = re.sub(r"Sigma\s*:=\s*[0-9.]+", f"Sigma := {sigma}", text)
    PRECOMP_MAIN.write_text(text)


def service_block_bounds(text, service):
    m = re.search(rf"(?m)^  {re.escape(service)}:\s*$", text)
    if not m: raise RuntimeError(f"Service {service} not found")
    start = m.start()
    n = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[m.end():])
    end = m.end() + n.start() if n else len(text)
    return start, end


def replace_in_service(text, service, fn):
    start, end = service_block_bounds(text, service)
    return text[:start] + fn(text[start:end]) + text[end:]


def replace_env_in_block(block, key, value):
    pattern = rf"(?m)^(\s*-\s*{re.escape(key)}=).*$"
    if re.search(pattern, block):
        return re.sub(pattern, rf"\g<1>{value}", block)
    m = re.search(r"(?m)^(\s*)environment:\s*$", block)
    if not m: raise RuntimeError("No environment section")
    indent = m.group(1) + "  "
    return block[:m.end()] + f"\n{indent}- {key}={value}" + block[m.end():]


def set_env(service, key, value):
    text = COMPOSE.read_text()
    COMPOSE.write_text(replace_in_service(text, service, lambda b: replace_env_in_block(b, key, value)))


def set_rate_mbit(service, rate):
    text = COMPOSE.read_text()
    def fn(block):
        block = re.sub(r"tc qdisc add dev eth0 root netem delay 20ms rate \d+mbit", f"tc qdisc add dev eth0 root netem delay 20ms rate {rate}mbit", block)
        block = re.sub(r"police rate \d+mbit", f"police rate {rate}mbit", block)
        block = re.sub(r"Network limits applied \(20ms, \d+Mbps\)", f"Network limits applied (20ms, {rate}Mbps)", block)
        block = re.sub(r"at \d+Mbps", f"at {rate}Mbps", block)
        return block
    COMPOSE.write_text(replace_in_service(text, service, fn))


def run_precompute_once():
    clean_all()
    set_precompute_params(PROFILE_TOTAL, SIGMA)
    res = run(["go", "run", "."], cwd=ROOT / "precompute", capture=True)
    print(res.stdout)


def prepare_compose(run_id):
    deltas_s = ",".join(f"{d:.2f}" for d in DELTAS)
    for svc in ["satellite", "terminal"]:
        set_env(svc, "RUN_ID", run_id)
        set_env(svc, "PARAM_M", PROFILE_TOTAL)
        set_env(svc, "PARAM_SIGMA", SIGMA)
        set_env(svc, "DATA_SIZE_MB", DATA_SIZE_MB)
        set_env(svc, "EXP_BANDWIDTH_MBPS", BANDWIDTH)
        set_env(svc, "EXP_RTT_MS", 20)
        set_env(svc, "EXP_LOSS_PCT", 0)
    set_env("satellite", "ENABLE_UPDATE_EXPERIMENT", "true")
    set_env("satellite", "UPDATE_DELTAS", deltas_s)
    set_rate_mbit("satellite", BANDWIDTH)


def compose_up():
    run(DC + ["up", "--build", "--force-recreate", "-d"], capture=True)


def get_logs(container):
    res = subprocess.run(["docker", "logs", container], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return res.stdout or ""


def wait_for_updates():
    pat = r"satellite_update_plot\.csv appended:\s*delta=([0-9.]+)\s+total=([0-9.]+)ms\s+recompile=([0-9.]+)ms\s+reencaps=([0-9.]+)ms\s+publication=([0-9.]+)ms"
    deadline = time.time() + TIMEOUT_SEC
    while time.time() < deadline:
        sat = get_logs("sat-node")
        matches = re.findall(pat, sat)
        if len(matches) >= len(DELTAS):
            return matches[:len(DELTAS)]
        time.sleep(2)
    raise TimeoutError("Timeout waiting for update PlotCSV lines")


def mean(vals): return sum(vals) / len(vals)
def std(vals):
    if len(vals) <= 1: return 0.0
    m = mean(vals)
    return math.sqrt(sum((v-m)**2 for v in vals) / (len(vals)-1))


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader(); w.writerows(rows)


def main():
    raw_rows, avg_rows = [], []
    raw_path, avg_path = ROOT / RAW_CSV, ROOT / AVG_CSV
    for p in [raw_path, avg_path]:
        if p.exists(): p.unlink()

    run_precompute_once()

    for run_idx in range(1, N_RUNS + 1):
        run_id = f"B5_2_R{run_idx:02d}"
        print("\n" + "=" * 100)
        print(f"[B-5-2] Run {run_idx}/{N_RUNS}: {run_id}")
        print("=" * 100)
        clean_runtime_keep_roots()
        prepare_compose(run_id)
        compose_up()
        try:
            matches = wait_for_updates()
            for delta, total, recompile, reencaps, publication in matches:
                row = {
                    "run_idx": run_idx,
                    "delta": float(delta),
                    "total_ms": float(total),
                    "recompile_ms": float(recompile),
                    "reencaps_ms": float(reencaps),
                    "publication_ms": float(publication),
                }
                raw_rows.append(row)
                print(f"[OK] {row}")
        finally:
            run(DC + ["down", "-v", "--remove-orphans"], check=False)
        write_csv(raw_path, raw_rows, ["run_idx", "delta", "total_ms", "recompile_ms", "reencaps_ms", "publication_ms"])

    for delta in DELTAS:
        subset = [r for r in raw_rows if abs(r["delta"] - delta) < 1e-9]
        avg = {"delta": delta}
        for k in ["total_ms", "recompile_ms", "reencaps_ms", "publication_ms"]:
            vals = [r[k] for r in subset]
            avg[k] = mean(vals)
            avg[k + "_std"] = std(vals)
        avg_rows.append(avg)
    write_csv(avg_path, avg_rows, ["delta", "total_ms", "total_ms_std", "recompile_ms", "recompile_ms_std", "reencaps_ms", "reencaps_ms_std", "publication_ms", "publication_ms_std"])

    print(f"\n[DONE] Raw results: {raw_path}")
    print(f"[DONE] Averaged results: {avg_path}")

if __name__ == "__main__":
    main()
