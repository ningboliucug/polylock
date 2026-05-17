#!/usr/bin/env python3
"""
B-4 experiment automation with repeated runs and averaging.

Runs ProfileTotal in {20000,30000,40000,50000,60000} and Sigma in {0.01,0.49}.
For each configuration, runs Docker N_RUNS times and reports the mean of:
  T_enc + T_dataenc, T_tx1, T_tx2, T_dec + T_datadec,
  satellite AvgCPUByQuota, satellite MaxRSS.

Usage:
  cd poly-lock-docker
  python3 run_b4_policy_profile_avg.py

Outputs:
  results_b4_policy_profile_raw.csv
  results_b4_policy_profile_avg.csv
"""

import csv
import math
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

PROFILE_TOTALS = [20000, 30000, 40000, 50000, 60000]
SIGMAS = [0.01, 0.49]
N_RUNS = 10
DATA_SIZE_MB = 10
TIMEOUT_SEC = 1200
RAW_CSV = "results_b4_policy_profile_raw.csv"
AVG_CSV = "results_b4_policy_profile_avg.csv"

ROOT = Path(__file__).resolve().parent
PRECOMP_MAIN = ROOT / "precompute" / "main.go"
COMPOSE = ROOT / "docker-compose.yml"
SHARED = ROOT / "shared-data"
IPFS_DATA = ROOT / "ipfs-data"


def run(cmd, cwd=ROOT, check=True, capture=True):
    print(f"$ {' '.join(map(str, cmd))}")
    return subprocess.run(
        list(map(str, cmd)), cwd=str(cwd), check=check, text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def docker_compose_cmd():
    try:
        subprocess.run(["docker", "compose", "version"], cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]

DC = docker_compose_cmd()


def clean_all():
    """Equivalent to: docker compose down -v && rm -rf ipfs-data/* shared-data/*"""
    run(DC + ["down", "-v", "--remove-orphans"], check=False)
    SHARED.mkdir(exist_ok=True)
    IPFS_DATA.mkdir(exist_ok=True)
    for folder in [SHARED, IPFS_DATA]:
        for p in list(folder.iterdir()):
            try:
                if p.is_dir():
                    shutil.rmtree(p)
                else:
                    p.unlink()
            except Exception as e:
                print(f"[WARN] Failed to remove {p}: {e}")


def clean_runtime_keep_roots():
    """Clean containers and runtime outputs, but keep validRoots/auth_user to avoid rerunning precompute in repeated runs."""
    run(DC + ["down", "-v", "--remove-orphans"], check=False)
    SHARED.mkdir(exist_ok=True)
    IPFS_DATA.mkdir(exist_ok=True)
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
    if not m:
        raise RuntimeError(f"Service {service} not found in docker-compose.yml")
    start = m.start()
    n = re.search(r"(?m)^  [A-Za-z0-9_-]+:\s*$", text[m.end():])
    end = m.end() + n.start() if n else len(text)
    return start, end


def replace_in_service(text, service, fn):
    start, end = service_block_bounds(text, service)
    block = fn(text[start:end])
    return text[:start] + block + text[end:]


def replace_env_in_block(block, key, value):
    pattern = rf"(?m)^(\s*-\s*{re.escape(key)}=).*$"
    if re.search(pattern, block):
        return re.sub(pattern, rf"\g<1>{value}", block)
    env_match = re.search(r"(?m)^(\s*)environment:\s*$", block)
    if not env_match:
        raise RuntimeError("No environment section")
    indent = env_match.group(1) + "  "
    return block[:env_match.end()] + f"\n{indent}- {key}={value}" + block[env_match.end():]


def set_env(service, key, value):
    text = COMPOSE.read_text()
    COMPOSE.write_text(replace_in_service(text, service, lambda b: replace_env_in_block(b, key, value)))


def prepare_compose(run_id, profile_total, sigma):
    for svc in ["satellite", "terminal"]:
        set_env(svc, "RUN_ID", run_id)
        set_env(svc, "PARAM_M", profile_total)
        set_env(svc, "PARAM_SIGMA", sigma)
        set_env(svc, "DATA_SIZE_MB", DATA_SIZE_MB)
    set_env("satellite", "ENABLE_UPDATE_EXPERIMENT", "false")


def run_precompute():
    res = run(["go", "run", "."], cwd=ROOT / "precompute", capture=True)
    print(res.stdout)


def compose_up():
    run(DC + ["up", "--build", "--force-recreate", "-d"], capture=True)


def get_logs(container):
    res = subprocess.run(["docker", "logs", container], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return res.stdout or ""


def wait_for_patterns():
    deadline = time.time() + TIMEOUT_SEC
    while time.time() < deadline:
        sat = get_logs("sat-node")
        term = get_logs("term-node")
        if ("[ResourceMetric] Satellite Active Workflow" in sat and
            "[Metric] T_tx1" in sat and
            "[RESULT] Total E2E Latency" in term and
            "[Metric] T_datadec" in term):
            return sat, term
        time.sleep(2)
    raise TimeoutError("Timeout waiting for B-4 logs")


def parse_go_duration_ms(s):
    units = {"h": 3600000.0, "m": 60000.0, "s": 1000.0, "ms": 1.0, "us": 0.001, "µs": 0.001, "ns": 0.000001}
    total = 0.0
    for num, unit in re.findall(r"([0-9]+(?:\.[0-9]+)?)(ns|µs|us|ms|s|m|h)", s):
        total += float(num) * units[unit]
    return total


def extract_one(pattern, text, name):
    m = re.search(pattern, text)
    if not m:
        raise RuntimeError(f"Could not extract {name}")
    return m.group(1)


def parse_metrics(sat, term):
    t_enc = parse_go_duration_ms(extract_one(r"T_enc \(KEM Encryption CPU Time\):\s*([^\n]+)", sat, "T_enc"))
    t_dataenc = parse_go_duration_ms(extract_one(r"T_dataenc \(DEM Encryption CPU Time\):\s*([^\s]+)", sat, "T_dataenc"))
    t_tx1 = parse_go_duration_ms(extract_one(r"T_tx1 \(Total Upload Latency\) =\s*([^\n]+)", sat, "T_tx1"))
    t_tx2 = parse_go_duration_ms(extract_one(r"T_tx2 \(Total Download Latency\) =\s*([^\n]+)", term, "T_tx2"))
    t_dec = parse_go_duration_ms(extract_one(r"T_dec \(KEM Decryption CPU Time\):\s*([^\s]+)", term, "T_dec"))
    t_datadec = parse_go_duration_ms(extract_one(r"T_datadec \(DEM Decryption CPU Time\):\s*([^\s]+)", term, "T_datadec"))
    res = re.search(r"Satellite Active Workflow .*?AvgCPUByQuota=([0-9.]+)%\s+MaxRSS=([0-9.]+) MB", sat)
    if not res:
        raise RuntimeError("Could not extract satellite resource metrics")
    return {
        "t_enc_plus_dataenc_ms": t_enc + t_dataenc,
        "t_tx1_ms": t_tx1,
        "t_tx2_ms": t_tx2,
        "t_dec_plus_datadec_ms": t_dec + t_datadec,
        "sat_avg_cpu_by_quota_pct": float(res.group(1)),
        "sat_max_rss_mb": float(res.group(2)),
    }


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
    raw_rows = []
    avg_rows = []
    raw_path = ROOT / RAW_CSV
    avg_path = ROOT / AVG_CSV
    for p in [raw_path, avg_path]:
        if p.exists(): p.unlink()

    for profile_total in PROFILE_TOTALS:
        for sigma in SIGMAS:
            print("\n" + "=" * 100)
            print(f"[B-4] Preparing ProfileTotal={profile_total}, Sigma={sigma}")
            print("=" * 100)
            clean_all()
            set_precompute_params(profile_total, sigma)
            run_precompute()

            config_metrics = []
            for run_idx in range(1, N_RUNS + 1):
                run_id = f"B4_M{profile_total}_S{sigma}_R{run_idx:02d}"
                print(f"\n[B-4] Run {run_idx}/{N_RUNS}: {run_id}")
                clean_runtime_keep_roots()
                prepare_compose(run_id, profile_total, sigma)
                compose_up()
                try:
                    sat, term = wait_for_patterns()
                    metrics = parse_metrics(sat, term)
                    config_metrics.append(metrics)
                    row = {"profile_total": profile_total, "sigma": sigma, "run_idx": run_idx, **metrics}
                    raw_rows.append(row)
                    print(f"[OK] {row}")
                finally:
                    run(DC + ["down", "-v", "--remove-orphans"], check=False)
                write_csv(raw_path, raw_rows, ["profile_total", "sigma", "run_idx", "t_enc_plus_dataenc_ms", "t_tx1_ms", "t_tx2_ms", "t_dec_plus_datadec_ms", "sat_avg_cpu_by_quota_pct", "sat_max_rss_mb"])

            avg = {"profile_total": profile_total, "sigma": sigma}
            for k in ["t_enc_plus_dataenc_ms", "t_tx1_ms", "t_tx2_ms", "t_dec_plus_datadec_ms", "sat_avg_cpu_by_quota_pct", "sat_max_rss_mb"]:
                vals = [m[k] for m in config_metrics]
                avg[k] = mean(vals)
                avg[k + "_std"] = std(vals)
            avg_rows.append(avg)
            write_csv(avg_path, avg_rows, ["profile_total", "sigma", "t_enc_plus_dataenc_ms", "t_enc_plus_dataenc_ms_std", "t_tx1_ms", "t_tx1_ms_std", "t_tx2_ms", "t_tx2_ms_std", "t_dec_plus_datadec_ms", "t_dec_plus_datadec_ms_std", "sat_avg_cpu_by_quota_pct", "sat_avg_cpu_by_quota_pct_std", "sat_max_rss_mb", "sat_max_rss_mb_std"])

    print(f"\n[DONE] Raw results: {raw_path}")
    print(f"[DONE] Averaged results: {avg_path}")

if __name__ == "__main__":
    main()
