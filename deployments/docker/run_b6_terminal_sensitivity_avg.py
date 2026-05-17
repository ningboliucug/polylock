#!/usr/bin/env python3
"""
B-6 experiment automation with repeated runs and averaging.

Fixed workload:
  ProfileTotal = 20000
  Sigma = 0.49
  DATA_SIZE_MB = 10
  network bandwidth = 100 Mbps

Runs terminal resource-envelope configurations:
  0.1 vCPU / 512 MB
  0.25 vCPU / 512 MB
  0.5 vCPU / 512 MB
  1.0 vCPU / 512 MB
  2.0 vCPU / 512 MB

For each configuration, repeats Docker N_RUNS times and averages:
  AvgCPUByQuota, MaxRSS, Download, Decrypt, Total.

Usage:
  cd poly-lock-docker
  python3 run_b6_terminal_sensitivity_avg.py

Outputs:
  results_b6_terminal_sensitivity_raw.csv
  results_b6_terminal_sensitivity_avg.csv
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
N_RUNS = 10

# Fixed memory budget: 512 MB.
# For fractional CPU quotas, bind the container to one physical core
# and use Docker CPU quota to emulate constrained terminal budgets.
TERMINAL_CONFIGS = [
    {"label": "0.1vCPU_512MB", "cpu": 0.1, "mem_gb": 0.5, "mem_limit": "512m", "cpuset": "2", "gomaxprocs": 1},
    {"label": "0.25vCPU_512MB", "cpu": 0.25, "mem_gb": 0.5, "mem_limit": "512m", "cpuset": "2", "gomaxprocs": 1},
    {"label": "0.5vCPU_512MB", "cpu": 0.5, "mem_gb": 0.5, "mem_limit": "512m", "cpuset": "2", "gomaxprocs": 1},
    {"label": "1vCPU_512MB", "cpu": 1.0, "mem_gb": 0.5, "mem_limit": "512m", "cpuset": "2", "gomaxprocs": 1},
    {"label": "2vCPU_512MB", "cpu": 2.0, "mem_gb": 0.5, "mem_limit": "512m", "cpuset": "2-3", "gomaxprocs": 2},
]

RAW_CSV = "results_b6_terminal_sensitivity_raw.csv"
AVG_CSV = "results_b6_terminal_sensitivity_avg.csv"
TIMEOUT_SEC = 1200

ROOT = Path(__file__).resolve().parent
PRECOMP_MAIN = ROOT / "precompute" / "main.go"
COMPOSE = ROOT / "docker-compose.yml"
SHARED = ROOT / "shared-data"
IPFS_DATA = ROOT / "ipfs-data"


def run(cmd, cwd=ROOT, check=True, capture=True):
    print(f"$ {' '.join(map(str, cmd))}")
    return subprocess.run(
        list(map(str, cmd)),
        cwd=str(cwd),
        check=check,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )


def docker_compose_cmd():
    try:
        subprocess.run(
            ["docker", "compose", "version"],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        return ["docker", "compose"]
    except Exception:
        return ["docker-compose"]


DC = docker_compose_cmd()


def clean_all():
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
    run(DC + ["down", "-v", "--remove-orphans"], check=False)
    SHARED.mkdir(exist_ok=True)
    IPFS_DATA.mkdir(exist_ok=True)

    for p in list(SHARED.iterdir()):
        if p.name in {"validRoots.json", "auth_user.json"}:
            continue
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
        except Exception as e:
            print(f"[WARN] Failed to remove {p}: {e}")

    for p in list(IPFS_DATA.iterdir()):
        try:
            if p.is_dir():
                shutil.rmtree(p)
            else:
                p.unlink()
        except Exception as e:
            print(f"[WARN] Failed to remove {p}: {e}")


def set_precompute_params(profile_total, sigma):
    text = PRECOMP_MAIN.read_text()
    text = re.sub(
        r"ProfileTotal\s*:=\s*\d+(\s*//[^\n]*)?",
        f"ProfileTotal := {profile_total} // AttrNum * 10",
        text,
    )
    text = re.sub(r"Sigma\s*:=\s*[0-9.]+", f"Sigma := {sigma}", text)
    PRECOMP_MAIN.write_text(text)


def service_block_bounds(text, service):
    m = re.search(rf"(?m)^  {re.escape(service)}:\s*$", text)
    if not m:
        raise RuntimeError(f"Service {service} not found")

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
    if not m:
        raise RuntimeError("No environment section")

    indent = m.group(1) + "  "
    return block[:m.end()] + f"\n{indent}- {key}={value}" + block[m.end():]


def set_env(service, key, value):
    text = COMPOSE.read_text()
    COMPOSE.write_text(
        replace_in_service(
            text,
            service,
            lambda b: replace_env_in_block(b, key, value),
        )
    )


def set_service_scalar(service, key, value):
    text = COMPOSE.read_text()

    def fn(block):
        pattern = rf"(?m)^(\s*){re.escape(key)}:\s*.*$"
        if re.search(pattern, block):
            return re.sub(pattern, rf"\g<1>{key}: {value}", block)

        m = re.search(r"(?m)^(\s*)depends_on:\s*\n(?:\s+-\s+[^\n]+\n)+", block)
        if m:
            return block[:m.end()] + f"\n    {key}: {value}\n" + block[m.end():]

        return block + f"\n    {key}: {value}\n"

    COMPOSE.write_text(replace_in_service(text, service, fn))


def fmt_cpu(cpu):
    """Format CPU quota for docker-compose, e.g., 0.1, 0.25, 1, 2."""
    return f"{float(cpu):g}"


def set_rate_mbit(service, rate):
    text = COMPOSE.read_text()

    def fn(block):
        block = re.sub(
            r"tc qdisc add dev eth0 root netem delay 20ms rate \d+mbit",
            f"tc qdisc add dev eth0 root netem delay 20ms rate {rate}mbit",
            block,
        )
        block = re.sub(
            r"police rate \d+mbit",
            f"police rate {rate}mbit",
            block,
        )
        block = re.sub(
            r"Network limits applied \(20ms, \d+Mbps\)",
            f"Network limits applied (20ms, {rate}Mbps)",
            block,
        )
        block = re.sub(
            r"at \d+Mbps",
            f"at {rate}Mbps",
            block,
        )
        return block

    COMPOSE.write_text(replace_in_service(text, service, fn))


def run_precompute_once():
    clean_all()
    set_precompute_params(PROFILE_TOTAL, SIGMA)
    res = run(["go", "run", "."], cwd=ROOT / "precompute", capture=True)
    print(res.stdout)


def prepare_compose_for_config(cfg, run_id):
    for svc in ["satellite", "terminal"]:
        set_env(svc, "RUN_ID", run_id)
        set_env(svc, "PARAM_M", PROFILE_TOTAL)
        set_env(svc, "PARAM_SIGMA", SIGMA)
        set_env(svc, "DATA_SIZE_MB", DATA_SIZE_MB)
        set_env(svc, "EXP_BANDWIDTH_MBPS", BANDWIDTH)
        set_env(svc, "EXP_RTT_MS", 20)
        set_env(svc, "EXP_LOSS_PCT", 0)

    set_env("satellite", "ENABLE_UPDATE_EXPERIMENT", "false")

    set_rate_mbit("satellite", BANDWIDTH)
    set_rate_mbit("terminal", BANDWIDTH)

    set_service_scalar("terminal", "cpus", fmt_cpu(cfg["cpu"]))
    set_service_scalar("terminal", "mem_limit", cfg["mem_limit"])
    set_service_scalar("terminal", "cpuset", f'"{cfg["cpuset"]}"')

    set_env("terminal", "GOMAXPROCS", cfg["gomaxprocs"])
    set_env("terminal", "TERMINAL_CPU", cfg["cpu"])
    set_env("terminal", "TERMINAL_MEM_GB", cfg["mem_gb"])


def compose_up():
    run(DC + ["up", "--build", "--force-recreate", "-d"], capture=True)


def get_logs(container):
    res = subprocess.run(
        ["docker", "logs", container],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return res.stdout or ""


def wait_for_terminal():
    deadline = time.time() + TIMEOUT_SEC
    while time.time() < deadline:
        term = get_logs("term-node")
        if "[ResourceMetric] Terminal Access Workflow" in term and "terminal_resource_plot.csv appended" in term:
            return term
        time.sleep(2)

    raise TimeoutError("Timeout waiting for terminal resource logs")


def parse_terminal(term):
    r1 = re.search(
        r"Terminal Access Workflow .*?AvgCPUByQuota=([0-9.]+)%\s+MaxRSS=([0-9.]+) MB",
        term,
    )
    if not r1:
        raise RuntimeError("Could not parse Terminal ResourceMetric")

    r2 = re.search(
        r"terminal_resource_plot\.csv appended:\s*Download=([0-9.]+)ms\s+Decrypt=([0-9.]+)ms\s+Total=([0-9.]+)ms",
        term,
    )
    if not r2:
        raise RuntimeError("Could not parse terminal PlotCSV")

    return {
        "avg_cpu_by_quota_pct": float(r1.group(1)),
        "max_rss_mb": float(r1.group(2)),
        "download_ms": float(r2.group(1)),
        "decrypt_ms": float(r2.group(2)),
        "total_ms": float(r2.group(3)),
    }


def mean(vals):
    return sum(vals) / len(vals)


def std(vals):
    if len(vals) <= 1:
        return 0.0
    m = mean(vals)
    return math.sqrt(sum((v - m) ** 2 for v in vals) / (len(vals) - 1))


def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main():
    raw_rows, avg_rows = [], []

    raw_path = ROOT / RAW_CSV
    avg_path = ROOT / AVG_CSV

    for p in [raw_path, avg_path]:
        if p.exists():
            p.unlink()

    run_precompute_once()

    for cfg in TERMINAL_CONFIGS:
        config_rows = []

        print("\n" + "=" * 100)
        print(f"[B-6] Terminal config: {cfg['label']}")
        print("=" * 100)

        for run_idx in range(1, N_RUNS + 1):
            run_id = f"B6_{cfg['label']}_R{run_idx:02d}"
            print(f"\n[B-6] Run {run_idx}/{N_RUNS}: {run_id}")

            clean_runtime_keep_roots()
            prepare_compose_for_config(cfg, run_id)
            compose_up()

            try:
                term = wait_for_terminal()
                metrics = parse_terminal(term)

                row = {
                    "terminal_config": cfg["label"],
                    "terminal_cpu": cfg["cpu"],
                    "terminal_mem_gb": cfg["mem_gb"],
                    "run_idx": run_idx,
                    **metrics,
                }

                raw_rows.append(row)
                config_rows.append(row)
                print(f"[OK] {row}")

            finally:
                run(DC + ["down", "-v", "--remove-orphans"], check=False)

            write_csv(
                raw_path,
                raw_rows,
                [
                    "terminal_config",
                    "terminal_cpu",
                    "terminal_mem_gb",
                    "run_idx",
                    "avg_cpu_by_quota_pct",
                    "max_rss_mb",
                    "download_ms",
                    "decrypt_ms",
                    "total_ms",
                ],
            )

        avg = {
            "terminal_config": cfg["label"],
            "terminal_cpu": cfg["cpu"],
            "terminal_mem_gb": cfg["mem_gb"],
        }

        for k in [
            "avg_cpu_by_quota_pct",
            "max_rss_mb",
            "download_ms",
            "decrypt_ms",
            "total_ms",
        ]:
            vals = [r[k] for r in config_rows]
            avg[k] = mean(vals)
            avg[k + "_std"] = std(vals)

        avg_rows.append(avg)

        write_csv(
            avg_path,
            avg_rows,
            [
                "terminal_config",
                "terminal_cpu",
                "terminal_mem_gb",
                "avg_cpu_by_quota_pct",
                "avg_cpu_by_quota_pct_std",
                "max_rss_mb",
                "max_rss_mb_std",
                "download_ms",
                "download_ms_std",
                "decrypt_ms",
                "decrypt_ms_std",
                "total_ms",
                "total_ms_std",
            ],
        )

    print(f"\n[DONE] Raw results: {raw_path}")
    print(f"[DONE] Averaged results: {avg_path}")


if __name__ == "__main__":
    main()