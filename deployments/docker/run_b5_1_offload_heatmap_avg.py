#!/usr/bin/env python3
"""
B-5-1 satellite-side offloading heatmap experiment with repeated runs and averaging.

Fixed workload:
  ProfileTotal = 20000
  Sigma = 0.49

7 x 7 sweep:
  Payload size (MB) = 10, 50, 100, 200, 350, 500, 1000
  Bandwidth (Mbps)  = 100, 150, 200, 300, 500, 700, 1000

For each configuration, repeats Docker N_RUNS times and averages:
  total latency, generation latency, publication latency.

The script parses the following satellite log line:
  [PlotCSV] satellite_offload_plot.csv appended:
  total=...ms generation=...ms publication=...ms

Usage:
  cd poly-lock-docker
  python3 run_b5_1_offload_heatmap_7x7_avg.py

Outputs:
  results_b5_1_offload_heatmap_7x7_raw.csv
  results_b5_1_offload_heatmap_7x7_avg.csv
"""

import csv
import math
import re
import shutil
import subprocess
import time
from pathlib import Path

# ────────── Experiment configuration ──────────
PROFILE_TOTAL = 20000
SIGMA = 0.49

PAYLOAD_MBS = [10, 50, 100, 200, 350, 500, 1000]
BANDWIDTHS = [100, 150, 200, 300, 500, 700, 1000]

N_RUNS = 10
TIMEOUT_SEC = 1200

RAW_CSV = "results_b5_1_offload_heatmap_7x7_raw.csv"
AVG_CSV = "results_b5_1_offload_heatmap_7x7_avg.csv"

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
    """
    Clean containers and runtime outputs, but keep validRoots/auth_user.

    This keeps the workload fixed across N repeated runs for the same
    ProfileTotal/Sigma setting, while clearing IPFS and runtime files.
    """
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

    text = re.sub(
        r"Sigma\s*:=\s*[0-9.]+",
        f"Sigma := {sigma}",
        text,
    )

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
        raise RuntimeError(f"No environment section found when setting {key}")

    indent = env_match.group(1) + "  "
    return block[:env_match.end()] + f"\n{indent}- {key}={value}" + block[env_match.end():]


def set_env(service, key, value):
    text = COMPOSE.read_text()
    COMPOSE.write_text(
        replace_in_service(
            text,
            service,
            lambda b: replace_env_in_block(b, key, value),
        )
    )


def set_rate_mbit(service, rate):
    """
    Update tc/netem bandwidth setting inside a service command block.

    It supports both:
      tc qdisc ... rate XXXmbit
      police rate XXXmbit
    """
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


def prepare_compose(run_id, payload_mb, bandwidth_mbps):
    for svc in ["satellite", "terminal"]:
        set_env(svc, "RUN_ID", run_id)
        set_env(svc, "PARAM_M", PROFILE_TOTAL)
        set_env(svc, "PARAM_SIGMA", SIGMA)
        set_env(svc, "DATA_SIZE_MB", payload_mb)
        set_env(svc, "EXP_BANDWIDTH_MBPS", bandwidth_mbps)
        set_env(svc, "EXP_RTT_MS", 20)
        set_env(svc, "EXP_LOSS_PCT", 0)

    # B-5-1 only measures initial data offloading.
    set_env("satellite", "ENABLE_UPDATE_EXPERIMENT", "false")

    # Satellite offloading path is the target of this experiment.
    set_rate_mbit("satellite", bandwidth_mbps)

    # Keep terminal metadata and network setting consistent. The script stops
    # once the satellite-side offloading metric is available.
    set_rate_mbit("terminal", bandwidth_mbps)


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


def wait_for_satellite_offload():
    deadline = time.time() + TIMEOUT_SEC

    while time.time() < deadline:
        sat = get_logs("sat-node")
        if "satellite_offload_plot.csv appended" in sat:
            return sat
        time.sleep(2)

    raise TimeoutError("Timeout waiting for satellite offloading logs")


def parse_satellite_offload(sat_log):
    pattern = (
        r"satellite_offload_plot\.csv appended:\s*"
        r"total=([0-9.]+)ms\s+"
        r"generation=([0-9.]+)ms\s+"
        r"publication=([0-9.]+)ms"
    )

    m = re.search(pattern, sat_log)
    if not m:
        raise RuntimeError("Could not parse satellite offload PlotCSV log")

    return {
        "total_ms": float(m.group(1)),
        "generation_ms": float(m.group(2)),
        "publication_ms": float(m.group(3)),
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
    raw_rows = []
    avg_rows = []

    raw_path = ROOT / RAW_CSV
    avg_path = ROOT / AVG_CSV

    for p in [raw_path, avg_path]:
        if p.exists():
            p.unlink()

    print("\n" + "=" * 100)
    print(f"[B-5-1] Precomputing workload: ProfileTotal={PROFILE_TOTAL}, Sigma={SIGMA}")
    print("=" * 100)

    run_precompute_once()

    for payload_mb in PAYLOAD_MBS:
        for bandwidth_mbps in BANDWIDTHS:
            config_rows = []

            print("\n" + "=" * 100)
            print(f"[B-5-1] Payload={payload_mb} MB, Bandwidth={bandwidth_mbps} Mbps")
            print("=" * 100)

            for run_idx in range(1, N_RUNS + 1):
                run_id = f"B5_1_P{payload_mb}_BW{bandwidth_mbps}_R{run_idx:02d}"
                print(f"\n[B-5-1] Run {run_idx}/{N_RUNS}: {run_id}")

                clean_runtime_keep_roots()
                prepare_compose(run_id, payload_mb, bandwidth_mbps)
                compose_up()

                try:
                    sat_log = wait_for_satellite_offload()
                    metrics = parse_satellite_offload(sat_log)

                    row = {
                        "payload_mb": payload_mb,
                        "bandwidth_mbps": bandwidth_mbps,
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
                        "payload_mb",
                        "bandwidth_mbps",
                        "run_idx",
                        "total_ms",
                        "generation_ms",
                        "publication_ms",
                    ],
                )

            avg = {
                "payload_mb": payload_mb,
                "bandwidth_mbps": bandwidth_mbps,
            }

            for k in ["total_ms", "generation_ms", "publication_ms"]:
                vals = [r[k] for r in config_rows]
                avg[k] = mean(vals)
                avg[k + "_std"] = std(vals)

            avg_rows.append(avg)

            write_csv(
                avg_path,
                avg_rows,
                [
                    "payload_mb",
                    "bandwidth_mbps",
                    "total_ms",
                    "total_ms_std",
                    "generation_ms",
                    "generation_ms_std",
                    "publication_ms",
                    "publication_ms_std",
                ],
            )

    print(f"\n[DONE] Raw results: {raw_path}")
    print(f"[DONE] Averaged results: {avg_path}")


if __name__ == "__main__":
    main()