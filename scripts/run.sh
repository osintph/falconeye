#!/usr/bin/env bash
# Run a FalconEye ingest worker, the sieve, the SSG, or a full ingest cycle.
# Usage: sudo bash scripts/run.sh <worker>
# Workers: urlhaus  kev  nvd  apnic  sieve  cluster  shodan  ssg  digest  all
set -euo pipefail

SECRETS=/opt/falconeye/config/secrets.env
PYTHON=/opt/falconeye/venv/bin/python

usage() {
  echo "Usage: $0 <worker>"
  echo "Workers: urlhaus  kev  nvd  apnic  sieve  cluster  shodan  ssg  digest  all"
  exit 1
}

# --- Root check ---
if [ "$(id -u)" != "0" ]; then
  echo "ERROR: Run as root: sudo bash scripts/run.sh <worker>"
  exit 1
fi

if [ $# -ne 1 ]; then
  usage
fi

WORKER="$1"

# --- secrets.env check ---
if [ ! -f "${SECRETS}" ]; then
  echo "ERROR: ${SECRETS} not found."
  echo "Copy config/secrets.env.example to ${SECRETS} and fill in the API keys."
  exit 1
fi

# shellcheck source=/dev/null
set -a
source "${SECRETS}"
set +a

# --- Dispatch ---
run_worker() {
  local w="$1"
  case "${w}" in
    urlhaus) exec_module="falconeye.ingest.urlhaus" ;;
    kev)     exec_module="falconeye.ingest.kev" ;;
    nvd)     exec_module="falconeye.ingest.nvd" ;;
    apnic)   exec_module="falconeye.ingest.apnic" ;;
    sieve)   exec_module="falconeye.sieve" ;;
    cluster) exec_module="falconeye.cluster" ;;
    shodan)  exec_module="falconeye.ingest.shodan_enrich" ;;
    ssg)     exec_module="falconeye.ssg" ;;
    digest)  exec_module="falconeye.digest" ;;
    *)       echo "Unknown worker: ${w}"; usage ;;
  esac
  "${PYTHON}" -m "${exec_module}"
}

if [ "${WORKER}" = "all" ]; then
  for w in urlhaus kev nvd apnic sieve cluster shodan ssg; do
    echo "--- ${w} ---"
    run_worker "${w}" || { echo "FAILED: ${w}"; exit 1; }
  done
else
  # Use exec so exit code propagates for single-worker calls
  case "${WORKER}" in
    urlhaus) exec "${PYTHON}" -m falconeye.ingest.urlhaus ;;
    kev)     exec "${PYTHON}" -m falconeye.ingest.kev ;;
    nvd)     exec "${PYTHON}" -m falconeye.ingest.nvd ;;
    apnic)   exec "${PYTHON}" -m falconeye.ingest.apnic ;;
    sieve)   exec "${PYTHON}" -m falconeye.sieve ;;
    cluster) exec "${PYTHON}" -m falconeye.cluster ;;
    shodan)  exec "${PYTHON}" -m falconeye.ingest.shodan_enrich ;;
    ssg)     exec "${PYTHON}" -m falconeye.ssg ;;
    digest)  exec "${PYTHON}" -m falconeye.digest ;;
    *)       echo "Unknown worker: ${WORKER}"; usage ;;
  esac
fi
