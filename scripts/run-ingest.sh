#!/usr/bin/env bash
# Run a single FalconEye ingest worker or the sieve/SSG manually.
# Usage: sudo bash scripts/run-ingest.sh <worker>
# Workers: urlhaus  kev  nvd  apnic  sieve  ssg
set -euo pipefail

SECRETS=/opt/falconeye/config/secrets.env
PYTHON=/opt/falconeye/venv/bin/python

VALID_WORKERS="urlhaus kev nvd apnic sieve ssg"

usage() {
  echo "Usage: $0 <worker>"
  echo "Workers: ${VALID_WORKERS}"
  exit 1
}

if [ $# -ne 1 ]; then
  usage
fi

WORKER="$1"

case "${WORKER}" in
  urlhaus) MODULE="falconeye.ingest.urlhaus" ;;
  kev)     MODULE="falconeye.ingest.kev" ;;
  nvd)     MODULE="falconeye.ingest.nvd" ;;
  apnic)   MODULE="falconeye.ingest.apnic" ;;
  sieve)   MODULE="falconeye.sieve" ;;
  ssg)     MODULE="falconeye.ssg" ;;
  *)       echo "Unknown worker: ${WORKER}"; usage ;;
esac

if [ ! -f "${SECRETS}" ]; then
  echo "ERROR: ${SECRETS} not found."
  echo "Copy config/secrets.env.example to ${SECRETS} and fill in the API keys."
  exit 1
fi

# shellcheck source=/dev/null
set -a
source "${SECRETS}"
set +a

exec "${PYTHON}" -m "${MODULE}" "$@"
