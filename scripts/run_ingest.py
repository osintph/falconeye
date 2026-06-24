#!/usr/bin/env python3
import asyncio
import json
import sys
import os

# Ensure app package is on path when run as a script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.workers.ingest import run_all_feeds

if __name__ == "__main__":
    result = asyncio.run(run_all_feeds())
    print(json.dumps(result, indent=2))
