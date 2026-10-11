"""Serve one-time results: the on-screen payload and the downloadable PDF.

Shared by the ASM and Hunt routers so the one-time rules live in one place. The
PDF stream deletes the ephemeral row and the file ONLY after the stream has
completed successfully; an interrupted download leaves the result available until
the TTL sweep. No em dashes in this module.
"""
from __future__ import annotations

import logging
import os

from fastapi.responses import JSONResponse, StreamingResponse

from app import config
from app.asm import store

log = logging.getLogger("falconeye.asm.serve")


def sweep() -> None:
    try:
        store.sweep_results(config.ASM_RESULT_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001 - a sweep failure must not break a request
        log.warning("asm result sweep failed: %s", exc)


def payload_response(scan: dict, result_id: str):
    """The status/result JSON for a run. Sweeps expired results first."""
    sweep()
    state = scan.get("state")
    if state in ("queued", "running"):
        from app.asm import jobs
        return {"scan_id": result_id, "state": state, "capacity": jobs.capacity()}
    if state == "error":
        return {"scan_id": result_id, "state": "error", "error": scan.get("error")}
    row = store.get_result(result_id)
    if not row or not row.get("payload"):
        # Done but the result has been downloaded or swept: one-time means gone.
        return {"scan_id": result_id, "state": "expired",
                "message": "Results are not kept. This result has been downloaded or has expired."}
    payload = row["payload"]
    payload["state"] = "done"
    payload["scan_id"] = result_id
    payload["pdf_ready"] = bool(row.get("pdf_path")) and os.path.exists(row.get("pdf_path") or "")
    return payload


def export_response(result_id: str, fmt: str):
    row = store.get_result(result_id)
    if not row or not row.get("payload"):
        return JSONResponse({"error": "Not found."}, status_code=404)
    from app.asm import report
    payload = row["payload"]
    base = f"falconeye-{payload.get('kind', 'asm')}-{str(payload.get('title') or 'report').replace('.', '-')}"
    if fmt == "json":
        return _text(report.export_json_payload(payload), "application/json", f"{base}.json")
    if fmt == "csv":
        return _text(report.export_csv_payload(payload), "text/csv", f"{base}.csv")
    return JSONResponse({"error": "Unknown format."}, status_code=400)


def _text(body: str, media: str, filename: str):
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(body, media_type=media,
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})


def pdf_stream(result_id: str, pdf_path: str):
    """Yield the PDF bytes, then delete the ephemeral row and file ONLY if the
    whole file was sent. A client disconnect raises GeneratorExit at the yield,
    leaving completed False, so the result stays available until the TTL sweep.
    Factored out so the completion-before-delete behaviour is directly testable."""
    completed = False
    try:
        with open(pdf_path, "rb") as fh:
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                yield chunk
        completed = True
    finally:
        if completed:
            store.delete_result(result_id)
            log.info("asm result delivered and purged id=%s", result_id)


def pdf_response(result_id: str):
    """Stream the PDF, then delete the row and file only on a completed stream."""
    row = store.get_result(result_id)
    pdf_path = (row or {}).get("pdf_path")
    if not row or not pdf_path or not os.path.exists(pdf_path):
        return JSONResponse({"error": "Not found."}, status_code=404)
    payload = row.get("payload") or {}
    base = f"falconeye-{payload.get('kind', 'asm')}-{str(payload.get('title') or 'report').replace('.', '-')}.pdf"
    return StreamingResponse(pdf_stream(result_id, pdf_path), media_type="application/pdf",
                             headers={"Content-Disposition": f'attachment; filename="{base}"'})
