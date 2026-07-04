from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter

from app.config import HTTPX_TIMEOUT
from app.utils.client_ip import get_client_ip_key
from app.utils.ssrf import validate_url

router = APIRouter(prefix="/api/crypto", tags=["crypto"])
limiter = Limiter(key_func=get_client_ip_key)

BLOCKSTREAM_BASE = "https://blockstream.info/api"
BLOCKCYPHER_ETH_BASE = "https://api.blockcypher.com/v1/eth/main/addrs"
TRONGRID_BASE = "https://api.trongrid.io"
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"


def detect_chain(address: str) -> str:
    address = address.strip()
    if address.startswith("T") and len(address) == 34:
        return "trc20"
    if address.startswith(("1", "3", "bc1")) and 25 <= len(address) <= 62:
        return "btc"
    if address.startswith("0x") and len(address) == 42:
        return "eth"
    return "unknown"


@router.get("/lookup/{address}")
@limiter.limit("20/minute")
async def lookup_address(request: Request, address: str):
    address = address.strip()
    chain = detect_chain(address)

    if chain == "unknown":
        raise HTTPException(
            status_code=400,
            detail="Unrecognized address format. Supported: BTC, ETH, USDT TRC20 (TRON).",
        )

    if chain == "btc":
        return await lookup_btc(address)
    elif chain == "eth":
        return await lookup_eth(address)
    elif chain == "trc20":
        return await lookup_trc20(address)


async def lookup_btc(address: str) -> dict:
    info_url = f"{BLOCKSTREAM_BASE}/address/{address}"
    txs_url = f"{BLOCKSTREAM_BASE}/address/{address}/txs"

    for url in (info_url, txs_url):
        ok, reason = validate_url(url)
        if not ok:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {reason}")

    try:
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
            r_info = await client.get(info_url, headers={"User-Agent": "FalconEye/3.0"})
            r_info.raise_for_status()
            info = r_info.json()

            r_txs = await client.get(txs_url, headers={"User-Agent": "FalconEye/3.0"})
            r_txs.raise_for_status()
            raw_txs = r_txs.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            raise HTTPException(status_code=429, detail="Blockstream rate limit reached. Try again in a moment.")
        raise HTTPException(status_code=503, detail=f"Blockstream API error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream fetch failed: {str(e)}")

    chain_stats = info.get("chain_stats", {})
    funded_sat = chain_stats.get("funded_txo_sum", 0) or 0
    spent_sat = chain_stats.get("spent_txo_sum", 0) or 0
    balance_sat = funded_sat - spent_sat
    tx_count = chain_stats.get("tx_count", 0) or 0

    transactions = []
    for tx in raw_txs[:25]:
        received_sat = sum(
            out.get("value", 0)
            for out in tx.get("vout", [])
            if out.get("scriptpubkey_address") == address
        )
        sent_sat_tx = sum(
            inp.get("prevout", {}).get("value", 0)
            for inp in tx.get("vin", [])
            if inp.get("prevout", {}).get("scriptpubkey_address") == address
        )
        balance_change = received_sat - sent_sat_tx
        is_received = balance_change > 0

        if is_received:
            counterparty = next(
                (
                    inp.get("prevout", {}).get("scriptpubkey_address", "")
                    for inp in tx.get("vin", [])
                    if inp.get("prevout", {}).get("scriptpubkey_address") != address
                ),
                "",
            )
        else:
            counterparty = next(
                (
                    out.get("scriptpubkey_address", "")
                    for out in tx.get("vout", [])
                    if out.get("scriptpubkey_address") != address
                ),
                "",
            )

        block_time = tx.get("status", {}).get("block_time")
        transactions.append({
            "hash": tx.get("txid", ""),
            "time": block_time * 1000 if block_time else None,
            "balance_change": balance_change,
            "is_received": is_received,
            "from": counterparty if is_received else address,
            "to": address if is_received else counterparty,
        })

    return {
        "chain": "BTC",
        "address": address,
        "balance_satoshi": balance_sat,
        "balance_btc": round(balance_sat / 1e8, 8),
        "received_btc": round(funded_sat / 1e8, 8),
        "spent_btc": round(spent_sat / 1e8, 8),
        "tx_count": tx_count,
        "first_seen": None,
        "transactions": transactions,
    }


async def lookup_eth(address: str) -> dict:
    url = f"{BLOCKCYPHER_ETH_BASE}/{address}"
    ok, reason = validate_url(url)
    if not ok:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {reason}")

    try:
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
            r = await client.get(url, headers={"User-Agent": "FalconEye/3.0"})
            r.raise_for_status()
            info = r.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 429:
            raise HTTPException(status_code=429, detail="BlockCypher rate limit reached. Try again in a moment.")
        raise HTTPException(status_code=503, detail=f"BlockCypher API error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Upstream fetch failed: {str(e)}")

    balance_wei = info.get("balance", 0) or 0
    tx_count = info.get("n_tx", 0) or 0

    transactions = []
    for tx in (info.get("txrefs") or [])[:25]:
        value_wei = tx.get("value", 0) or 0
        # tx_output_n >= 0 means this is an output (received); tx_input_n >= 0 means input (sent)
        is_received = (tx.get("tx_output_n") or -1) >= 0
        block_time_ms = None
        confirmed_str = tx.get("confirmed") or ""
        if confirmed_str:
            try:
                dt = datetime.strptime(confirmed_str[:19], "%Y-%m-%dT%H:%M:%S")
                block_time_ms = int(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)
            except Exception:
                pass

        transactions.append({
            "hash": tx.get("tx_hash", ""),
            "time": block_time_ms,
            "value_eth": round(value_wei / 1e18, 6),
            "is_received": is_received,
        })

    return {
        "chain": "ETH",
        "address": address,
        "balance_wei": balance_wei,
        "balance_eth": round(balance_wei / 1e18, 6),
        "tx_count": tx_count,
        "transactions": transactions,
    }


async def lookup_trc20(address: str) -> dict:
    acc_url = f"{TRONGRID_BASE}/v1/accounts/{address}"
    tx_url = f"{TRONGRID_BASE}/v1/accounts/{address}/transactions/trc20"

    for url in (acc_url, tx_url):
        ok, reason = validate_url(url)
        if not ok:
            raise HTTPException(status_code=400, detail=f"Invalid URL: {reason}")

    try:
        async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
            acc_r = await client.get(acc_url, headers={"User-Agent": "FalconEye/3.0"})
            tx_r = await client.get(
                tx_url,
                params={
                    "limit": 50,
                    "contract_address": USDT_TRC20_CONTRACT,
                    "only_confirmed": "true",
                },
                headers={"User-Agent": "FalconEye/3.0"},
            )
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"TronGrid fetch failed: {str(e)}")

    acc_data = acc_r.json() if acc_r.status_code == 200 else {}
    tx_data = tx_r.json() if tx_r.status_code == 200 else {}

    usdt_balance = 0.0
    account_list = acc_data.get("data", [])
    if account_list:
        for token in account_list[0].get("trc20", []):
            if USDT_TRC20_CONTRACT in token:
                usdt_balance = int(token[USDT_TRC20_CONTRACT]) / 1e6
                break

    transactions = []
    for tx in tx_data.get("data", [])[:50]:
        token_info = tx.get("token_info", {})
        if token_info.get("address") != USDT_TRC20_CONTRACT:
            continue
        amount = int(tx.get("value", 0)) / (10 ** token_info.get("decimals", 6))
        transactions.append({
            "hash": tx.get("transaction_id"),
            "time": tx.get("block_timestamp"),
            "amount_usdt": round(amount, 2),
            "from": tx.get("from"),
            "to": tx.get("to"),
            "is_received": tx.get("to", "").lower() == address.lower(),
        })

    return {
        "chain": "USDT-TRC20",
        "address": address,
        "usdt_balance": usdt_balance,
        "tx_count": len(transactions),
        "transactions": transactions,
    }
