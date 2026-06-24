import httpx
from fastapi import APIRouter, HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

router = APIRouter(prefix="/api/crypto", tags=["crypto"])
limiter = Limiter(key_func=get_remote_address)

BLOCKCHAIR_BASE = "https://api.blockchair.com"
TRONGRID_BASE = "https://api.trongrid.io"
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"

KNOWN_EXCHANGES = {
    "binance": ["binance", "bnb"],
    "coinbase": ["coinbase"],
    "kraken": ["kraken"],
    "okx": ["okx", "okex"],
    "bybit": ["bybit"],
    "huobi": ["huobi", "htx"],
    "kucoin": ["kucoin"],
    "bitfinex": ["bitfinex"],
    "gate": ["gate.io", "gateio"],
}


def detect_exchange(label: str) -> str | None:
    if not label:
        return None
    label_lower = label.lower()
    for exchange, keywords in KNOWN_EXCHANGES.items():
        if any(kw in label_lower for kw in keywords):
            return exchange
    return None


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
        raise HTTPException(status_code=400, detail="Unrecognized address format. Supported: BTC, ETH, USDT TRC20 (TRON).")

    if chain == "btc":
        return await lookup_btc(address)
    elif chain == "eth":
        return await lookup_eth(address)
    elif chain == "trc20":
        return await lookup_trc20(address)


async def lookup_btc(address: str) -> dict:
    url = f"{BLOCKCHAIR_BASE}/bitcoin/dashboards/address/{address}?transaction_details=true&limit=50"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers={"User-Agent": "FalconEye/3.0 (osintph.info)"})
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 402:
            raise HTTPException(status_code=429, detail="Blockchair daily limit reached. Try again tomorrow.")
        raise HTTPException(status_code=502, detail=f"Blockchair error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {str(e)}")

    addr_data = data.get("data", {}).get(address, {})
    if not addr_data:
        raise HTTPException(status_code=404, detail="Address not found on Bitcoin blockchain.")

    info = addr_data.get("address", {})
    txs_raw = addr_data.get("transactions", [])

    transactions = []
    for tx in txs_raw[:50]:
        transactions.append({
            "hash": tx.get("hash"),
            "time": tx.get("time"),
            "balance_change": tx.get("balance_change"),
            "is_received": (tx.get("balance_change", 0) or 0) > 0,
        })

    return {
        "chain": "BTC",
        "address": address,
        "balance_satoshi": info.get("balance", 0),
        "balance_btc": round((info.get("balance", 0) or 0) / 1e8, 8),
        "received_btc": round((info.get("received", 0) or 0) / 1e8, 8),
        "spent_btc": round((info.get("spent", 0) or 0) / 1e8, 8),
        "tx_count": info.get("transaction_count", 0),
        "first_seen": info.get("first_seen_receiving"),
        "last_seen": info.get("last_seen_receiving"),
        "transactions": transactions,
    }


async def lookup_eth(address: str) -> dict:
    url = f"{BLOCKCHAIR_BASE}/ethereum/dashboards/address/{address}?transaction_details=true&limit=50"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers={"User-Agent": "FalconEye/3.0 (osintph.info)"})
            r.raise_for_status()
            data = r.json()
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 402:
            raise HTTPException(status_code=429, detail="Blockchair daily limit reached. Try again tomorrow.")
        raise HTTPException(status_code=502, detail=f"Blockchair error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Upstream fetch failed: {str(e)}")

    addr_data = data.get("data", {}).get(address.lower(), {}) or data.get("data", {}).get(address, {})
    if not addr_data:
        raise HTTPException(status_code=404, detail="Address not found on Ethereum blockchain.")

    info = addr_data.get("address", {})
    txs_raw = addr_data.get("calls", []) or addr_data.get("transactions", [])

    transactions = []
    for tx in txs_raw[:50]:
        transactions.append({
            "hash": tx.get("transaction_hash") or tx.get("hash"),
            "time": tx.get("time"),
            "value_wei": tx.get("value", 0),
            "value_eth": round((tx.get("value", 0) or 0) / 1e18, 6),
            "is_received": (tx.get("recipient") or "").lower() == address.lower(),
            "sender": tx.get("sender"),
            "recipient": tx.get("recipient"),
        })

    return {
        "chain": "ETH",
        "address": address,
        "balance_wei": info.get("balance", 0),
        "balance_eth": round((info.get("balance", 0) or 0) / 1e18, 6),
        "tx_count": info.get("transaction_count", 0),
        "first_seen": info.get("first_seen_receiving"),
        "last_seen": info.get("last_seen_receiving"),
        "transactions": transactions,
    }


async def lookup_trc20(address: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            acc_r = await client.get(
                f"{TRONGRID_BASE}/v1/accounts/{address}",
                headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
            )
            tx_r = await client.get(
                f"{TRONGRID_BASE}/v1/accounts/{address}/transactions/trc20",
                params={
                    "limit": 50,
                    "contract_address": USDT_TRC20_CONTRACT,
                    "only_confirmed": "true",
                },
                headers={"User-Agent": "FalconEye/3.0 (osintph.info)"},
            )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"TronGrid fetch failed: {str(e)}")

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
