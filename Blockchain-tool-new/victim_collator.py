"""
====================================================================
 VICTIM COLLATOR - "Who Sent Money To This Wallet" Checker
 (Ethereum + Bitcoin)
====================================================================

WHAT THIS SCRIPT DOES (plain English):
You give this script a suspected hacker/scam wallet address - either
an ETHEREUM address (starts with 0x) or a BITCOIN address (starts
with 1, 3, or bc1). The script automatically detects which chain
the address belongs to and looks at every incoming payment that
wallet has ever received, building a list of every UNIQUE address
that sent it money. Each unique sending address is treated as one
"potential victim."

For ETHEREUM addresses it checks both plain ETH transfers AND
common token transfers (like USDT/USDC), via Etherscan.

For BITCOIN addresses it checks incoming payments via mempool.space
(a free, open-source Bitcoin block explorer - no API key needed),
and attributes each payment to the address(es) that funded the
paying transaction's inputs. NOTE: Bitcoin transactions can combine
multiple people's coins into one input set (this is normal wallet
behaviour, e.g. exchange withdrawals or coin consolidation), so
where a transaction has more than one input address, this script
lists ALL of them as possible senders for that payment rather than
guessing which one is "the real" sender. Treat multi-input
attributions as leads to verify, not confirmed identities.

It then prints a report showing:
    - Total number of potential victims (unique senders/inputs)
    - Total value received (in ETH or BTC as appropriate)
    - For Ethereum: total token transfers received (by token type)
    - A highly visible alert if victims are found

HOW TO RUN THIS SCRIPT (step-by-step, no coding knowledge needed):

STEP 1 - Install Python (if you don't already have it):
    Download from https://www.python.org/downloads/
    (During install, tick the box "Add Python to PATH")

STEP 2 - Install the one required library.
    Open your terminal (Command Prompt / Terminal app) and type:

        pip install requests

STEP 3 - Get a free Etherscan API key (only needed for ETH wallets).
    Etherscan is the standard public website/database used to look
    up Ethereum blockchain activity. Anyone can request a free key:
        1. Go to https://etherscan.io/register
        2. Create a free account
        3. Go to https://etherscan.io/myapikey
        4. Click "Add" to generate a key, then copy it

    NOTE: Bitcoin wallets do NOT need an API key. mempool.space's
    public API is free and open, no registration required.

STEP 4 - Paste your Etherscan API key into this script (skip this
    step if you're only investigating Bitcoin wallets).
    Scroll down to the line that says:
        ETHERSCAN_API_KEY = "PASTE_YOUR_API_KEY_HERE"
    and replace the text between the quotes with your real key.

STEP 5 - Confirm/edit the target wallet.
    Scroll down to TARGET_WALLET below. It is already pre-filled
    with the wallet you gave me. Change it any time you need to
    run this analysis on a different address - the script will
    automatically work out whether it's an Ethereum or Bitcoin
    address and use the right method.

STEP 6 - Run it.
    In your terminal, navigate to the folder this file is saved in,
    then type:

        python victim_collator.py

    The script will fetch the wallet's history and print a report.
====================================================================
"""

import os
import sys
import requests
import time
from datetime import datetime, timezone


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# ====================================================================

# Reads from the ETHERSCAN_API_KEY environment variable first (this
# is what the dashboard sets), falling back to whatever is pasted
# here directly if you're running this script on its own.
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ")

# --------------------------------------------------------------
# "technical" (default) prints the full report with raw sender
# addresses. "simple" prints a jury/solicitor-friendly version:
# senders get consistent plain-English labels ("Sender A", "Sender
# B", ... - or their real name if they're a known exchange/mixer),
# plus a legend at the end mapping each label back to its real
# address. Set via the OUTPUT_STYLE environment variable, or
# threat_intel_dashboard.py's view toggle sets this automatically.
# --------------------------------------------------------------
OUTPUT_STYLE = os.environ.get("OUTPUT_STYLE", "technical").strip().lower()
if OUTPUT_STYLE not in ("technical", "simple"):
    OUTPUT_STYLE = "technical"

try:
    import link_tracer as _lt  # reuse its known_entities.json lookup, not reimplement it

    def _check_known_entity(address):
        return _lt.check_known_entity(address)

    _VISUAL_OUTPUT_DIR = _lt.CLEAN_OUTPUT_DIR
except ImportError:
    def _check_known_entity(address):
        return None

    _VISUAL_OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "trace_reports")

# --------------------------------------------------------------
# EXAMPLE target only - REPLACE with your real flagged wallet, or
# just pass one on the command line instead of editing this file:
#     python victim_collator.py rDx1SUvXQdE3D6vP...
# A wallet passed on the command line overrides this value for that
# run. Works for Ethereum (0x...), Bitcoin (1..., 3..., bc1...), and
# XRP (r...) addresses - the chain is auto-detected either way.
# --------------------------------------------------------------
TARGET_WALLET = "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh"  # EXAMPLE XRP address

# Public XRP Ledger node used for XRP lookups. No API key needed.
XRPL_RPC_URL = "https://s1.ripple.com:51234"

# TRON / USDT-TRC20 - covers USDT specifically via TronGrid. Free,
# no key needed for light use.
TRONGRID_BASE_URL = "https://api.trongrid.io"
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # official Tether contract
TRON_API_KEY = os.environ.get("TRON_API_KEY", "")
TRON_MAX_PAGES = 4  # how many ~50-tx pages of USDT history to fetch per wallet


def get_target_wallet_from_cli_or_default():
    """
    PLAIN ENGLISH: If a wallet was passed in on the command line, use
    that instead of TARGET_WALLET above. This is what lets the
    dashboard (or any other tool) run this script against an address
    typed in on the fly, without editing the file.
    """
    cli_args = sys.argv[1:]
    if cli_args and cli_args[0].strip():
        return cli_args[0].strip()
    return TARGET_WALLET


SECONDS_BETWEEN_REQUESTS = 0.25

# BITCOIN ONLY: how many ~25-75 tx pages of mempool.space history to
# fetch per wallet. Increase for busy/high-traffic addresses.
BITCOIN_MAX_PAGES = 4

# XRP ONLY: how many ~20-tx pages of XRPL history to fetch per
# wallet. Increase for busy/high-traffic addresses.
XRP_MAX_PAGES = 4


# ====================================================================
# SECTION 2: ADDRESS DETECTION AND VALIDATION
# ====================================================================

def is_valid_ethereum_address(address):
    if not address.startswith("0x"):
        return False
    if len(address) != 42:
        return False
    hex_part = address[2:]
    allowed_characters = "0123456789abcdefABCDEF"
    for character in hex_part:
        if character not in allowed_characters:
            return False
    return True


def is_valid_bitcoin_address(address):
    """
    Basic sanity check only (not full checksum validation):
      - Legacy (P2PKH):  starts with "1"
      - Script (P2SH):   starts with "3"
      - SegWit/Taproot:  starts with "bc1"
    """
    if address.startswith("bc1"):
        return 14 <= len(address) <= 74
    if address.startswith("1") or address.startswith("3"):
        allowed_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if not (25 <= len(address) <= 35):
            return False
        return all(character in allowed_characters for character in address)
    return False


def is_valid_xrp_address(address):
    """
    Basic sanity check only (not full checksum validation): starts
    with "r" and is base58-encoded, 25-35 characters long. Covers
    the common classic "r..." form, not X-addresses.
    """
    if not address.startswith("r"):
        return False
    if not (25 <= len(address) <= 35):
        return False
    allowed_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(character in allowed_characters for character in address)


def is_valid_tron_address(address):
    """Basic sanity check only: starts with 'T' and is 34 characters, base58 charset."""
    if not address.startswith("T") or len(address) != 34:
        return False
    allowed_characters = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(character in allowed_characters for character in address)


def detect_chain(address):
    if is_valid_ethereum_address(address):
        return "ethereum"
    if is_valid_bitcoin_address(address):
        return "bitcoin"
    if is_valid_xrp_address(address):
        return "xrp"
    if is_valid_tron_address(address):
        return "tron"
    return None


# ====================================================================
# SECTION 3: ETHEREUM LOGIC (via Etherscan)
# ====================================================================

def get_normal_transactions(wallet_address, api_key):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": 1,
        "module": "account",
        "action": "txlist",
        "address": wallet_address,
        "sort": "asc",
        "apikey": api_key,
    }
    response = requests.get(url, params=params, timeout=15)
    data = response.json()
    if data.get("status") == "1":
        return data.get("result", [])
    elif data.get("message") != "No transactions found":
        print(f"  [!] Etherscan error: {data.get('message')} - {data.get('result')}")
    return []


def get_token_transfers(wallet_address, api_key):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": 1,
        "module": "account",
        "action": "tokentx",
        "address": wallet_address,
        "sort": "asc",
        "apikey": api_key,
    }
    response = requests.get(url, params=params, timeout=15)
    data = response.json()
    if data.get("status") == "1":
        return data.get("result", [])
    elif data.get("message") != "No transactions found":
        print(f"  [!] Etherscan error: {data.get('message')} - {data.get('result')}")
    return []


def collate_incoming_senders_ethereum(transactions, wallet_address):
    senders = {}
    total_received = 0
    for tx in transactions:
        if tx.get("to", "").lower() == wallet_address.lower():
            sender_address = tx.get("from", "").lower()
            decimals = int(tx.get("tokenDecimal", 18)) if tx.get("tokenDecimal") else 18
            raw_value = int(tx.get("value", 0))
            human_value = raw_value / (10 ** decimals)
            senders[sender_address] = senders.get(sender_address, 0) + human_value
            total_received += human_value
    return senders, total_received


def run_ethereum_collation(wallet_address):
    try:
        print("\nFetching normal ETH transaction history...")
        normal_txs = get_normal_transactions(wallet_address, ETHERSCAN_API_KEY)
        time.sleep(SECONDS_BETWEEN_REQUESTS)
    except requests.exceptions.RequestException as error:
        print(f"[!] Could not fetch ETH transaction history: {error}")
        normal_txs = []

    try:
        print("Fetching token transfer history...")
        token_txs = get_token_transfers(wallet_address, ETHERSCAN_API_KEY)
        time.sleep(SECONDS_BETWEEN_REQUESTS)
    except requests.exceptions.RequestException as error:
        print(f"[!] Could not fetch token transfer history: {error}")
        token_txs = []

    eth_senders, eth_total = collate_incoming_senders_ethereum(normal_txs, wallet_address)

    tokens_by_symbol = {}
    for tx in token_txs:
        symbol = tx.get("tokenSymbol", "UNKNOWN")
        tokens_by_symbol.setdefault(symbol, []).append(tx)

    token_transfer_report = {}
    for symbol, tx_list in tokens_by_symbol.items():
        senders_for_this_token, _ = collate_incoming_senders_ethereum(tx_list, wallet_address)
        if senders_for_this_token:
            token_transfer_report[symbol] = senders_for_this_token

    print_victim_report(
        chain="ethereum",
        wallet_address=wallet_address,
        senders=eth_senders,
        total_received=eth_total,
        currency_label="ETH",
        token_transfers=token_transfer_report,
    )


# ====================================================================
# SECTION 4: BITCOIN LOGIC (via mempool.space)
# ====================================================================

def get_bitcoin_transactions(address, max_pages):
    """
    Fetches address history from mempool.space's free public API.
    First page includes pending mempool tx + first batch of confirmed
    tx; subsequent pages are fetched via the last seen txid until we
    run out of history or hit max_pages.
    """
    all_transactions = []

    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        page = response.json()
    except requests.exceptions.RequestException as error:
        print(f"  [!] Could not reach mempool.space: {error}")
        return all_transactions
    except ValueError:
        print("  [!] mempool.space returned an unexpected response "
              "(the address may not exist or may be malformed).")
        return all_transactions

    all_transactions.extend(page)

    pages_fetched = 1
    while page and pages_fetched < max_pages:
        last_txid = page[-1].get("txid")
        if not last_txid:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)
        next_url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
        try:
            response = requests.get(next_url, timeout=15)
            response.raise_for_status()
            page = response.json()
        except requests.exceptions.RequestException as error:
            print(f"  [!] Could not fetch further history: {error}")
            break
        if not page:
            break
        all_transactions.extend(page)
        pages_fetched += 1

    return all_transactions


def collate_incoming_senders_bitcoin(transactions, address):
    """
    Attributes each incoming payment to every input (funding) address
    on that transaction - the "common input ownership" heuristic.
    Multi-input transactions list all input addresses as candidate
    senders rather than guessing a single one.
    """
    senders = {}
    total_received_btc = 0.0

    for tx in transactions:
        vout = tx.get("vout", [])
        received_satoshis = sum(
            output.get("value", 0)
            for output in vout
            if output.get("scriptpubkey_address", "").lower() == address.lower()
        )
        if received_satoshis <= 0:
            continue

        received_btc = received_satoshis / 100_000_000
        total_received_btc += received_btc

        input_addresses = set()
        for tx_input in tx.get("vin", []):
            prevout = tx_input.get("prevout") or {}
            input_address = prevout.get("scriptpubkey_address")
            if input_address:
                input_addresses.add(input_address.lower())

        if not input_addresses:
            input_addresses = {"(unresolvable input - coinbase or non-standard)"}

        for sender_address in input_addresses:
            senders[sender_address] = senders.get(sender_address, 0) + received_btc

    return senders, total_received_btc


def run_bitcoin_collation(address):
    print("\nFetching Bitcoin transaction history from mempool.space...")
    try:
        transactions = get_bitcoin_transactions(address, BITCOIN_MAX_PAGES)
    except requests.exceptions.RequestException as error:
        print(f"[!] Could not fetch Bitcoin transaction history: {error}")
        transactions = []

    print(f"  Retrieved {len(transactions)} transaction(s) "
          f"(up to {BITCOIN_MAX_PAGES} page(s) of history).")

    senders, total_received = collate_incoming_senders_bitcoin(transactions, address)

    print_victim_report(
        chain="bitcoin",
        wallet_address=address,
        senders=senders,
        total_received=total_received,
        currency_label="BTC",
        token_transfers={},
    )


# ====================================================================
# SECTION 4B: XRP LEDGER LOGIC (via Ripple's public XRPL node)
# ====================================================================

def get_xrp_transactions(address, max_pages):
    """
    Fetches validated transaction history for an XRP address from a
    public XRPL node, paginating via the "marker" the node returns
    until we run out of history or hit max_pages. No API key needed.
    """
    all_transactions = []
    marker = None
    pages_fetched = 0

    while pages_fetched < max_pages:
        params = {
            "account": address,
            "ledger_index_min": -1,
            "ledger_index_max": -1,
            "limit": 50,
            "forward": False,
        }
        if marker:
            params["marker"] = marker

        try:
            response = requests.post(
                XRPL_RPC_URL, json={"method": "account_tx", "params": [params]}, timeout=15
            )
            data = response.json()
        except requests.exceptions.RequestException as error:
            print(f"  [!] Could not reach the XRP Ledger node: {error}")
            break
        except ValueError:
            print("  [!] XRP Ledger node returned an unexpected response.")
            break

        result = data.get("result", {})
        if result.get("status") != "success":
            error_message = result.get("error_message") or result.get("error") or "unknown error"
            print(f"  [!] XRP Ledger error: {error_message}")
            break

        all_transactions.extend(result.get("transactions", []))
        pages_fetched += 1

        marker = result.get("marker")
        if not marker:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    return all_transactions


def collate_incoming_senders_xrp(transactions, address):
    """
    Attributes each validated incoming Payment to its sender (the
    "Account" field). Unlike Bitcoin, XRP Payments have exactly one
    sender per transaction, so there's no multi-input ambiguity to
    flag here. Only native XRP amounts are totalled; issued-currency
    (token) payments are counted as senders but not summed into the
    XRP total, since that needs the token's own decimals.
    """
    senders = {}
    total_received_xrp = 0.0

    for tx_entry in transactions:
        if not tx_entry.get("validated", False):
            continue

        tx = tx_entry.get("tx", {})
        meta = tx_entry.get("meta", {})

        if tx.get("TransactionType") != "Payment":
            continue
        if tx.get("Destination", "").lower() != address.lower():
            continue
        # meta.TransactionResult == "tesSUCCESS" confirms the payment
        # actually completed rather than merely being submitted.
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue

        sender_address = tx.get("Account", "").lower()
        if not sender_address:
            continue

        delivered = meta.get("delivered_amount", tx.get("Amount"))
        if isinstance(delivered, str):
            received_xrp = int(delivered) / 1_000_000
            total_received_xrp += received_xrp
            senders[sender_address] = senders.get(sender_address, 0) + received_xrp
        else:
            # Issued-currency (token) payment - still a lead worth
            # recording as a sender, just not added to the XRP total.
            senders.setdefault(sender_address, 0)

    return senders, total_received_xrp


def run_xrp_collation(address):
    print("\nFetching XRP transaction history from the XRP Ledger...")
    transactions = get_xrp_transactions(address, XRP_MAX_PAGES)

    print(f"  Retrieved {len(transactions)} transaction(s) "
          f"(up to {XRP_MAX_PAGES} page(s) of history).")

    senders, total_received = collate_incoming_senders_xrp(transactions, address)

    print_victim_report(
        chain="xrp",
        wallet_address=address,
        senders=senders,
        total_received=total_received,
        currency_label="XRP",
        token_transfers={},
    )


def get_tron_transactions(address, max_pages):
    """Fetches this address's USDT (TRC-20) transfer history from
    TronGrid, paginating via the 'fingerprint' cursor TronGrid returns."""
    all_transactions = []
    fingerprint = None
    pages_fetched = 0

    while pages_fetched < max_pages:
        url = f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20"
        params = {"contract_address": USDT_TRC20_CONTRACT, "limit": 50, "only_confirmed": "true"}
        if fingerprint:
            params["fingerprint"] = fingerprint
        headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}

        try:
            response = requests.get(url, params=params, headers=headers, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"  [!] Could not reach TronGrid: {error}")
            break

        if data.get("success") is False:
            print(f"  [!] TronGrid error: {data.get('error', 'unknown error')}")
            break

        page = data.get("data", [])
        all_transactions.extend(page)
        pages_fetched += 1

        fingerprint = (data.get("meta") or {}).get("fingerprint")
        if not fingerprint or not page:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    return all_transactions


def collate_incoming_senders_tron(transactions, address):
    """Attributes each incoming USDT transfer to its sender. TRC-20
    transfers, like XRP payments, have exactly one sender each - no
    multi-input ambiguity to flag."""
    senders = {}
    total_received_usdt = 0.0

    for tx in transactions:
        if tx.get("to", "").lower() != address.lower():
            continue
        sender_address = tx.get("from", "").lower()
        if not sender_address:
            continue

        decimals = (tx.get("token_info") or {}).get("decimals", 6)
        try:
            amount = int(tx.get("value", 0)) / (10 ** decimals)
        except (TypeError, ValueError):
            amount = 0.0

        total_received_usdt += amount
        senders[sender_address] = senders.get(sender_address, 0) + amount

    return senders, total_received_usdt


def run_tron_collation(address):
    print("\nFetching USDT (TRC-20) transaction history from TronGrid...")
    transactions = get_tron_transactions(address, TRON_MAX_PAGES)

    print(f"  Retrieved {len(transactions)} transaction(s) "
          f"(up to {TRON_MAX_PAGES} page(s) of history).")

    senders, total_received = collate_incoming_senders_tron(transactions, address)

    print_victim_report(
        chain="tron",
        wallet_address=address,
        senders=senders,
        total_received=total_received,
        currency_label="USDT",
        token_transfers={},
    )


# ====================================================================
# SECTION 5: SHARED REPORTING
# ====================================================================

def _build_sender_aliases(sorted_senders):
    """Rank-ordered aliases for Simple View: known entities get their real
    name, everyone else gets 'Sender A', 'Sender B', ... in rank order
    (largest amount sent first)."""
    aliases = {}
    next_letter_index = 0
    for sender_address, _amount in sorted_senders:
        entity = _check_known_entity(sender_address)
        if entity:
            aliases[sender_address] = f"{entity['name']} ({entity['type']})"
        else:
            letters = ""
            index = next_letter_index + 1
            while index > 0:
                index, remainder = divmod(index - 1, 26)
                letters = chr(65 + remainder) + letters
            aliases[sender_address] = f"Sender {letters}"
            next_letter_index += 1
    return aliases


_DIAGRAM_CSS = """
  body { font-family: -apple-system, "Segoe UI", Arial, sans-serif; background:#f4f5f7; color:#1e1e2e; margin:0; padding:32px; }
  h1 { font-size:20px; margin-bottom:4px; }
  .subtitle { color:#6b7280; font-size:13px; margin-bottom:28px; }
  .hub-wrap { display:flex; flex-direction:column; align-items:center; gap:14px; margin:28px 0; }
  .hub-box { background:#eef2ff; border:2px solid #4338ca; border-radius:10px; padding:14px 20px;
             font-size:14px; font-weight:700; text-align:center; box-shadow:0 1px 2px rgba(0,0,0,.08); }
  .spoke-row { display:flex; align-items:center; gap:14px; }
  .spoke-arrow { font-size:20px; color:#9ca3af; transform:rotate(90deg); }
  .senders-grid { display:flex; flex-wrap:wrap; gap:14px; justify-content:center; max-width:900px; }
  .sender-box { background:#fff; border:2px solid #93c5fd; border-radius:10px; padding:10px 14px;
                font-size:13px; font-weight:600; text-align:center; min-width:120px; box-shadow:0 1px 2px rgba(0,0,0,.08); }
  .entity-box { border-color:#0891b2; background:#ecfeff; }
  .sender-amount { font-size:11px; color:#374151; font-weight:400; margin-top:4px; }
  table.legend { border-collapse:collapse; margin-top:10px; font-size:12px; }
  table.legend td { padding:4px 10px; border-bottom:1px solid #e5e7eb; }
  .legend-label { font-weight:600; }
  .legend-address { font-family:monospace; color:#4b5563; }
  .footer-note { margin-top:26px; font-size:12px; color:#6b7280; }
  @media print { body { background:#fff; } }
"""


def _escape_html(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def write_victim_visual_html(wallet_address, sorted_senders, aliases, currency_label):
    """
    PLAIN ENGLISH: Writes a self-contained HTML page showing every
    sender flowing INTO the wallet under investigation as a hub
    diagram - each sender box labeled with the amount it sent - built
    for showing to a solicitor, victim, or jury. Uses the SAME
    aliases already built for the Simple View text report. Open the
    file in any browser; it's plain HTML so it prints cleanly too.

    Returns the saved file path, or None if there were no senders.
    """
    if not sorted_senders:
        return None

    os.makedirs(_VISUAL_OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_wallet = "".join(c for c in wallet_address if c.isalnum())[:20]
    html_path = os.path.join(_VISUAL_OUTPUT_DIR, f"victim_diagram_{safe_wallet}_{timestamp}.html")

    sender_boxes = []
    for sender_address, amount in sorted_senders[:10]:
        label = aliases.get(sender_address, sender_address)
        box_class = "entity-box" if _check_known_entity(sender_address) else "sender-box"
        sender_boxes.append(
            f'<div class="sender-box {box_class}">{_escape_html(label)}'
            f'<div class="sender-amount">{amount:.4f} {_escape_html(currency_label)}</div></div>'
        )

    legend_rows = "".join(
        f'<tr><td class="legend-label">{_escape_html(label_text)}</td>'
        f'<td class="legend-address">{_escape_html(address)}</td></tr>'
        for address, label_text in aliases.items()
    )

    extra_note = ""
    if len(sorted_senders) > 10:
        extra_note = (f'<div class="footer-note">+{len(sorted_senders) - 10} more sender(s) not shown here - '
                       f'see Technical View for the complete list.</div>')

    html_document = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Victim Collation Diagram - {_escape_html(wallet_address)}</title>
<style>{_DIAGRAM_CSS}</style></head>
<body>
  <h1>Victim Collation Diagram</h1>
  <div class="subtitle">Wallet under investigation: {_escape_html(wallet_address)}</div>
  <div class="senders-grid">{"".join(sender_boxes)}</div>
  <div class="hub-wrap">
    <div class="spoke-arrow">&#8593;</div>
    <div class="hub-box">Wallet Under Investigation</div>
  </div>
  {extra_note}
  <h2>Key</h2>
  <table class="legend">{legend_rows}</table>
  <div class="footer-note">Full technical detail (exact addresses, totals) is available in Technical View.</div>
</body></html>"""

    with open(html_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(html_document)

    return html_path


def print_victim_report(chain, wallet_address, senders, total_received,
                         currency_label, token_transfers):
    all_victim_addresses = set(senders.keys())
    for token_symbol, senders_dict in token_transfers.items():
        all_victim_addresses.update(senders_dict.keys())

    victim_count = len(all_victim_addresses)

    if chain == "ethereum":
        explorer_url = f"https://etherscan.io/address/{wallet_address}"
    elif chain == "bitcoin":
        explorer_url = f"https://mempool.space/address/{wallet_address}"
    elif chain == "tron":
        explorer_url = f"https://tronscan.org/#/address/{wallet_address}"
    else:
        explorer_url = f"https://livenet.xrpl.org/accounts/{wallet_address}"

    sorted_senders = sorted(senders.items(), key=lambda item: item[1], reverse=True)

    if OUTPUT_STYLE == "simple":
        print("\n" + "=" * 60)
        print("VICTIM COLLATION SUMMARY")
        print("=" * 60)
        print(f"Wallet under investigation: {wallet_address}")

        if victim_count > 0:
            print(f"\n⚠️  This wallet received {currency_label} from {victim_count} "
                  f"different source(s), totalling {total_received:.4f} {currency_label}.")

            if chain == "bitcoin":
                print("  Note: for Bitcoin, a payment can have more than one input address -")
                print("  when that happens, every one of them is listed as a possible sender.")
                print("  Treat these as leads to verify, not confirmed identities.")

            aliases = _build_sender_aliases(sorted_senders)
            print(f"\n  Senders, largest amount first (top {min(10, len(sorted_senders))} shown):")
            for rank, (sender_address, amount) in enumerate(sorted_senders[:10], start=1):
                print(f"    {rank}. {aliases[sender_address]} — {amount:.4f} {currency_label}")

            if token_transfers:
                print("\n  Other token activity was also found - see Technical View for detail.")

            print("\n" + "=" * 78)
            print("KEY - what each label above stands for")
            print("=" * 78)
            print("  (Full addresses are listed here so this summary can still be")
            print("   independently verified.)\n")
            for sender_address, label in aliases.items():
                print(f"  {label:<30} {sender_address}")

            diagram_path = write_victim_visual_html(wallet_address, sorted_senders, aliases, currency_label)
            if diagram_path:
                print(f"\n📊 Visual diagram saved (open in any browser): {diagram_path}")
        else:
            print("\n✅ No incoming transactions found - no senders identified.")

        print("\n" + "=" * 60)
        print(f"Total potential victims/senders identified: {victim_count}")
        print("=" * 60)
        return

    # ---- Technical View (unchanged) ----
    print("\n" + "=" * 60)
    print(f"VICTIM COLLATION REPORT ({chain.upper()})")
    print("=" * 60)
    print(f"Target wallet: {wallet_address}")
    print(f"View on block explorer: {explorer_url}")
    print("-" * 60)

    if victim_count > 0:
        print("\n" + "!" * 20)
        print("  ALERT: POTENTIAL VICTIMS IDENTIFIED  ")
        print("!" * 20)
        print(f"  Unique sending addresses (potential victims): {victim_count}")
        print(f"  Total {currency_label} received directly          : {total_received:.8f} {currency_label}")

        if chain == "bitcoin":
            print("  NOTE: Bitcoin senders are attributed using the common-input-")
            print("  ownership heuristic. Where a payment's transaction has more")
            print("  than one input address, ALL of them are listed as possible")
            print("  senders - treat these as leads to verify, not confirmed IDs.")

        if token_transfers:
            print("  Token activity breakdown:")
            for token_symbol, senders_dict in token_transfers.items():
                token_total = sum(senders_dict.values())
                print(f"    - {token_symbol}: {len(senders_dict)} unique senders, "
                      f"{token_total:,.4f} total received")
        print("!" * 20)

        print(f"\n  Top senders by {currency_label} value sent (up to 10 shown):")
        for sender_address, amount in sorted_senders[:10]:
            print(f"    {sender_address}  ->  {amount:.8f} {currency_label}")
    else:
        print("\n[OK] No incoming transactions found. No victims identified.")

    print("\n" + "=" * 60)
    print("REPORT COMPLETE")
    print(f"Total potential victims identified: {victim_count}")
    print("=" * 60)


# ====================================================================
# SECTION 6: SCRIPT ENTRY POINT / DISPATCH
# ====================================================================

def run_victim_collation(target_wallet):
    print("=" * 60)
    print("Starting victim collation analysis")
    print(f"Target wallet: {target_wallet}")
    print("=" * 60)

    chain = detect_chain(target_wallet)

    if chain == "ethereum":
        print("Detected chain: Ethereum")
        run_ethereum_collation(target_wallet)
    elif chain == "bitcoin":
        print("Detected chain: Bitcoin")
        run_bitcoin_collation(target_wallet)
    elif chain == "xrp":
        print("Detected chain: XRP")
        run_xrp_collation(target_wallet)
    elif chain == "tron":
        print("Detected chain: Tron (USDT)")
        run_tron_collation(target_wallet)
    else:
        print("[!] That address does not look like a valid Ethereum address")
        print("    (0x... , 42 characters), Bitcoin address (1..., 3..., or")
        print("    bc1...), XRP address (r..., 25-35 characters), or Tron")
        print("    address (T..., 34 characters). Please double check it and try again.")


if __name__ == "__main__":
    active_target_wallet = get_target_wallet_from_cli_or_default()

    if is_valid_ethereum_address(active_target_wallet) and ETHERSCAN_API_KEY == "":
        print("[!] Please add your Etherscan API key before running this script")
        print("    on an Ethereum wallet. See STEP 3 in the instructions above.")
        print("    (Bitcoin and XRP wallets don't need an API key.)")
    else:
        run_victim_collation(active_target_wallet)