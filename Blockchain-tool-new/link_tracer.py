"""
====================================================================
 LINK TRACER - "Does This Victim's Money Lead To A Flagged Wallet?"
 (Ethereum + Bitcoin + XRP)
====================================================================

WHAT THIS SCRIPT DOES (plain English):
You give this script a wallet address and a direction.

FORWARD (default): give it a VICTIM'S wallet address and it follows
the money FORWARD from that address - who they sent funds to, then
who THOSE addresses sent funds to, and so on for a few "hops" - and
checks at every step whether it has reached one of your known
illicit/flagged wallets (the same TARGET_ILLICIT_WALLETS list below,
automatically combined with anything in the shared
case_watchlist.json file that crypto_address_watcher.py and
wallet_watcher.py also use).

BACKWARD: give it an ILLICIT/FLAGGED wallet address instead, and it
follows the money BACKWARD - who sent funds INTO that address, then
who sent funds into those addresses, and so on - to see where the
money actually originated. Optionally check whether the trail leads
back to a specific known source wallet (e.g. a particular victim),
or just leave the target blank to see every backward trail it can
follow up to the hop limit.

If it finds a path, it prints the full trail: every wallet, every
transaction hash, every hop, so you can verify each step yourself on
a block explorer.

====================================================================
 IMPORTANT LIMITATIONS - READ THIS BEFORE USING IN A CASE
====================================================================
1. SAME-CHAIN ONLY. This follows Ethereum wallets to Ethereum
   wallets, Bitcoin to Bitcoin, XRP to XRP. It does NOT follow funds
   across a bridge, swap, or cross-chain exchange - if a victim's
   ETH gets swapped for BTC partway through the trail, this script
   cannot see past that point on its own.

2. EXCHANGES AND MIXERS BREAK THE TRAIL. The moment funds land in a
   real exchange's hot wallet (or a mixing service), that exchange
   internally re-shuffles funds across thousands of unrelated users.
   This script has no way to see "through" an exchange to whichever
   of their customers eventually withdrew related funds - that needs
   a subpoena/production order to the exchange itself, not more
   on-chain tracing.

3. "NO LINK FOUND" IS NOT PROOF OF NO RELATIONSHIP. It only means no
   DIRECT on-chain path was found within the hop limit you set, on
   the same chain, using the counterparties this script happened to
   check. Increase MAX_HOPS, check the intermediate wallets it DID
   find by hand, and treat a negative result as inconclusive - not
   as evidence of innocence.

4. THIS IS A LEAD-GENERATION TOOL, NOT COURTROOM PROOF ON ITS OWN.
   Every hop in a path this script reports is independently
   verifiable on a public block explorer - always check the actual
   transactions before relying on a finding.
====================================================================

HOW TO RUN THIS SCRIPT (step-by-step, no coding knowledge needed):

STEP 1 - Install Python (if you don't already have it) and the one
    required library:
        pip install requests

STEP 2 - Get a free Etherscan API key if you'll be tracing Ethereum
    wallets (see wallet_watcher.py's instructions for the exact
    steps), and either paste it below or set it as the
    ETHERSCAN_API_KEY environment variable.

STEP 3 - Edit VICTIM_WALLET and TARGET_ILLICIT_WALLETS below, or
    just pass them on the command line instead:
        python link_tracer.py <wallet> [target_wallets] [direction] [starting_amount]
    - <wallet> is required.
    - [target_wallets] is optional, comma-separated. In "forward"
      direction these are illicit wallets to check for a link TO
      (combined with anything already in case_watchlist.json). In
      "backward" direction these are known SOURCE wallets to check
      the trail against (e.g. a specific victim) - leave blank/""
      to just see everywhere the backward trail leads.
    - [direction] is optional: "forward" (default), "backward", or
      "both". "forward" follows money FROM a victim wallet looking
      for a flagged wallet downstream. "backward" follows money
      INTO an illicit wallet looking for where it came from.
    - [starting_amount] is optional. If you know how much the victim
      actually sent (or how much moved through the illicit wallet),
      give it here (same units as the wallet's native currency, e.g.
      23080.283377) and hops that clearly aren't part of that amount
      get skipped - cuts out unrelated dust/other-customer activity
      at busy addresses. Leave blank to trace every hop regardless
      of size (see STARTING_TRACE_AMOUNT below to change the default).
    Examples:
        python link_tracer.py rVictim...                forward, uses TARGET_ILLICIT_WALLETS below
        python link_tracer.py rVictim... rIllicit1,rIllicit2
        python link_tracer.py rIllicit... "" backward     backward, no specific target
        python link_tracer.py rIllicit... rVictim... backward
        python link_tracer.py rWallet... "" both
        python link_tracer.py rVictim... "" forward 23080.283377   only follow ~23080-worth hops

STEP 4 - Run it:
        python link_tracer.py
====================================================================
"""

import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import os
import csv
import json
import time
import requests
from datetime import datetime, timezone


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# ====================================================================

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ")
XRPL_RPC_URL = "https://s1.ripple.com:51234"

# --------------------------------------------------------------
# TRON / USDT-TRC20. This covers USDT specifically (by far the
# dominant use of Tron for the kind of transfers this toolkit
# traces) via TronGrid, Tron's standard public API - free, no key
# needed for light/occasional use (an optional key raises the rate
# limit if you're doing heavy usage - see TRON_API_KEY below).
# Native TRX is NOT covered - only USDT-TRC20 token transfers.
# --------------------------------------------------------------
TRONGRID_BASE_URL = "https://api.trongrid.io"
USDT_TRC20_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"  # official Tether contract - verify at tether.to if in doubt
TRON_API_KEY = os.environ.get("TRON_API_KEY", "")  # optional - raises TronGrid's rate limit

# --------------------------------------------------------------
# "technical" (default) prints full detail: raw addresses, tx
# hashes, exact UTC timestamps - everything you need to verify each
# hop yourself. "simple" prints a jury/solicitor-friendly version
# instead: consistent plain-English wallet labels (a known exchange
# shows its real name; everything else becomes "Wallet A", "Wallet
# B", ...), plain language, and a legend at the end mapping every
# label back to its real address so the summary is still fully
# traceable. Set via the OUTPUT_STYLE environment variable, or
# threat_intel_dashboard.py's view toggle sets this automatically.
# --------------------------------------------------------------
OUTPUT_STYLE = os.environ.get("OUTPUT_STYLE", "technical").strip().lower()
if OUTPUT_STYLE not in ("technical", "simple"):
    OUTPUT_STYLE = "technical"

# --------------------------------------------------------------
# EXAMPLE ONLY - the wallet you're tracing FROM (the victim/source).
# Overridden by the first command-line argument if one is given.
# --------------------------------------------------------------
VICTIM_WALLET = "0x1f2f10d1c40777ae1da742455c65828ff36df387"

# --------------------------------------------------------------
# Which way to trace:
#   "forward"  - follow money FORWARD from a victim wallet, looking
#                for a path TO a flagged illicit wallet (original
#                behaviour).
#   "backward" - follow money BACKWARD from an illicit/flagged
#                wallet, looking for where it came FROM - optionally
#                checking whether it traces back to a specific known
#                source (e.g. a particular victim). If no target is
#                given, it just reports every backward trail it can
#                follow up to MAX_HOPS (dead ends, exchange deposit
#                addresses, etc. - all useful investigative leads).
#   "both"     - runs forward then backward in the same pass.
# Overridden by an optional third command-line argument.
# --------------------------------------------------------------
DIRECTION = "forward"

# --------------------------------------------------------------
# EXAMPLE ONLY - wallets you're checking for a link TO (the
# illicit/flagged side) when DIRECTION is "forward". Automatically
# combined with every address already in the shared
# case_watchlist.json file, so anything crypto_address_watcher.py
# has found is checked too. Overridden/extended by a second,
# comma-separated command-line argument.
#
# When DIRECTION is "backward", this same list/argument instead
# means "known source wallets to check the trail against" (e.g. a
# specific victim wallet) - the shared case watchlist is NOT auto-
# added here, since that list is illicit destinations, not sources.
# Leave empty for backward tracing to just see everywhere the trail
# leads within MAX_HOPS.
# --------------------------------------------------------------
TARGET_ILLICIT_WALLETS = [
    "r9R8jciZBYGq32DxxQrBPi5ysZm67iQitH"
]

# --------------------------------------------------------------
# How many hops forward to follow before giving up. Each extra hop
# multiplies the number of API calls needed (bounded by
# MAX_FANOUT_PER_HOP below), so keep this modest - 3 is a reasonable
# default. 4+ can take a long time and hit free-tier rate limits.
# --------------------------------------------------------------
MAX_HOPS = 4

# --------------------------------------------------------------
# At each wallet, only follow its MOST RECENT N outgoing
# counterparties, rather than every single one - this keeps a busy
# wallet (e.g. one that touched an exchange) from making the search
# explode combinatorially. Increase for more thoroughness, at the
# cost of speed.
# --------------------------------------------------------------
MAX_FANOUT_PER_HOP = 15

SECONDS_BETWEEN_REQUESTS = 0.3

# --------------------------------------------------------------
# Where case_watchlist.json, known_entities.json, and trace_reports/
# actually live. Defaults to the folder this script sits in - fine
# for local/desktop use. When deploying somewhere with an EPHEMERAL
# filesystem (e.g. Render without a Persistent Disk attached), local
# file writes get wiped on every restart/redeploy/spin-down - set
# TOOLKIT_DATA_DIR to a mounted persistent disk's path instead, so
# your actual case data survives:
#     TOOLKIT_DATA_DIR=/var/data
# (matching the mount path you configured for the disk).
# --------------------------------------------------------------
TOOLKIT_DATA_DIR = os.environ.get(
    "TOOLKIT_DATA_DIR", os.path.dirname(os.path.abspath(__file__))
)

CASE_WATCHLIST_FILE = os.path.join(TOOLKIT_DATA_DIR, "case_watchlist.json")

# --------------------------------------------------------------
# Where the clean, easy-to-read trace summaries (CSV + plain text)
# get written every time a run finds at least one path. Defaults to
# a "trace_reports" folder next to this script (or under
# TOOLKIT_DATA_DIR, if set).
# --------------------------------------------------------------
CLEAN_OUTPUT_DIR = os.path.join(TOOLKIT_DATA_DIR, "trace_reports")

# --------------------------------------------------------------
# KNOWN ENTITY LABELS (exchanges, mixers, other custodial services).
# When a trace reaches one of these addresses, the trail is reported
# as ending there WITH A REASON, instead of either silently stopping
# or (worse) trying to keep tracing into an exchange's internal,
# commingled customer funds - which no on-chain data can resolve.
#
# Populate KNOWN_ENTITIES_FILE (JSON, in TOOLKIT_DATA_DIR) as your
# team identifies real hot wallets/deposit addresses, e.g.:
#   [
#     {"address": "0xabc...", "name": "Example Exchange", "type": "exchange"},
#     {"address": "0xdef...", "name": "Example Mixer", "type": "mixer"}
#   ]
# There is no reliable universal public list of every exchange's hot
# wallets (they rotate, and custody structures vary) - this has to
# be maintained per-case from your own intel (Etherscan/Arkham/etc.
# labels, exchange disclosures, prior investigations). BUILT_IN_
# KNOWN_ENTITIES below is intentionally empty for the same reason -
# don't rely on a hardcoded list being current or complete.
# --------------------------------------------------------------
KNOWN_ENTITIES_FILE = os.path.join(TOOLKIT_DATA_DIR, "known_entities.json")
BUILT_IN_KNOWN_ENTITIES = []

# --------------------------------------------------------------
# DEPOSIT & CONSOLIDATION MAP - addresses CONFIRMED to be an
# exchange's deposit addresses, discovered by watching for a sweep/
# consolidation transaction into one of that exchange's known
# treasury wallets (see SECTION 3C below). Once an address is
# recorded here, EVERY future run recognizes it immediately via
# check_known_entity() - this is how the tool accumulates knowledge
# across cases instead of re-discovering the same thing every time.
# --------------------------------------------------------------
ENABLE_DEPOSIT_CONSOLIDATION_MAPPING = True
DEPOSIT_MAP_FILE = os.path.join(TOOLKIT_DATA_DIR, "deposit_address_map.json")

# --------------------------------------------------------------
# If a wallet has this many or more DISTINCT counterparties in its
# recent activity (the same page of transactions the trace already
# fetches - no extra API calls needed), it's treated as a likely
# custodial/exchange/mixer wallet even without a name label, and the
# trail is reported as ending there rather than fanning out into
# what's almost certainly an unrelated crowd of other customers.
# Lower = more cautious (flags smaller wallets too); higher = only
# flags very obviously busy wallets. 25 is a reasonable default.
# --------------------------------------------------------------
HIGH_FANOUT_THRESHOLD = 25

# --------------------------------------------------------------
# AMOUNT-BASED FILTERING (optional). If you know how much the victim
# actually sent (or how much the illicit wallet actually moved), give
# it here and the trace will ignore hops that clearly AREN'T part of
# that money - e.g. a wallet's own unrelated dust transactions, fee
# collections, or other customers' activity mixed into the same
# address's history. This is the same idea real chain-analysis tools
# use (often called "taint"/threshold tracing): the amount you're
# following is carried forward hop by hop, and only transactions
# whose amount is still in a plausible range of what's being tracked
# get followed further.
#
# Leave STARTING_TRACE_AMOUNT as None to disable this and trace every
# hop regardless of size (the original behaviour). Set it (or pass it
# as a 4th command-line argument) to turn filtering on.
# --------------------------------------------------------------
STARTING_TRACE_AMOUNT = None  # e.g. 23080.283377 - same units as the wallet's native currency

# A hop must carry at least this fraction of the amount currently
# being tracked to be considered "the same money" rather than noise.
# 0.10 = ignore anything under 10% of the tracked amount. Lower this
# if funds are being split into many small pieces you still want to
# follow; raise it to be stricter about what counts as related.
AMOUNT_MATCH_MIN_RATIO = 0.10

# A hop carrying meaningfully MORE than the tracked amount usually
# means unrelated funds got mixed in at that address (e.g. someone
# else's deposit) rather than a clean continuation of the same
# money. 1.05 allows a small buffer for rounding.
AMOUNT_MATCH_MAX_RATIO = 1.05

# --------------------------------------------------------------
# SWAP CORRELATION - for tracing THROUGH no-KYC instant swap
# services (e.g. changenow.io, swapuz.io, fixedfloat.com) that are
# NOT the same thing as a big pooled-liquidity exchange like Binance
# or Coinbase. These services generate a one-time deposit address
# per swap and typically pay out within minutes, at a near-equal USD
# value minus their fee - a genuinely useful (though still heuristic,
# not proof) correlation to search for.
#
# This ONLY runs for known_entities.json entries tagged
# "type": "instant_swap" - NOT for "exchange"/"mixer", where a
# pooled hot wallet handling thousands of unrelated transactions a
# minute would make timing/amount correlation meaningless noise.
# See known_entities.json for how to add a service's known wallets
# (add one entry per chain the service operates on, all sharing the
# same "name" - that's how its wallets get grouped together here).
# --------------------------------------------------------------
ENABLE_SWAP_CORRELATION = True

# How long after a deposit (or before a payout) to search for a
# plausible match. Instant swappers usually complete within minutes;
# 60 gives some buffer for a busier swap queue.
SWAP_CORRELATION_WINDOW_MINUTES = 60

# A payout is usually SLIGHTLY less than the deposit (their fee/
# spread) - rarely more. 0.85-1.05 allows for a ~15% fee/spread on
# the low end and a small buffer for price-data imprecision on the
# high end.
SWAP_CORRELATION_MIN_RATIO = 0.85
SWAP_CORRELATION_MAX_RATIO = 1.05

# Free, no-API-key historical price lookup, used to compare a
# deposit/payout pair across two DIFFERENT currencies in USD terms
# (e.g. a BTC deposit that came out as XRP). Only day-level price
# granularity is available for free, which is fine here since the
# ratio tolerance above already allows room for normal price
# movement within a day.
COINGECKO_COIN_ID_BY_CHAIN = {"ethereum": "ethereum", "bitcoin": "bitcoin", "xrp": "ripple"}

# Stablecoins are priced at $1 directly rather than looked up - this is
# what lets swap/bridge correlation work for a USDT leg (e.g. an ETH
# deposit into a bridge, paid out as USDT-TRC20 on Tron): Tron isn't a
# chain with a "native coin" price the way ETH/BTC/XRP are, and even if
# it were, USDT's peg is what matters here, not TRX's market price.
STABLECOIN_SYMBOLS = {"USDT", "USDC", "BUSD", "DAI", "TUSD", "USDP"}


def get_price_usd_for_amount(chain, symbol, when):
    """Returns the USD price to use for an amount: $1 for a known
    stablecoin symbol (regardless of chain), otherwise the chain's
    native coin's historical price via get_historical_price_usd."""
    if symbol and symbol.upper() in STABLECOIN_SYMBOLS:
        return 1.0
    return get_historical_price_usd(chain, when)


# ====================================================================
# SECTION 2: ADDRESS DETECTION (same rules as the other scripts)
# ====================================================================

def is_valid_ethereum_address(address):
    if not address.startswith("0x") or len(address) != 42:
        return False
    try:
        int(address[2:], 16)
        return True
    except ValueError:
        return False


def is_valid_bitcoin_address(address):
    if address.startswith("bc1"):
        return 14 <= len(address) <= 74
    if address.startswith("1") or address.startswith("3"):
        allowed = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if not (25 <= len(address) <= 35):
            return False
        return all(c in allowed for c in address)
    return False


def is_valid_xrp_address(address):
    if not address.startswith("r"):
        return False
    if not (25 <= len(address) <= 35):
        return False
    allowed = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(c in allowed for c in address)


def is_valid_tron_address(address):
    """Basic sanity check only (not full Base58Check validation):
    starts with 'T' and is 34 characters, base58 charset."""
    if not address.startswith("T") or len(address) != 34:
        return False
    allowed = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return all(character in allowed for character in address)


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
# SECTION 3: PER-CHAIN "WHO DID THIS ADDRESS SEND TO?" LOOKUPS
# Each returns (results, unique_counterparty_count):
#   results   - list of dicts {counterparty, tx_hash, tx_time, amount_label},
#               sorted newest-first, capped to MAX_FANOUT_PER_HOP.
#   unique_counterparty_count - how many DISTINCT counterparties showed
#               up across the whole fetched page (not just the capped
#               list) - a free-to-compute fan-out signal used to spot
#               likely exchange/custodial wallets. See HIGH_FANOUT_THRESHOLD.
# ====================================================================

def get_outgoing_ethereum(address):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": "1", "module": "account", "action": "txlist",
        "address": address, "sort": "desc", "apikey": ETHERSCAN_API_KEY,
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        print(f"    ⚠️  Could not reach Etherscan: {error}")
        return [], 0

    if data.get("status") != "1":
        if data.get("message") != "No transactions found":
            print(f"    ⚠️  Etherscan error: {data.get('message')}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in data.get("result", []):
        if tx.get("from", "").lower() != address.lower():
            continue
        to_address = tx.get("to", "")
        if not to_address:
            continue  # contract creation, no simple recipient
        unique_counterparties.add(to_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue
        eth_value = int(tx.get("value", 0)) / 1_000_000_000_000_000_000
        results.append({
            "counterparty": to_address,
            "tx_hash": tx.get("hash"),
            "tx_time": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc),
            "amount_label": f"{eth_value:.6f} ETH",
            "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
        })
    return results, len(unique_counterparties)


def get_outgoing_bitcoin(address):
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        transactions = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach mempool.space: {error}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in transactions:
        # Only interested in transactions where THIS address is
        # actually spending (an input), not just receiving change.
        is_spender = any(
            (tx_input.get("prevout") or {}).get("scriptpubkey_address", "").lower() == address.lower()
            for tx_input in tx.get("vin", [])
        )
        if not is_spender:
            continue

        status = tx.get("status", {})
        if status.get("confirmed", False):
            block_time = status.get("block_time")
            tx_time = datetime.fromtimestamp(block_time, tz=timezone.utc) if block_time else datetime.now(timezone.utc)
        else:
            tx_time = datetime.now(timezone.utc)

        for output in tx.get("vout", []):
            recipient = output.get("scriptpubkey_address")
            # Skip change back to the same address - not a new hop.
            if not recipient or recipient.lower() == address.lower():
                continue
            unique_counterparties.add(recipient.lower())
            if len(results) < MAX_FANOUT_PER_HOP:
                results.append({
                    "counterparty": recipient,
                    "tx_hash": tx.get("txid"),
                    "tx_time": tx_time,
                    "amount_label": f"{output.get('value', 0) / 100_000_000:.8f} BTC",
                    "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                })
    return results, len(unique_counterparties)


RIPPLE_EPOCH_OFFSET_SECONDS = 946684800


def get_outgoing_xrp(address):
    payload = {
        "method": "account_tx",
        "params": [{
            "account": address, "ledger_index_min": -1, "ledger_index_max": -1,
            "limit": 50, "forward": False,
        }],
    }
    try:
        response = requests.post(XRPL_RPC_URL, json=payload, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach the XRP Ledger node: {error}")
        return [], 0

    result = data.get("result", {})
    if result.get("status") != "success":
        print(f"    ⚠️  XRP Ledger error: {result.get('error_message') or result.get('error')}")
        return [], 0

    results = []
    unique_counterparties = set()
    # If the node returned a "marker", there are MORE transactions
    # beyond this one page of 50 - treat that as a fan-out signal too.
    has_more_pages = "marker" in result
    for tx_entry in result.get("transactions", []):
        if not tx_entry.get("validated", False):
            continue
        tx = tx_entry.get("tx", {})
        meta = tx_entry.get("meta", {})
        if tx.get("TransactionType") != "Payment":
            continue
        if tx.get("Account", "").lower() != address.lower():
            continue
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue

        destination = tx.get("Destination")
        if not destination:
            continue

        unique_counterparties.add(destination.lower())
        if len(results) < MAX_FANOUT_PER_HOP:
            delivered = meta.get("delivered_amount", tx.get("Amount"))
            amount_label = f"{int(delivered) / 1_000_000:.6f} XRP" if isinstance(delivered, str) else "token payment"
            ripple_ts = tx.get("date")
            tx_time = (
                datetime.fromtimestamp(ripple_ts + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc)
                if ripple_ts is not None else datetime.now(timezone.utc)
            )
            results.append({
                "counterparty": destination,
                "tx_hash": tx.get("hash"),
                "tx_time": tx_time,
                "amount_label": amount_label,
                "explorer_url": f"https://livenet.xrpl.org/transactions/{tx.get('hash')}",
            })

    fanout_count = len(unique_counterparties) + (HIGH_FANOUT_THRESHOLD if has_more_pages else 0)
    return results, fanout_count


def get_outgoing_tron(address):
    """
    PLAIN ENGLISH: Fetches this address's recent USDT (TRC-20) transfer
    history from TronGrid and returns the ones where THIS address was
    the sender. Same return shape as every other chain's outgoing
    lookup, so it plugs straight into the existing trace logic.
    """
    url = f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20"
    params = {"contract_address": USDT_TRC20_CONTRACT, "limit": 50, "only_confirmed": "true"}
    headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach TronGrid: {error}")
        return [], 0

    if data.get("success") is False:
        print(f"    ⚠️  TronGrid error: {data.get('error', 'unknown error')}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in data.get("data", []):
        if tx.get("from", "").lower() != address.lower():
            continue
        to_address = tx.get("to")
        if not to_address:
            continue
        unique_counterparties.add(to_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue

        decimals = (tx.get("token_info") or {}).get("decimals", 6)
        try:
            amount = int(tx.get("value", 0)) / (10 ** decimals)
        except (TypeError, ValueError):
            amount = 0.0
        tx_time = datetime.fromtimestamp(tx.get("block_timestamp", 0) / 1000, tz=timezone.utc)

        results.append({
            "counterparty": to_address,
            "tx_hash": tx.get("transaction_id"),
            "tx_time": tx_time,
            "amount_label": f"{amount:.6f} USDT",
            "explorer_url": f"https://tronscan.org/#/transaction/{tx.get('transaction_id')}",
        })
    return results, len(unique_counterparties)


def get_outgoing_counterparties(chain, address):
    if chain == "ethereum":
        return get_outgoing_ethereum(address)
    if chain == "bitcoin":
        return get_outgoing_bitcoin(address)
    if chain == "xrp":
        return get_outgoing_xrp(address)
    if chain == "tron":
        return get_outgoing_tron(address)
    return [], 0


# ====================================================================
# SECTION 3B: PER-CHAIN "WHO SENT TO THIS ADDRESS?" LOOKUPS (REVERSE)
# Same return shape as Section 3, but counterparty is the SENDER,
# not the recipient - this is what powers backward tracing.
# ====================================================================

def get_incoming_ethereum(address):
    url = "https://api.etherscan.io/v2/api"
    params = {
        "chainid": "1", "module": "account", "action": "txlist",
        "address": address, "sort": "desc", "apikey": ETHERSCAN_API_KEY,
    }
    try:
        response = requests.get(url, params=params, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        print(f"    ⚠️  Could not reach Etherscan: {error}")
        return [], 0

    if data.get("status") != "1":
        if data.get("message") != "No transactions found":
            print(f"    ⚠️  Etherscan error: {data.get('message')}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in data.get("result", []):
        if tx.get("to", "").lower() != address.lower():
            continue
        from_address = tx.get("from", "")
        if not from_address:
            continue
        unique_counterparties.add(from_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue
        eth_value = int(tx.get("value", 0)) / 1_000_000_000_000_000_000
        results.append({
            "counterparty": from_address,
            "tx_hash": tx.get("hash"),
            "tx_time": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc),
            "amount_label": f"{eth_value:.6f} ETH",
            "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
        })
    return results, len(unique_counterparties)


def get_incoming_bitcoin(address):
    """
    NOTE: same caveat as victim_collator.py - a Bitcoin transaction
    can combine multiple people's coins into one set of inputs. Where
    a payment TO this address came from a transaction with more than
    one input address, ALL of those input addresses are reported as
    possible senders rather than guessing which one is "the real"
    one. Treat multi-input attributions as leads to verify by hand.
    """
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        transactions = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach mempool.space: {error}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in transactions:
        received_value = sum(
            output.get("value", 0) for output in tx.get("vout", [])
            if (output.get("scriptpubkey_address") or "").lower() == address.lower()
        )
        if received_value <= 0:
            continue  # this tx didn't pay this address

        senders = []
        seen_lower = set()
        for tx_input in tx.get("vin", []):
            sender = (tx_input.get("prevout") or {}).get("scriptpubkey_address")
            if sender and sender.lower() != address.lower() and sender.lower() not in seen_lower:
                seen_lower.add(sender.lower())
                senders.append(sender)
        if not senders:
            continue  # coinbase reward or unknown input script

        status = tx.get("status", {})
        if status.get("confirmed", False):
            block_time = status.get("block_time")
            tx_time = datetime.fromtimestamp(block_time, tz=timezone.utc) if block_time else datetime.now(timezone.utc)
        else:
            tx_time = datetime.now(timezone.utc)
        amount_label = f"{received_value / 100_000_000:.8f} BTC"

        for sender in senders:
            unique_counterparties.add(sender.lower())
            if len(results) < MAX_FANOUT_PER_HOP:
                results.append({
                    "counterparty": sender,
                    "tx_hash": tx.get("txid"),
                    "tx_time": tx_time,
                    "amount_label": amount_label,
                    "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                })
    return results, len(unique_counterparties)


def get_incoming_xrp(address):
    payload = {
        "method": "account_tx",
        "params": [{
            "account": address, "ledger_index_min": -1, "ledger_index_max": -1,
            "limit": 50, "forward": False,
        }],
    }
    try:
        response = requests.post(XRPL_RPC_URL, json=payload, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach the XRP Ledger node: {error}")
        return [], 0

    result = data.get("result", {})
    if result.get("status") != "success":
        print(f"    ⚠️  XRP Ledger error: {result.get('error_message') or result.get('error')}")
        return [], 0

    results = []
    unique_counterparties = set()
    has_more_pages = "marker" in result
    for tx_entry in result.get("transactions", []):
        if not tx_entry.get("validated", False):
            continue
        tx = tx_entry.get("tx", {})
        meta = tx_entry.get("meta", {})
        if tx.get("TransactionType") != "Payment":
            continue
        if tx.get("Destination", "").lower() != address.lower():
            continue
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue

        sender = tx.get("Account")
        if not sender:
            continue

        unique_counterparties.add(sender.lower())
        if len(results) < MAX_FANOUT_PER_HOP:
            delivered = meta.get("delivered_amount", tx.get("Amount"))
            amount_label = f"{int(delivered) / 1_000_000:.6f} XRP" if isinstance(delivered, str) else "token payment"
            ripple_ts = tx.get("date")
            tx_time = (
                datetime.fromtimestamp(ripple_ts + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc)
                if ripple_ts is not None else datetime.now(timezone.utc)
            )
            results.append({
                "counterparty": sender,
                "tx_hash": tx.get("hash"),
                "tx_time": tx_time,
                "amount_label": amount_label,
                "explorer_url": f"https://livenet.xrpl.org/transactions/{tx.get('hash')}",
            })

    fanout_count = len(unique_counterparties) + (HIGH_FANOUT_THRESHOLD if has_more_pages else 0)
    return results, fanout_count


def get_incoming_tron(address):
    """Same as get_outgoing_tron but for INCOMING USDT transfers (this
    address as the recipient) - powers backward tracing."""
    url = f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20"
    params = {"contract_address": USDT_TRC20_CONTRACT, "limit": 50, "only_confirmed": "true"}
    headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    try:
        response = requests.get(url, params=params, headers=headers, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach TronGrid: {error}")
        return [], 0

    if data.get("success") is False:
        print(f"    ⚠️  TronGrid error: {data.get('error', 'unknown error')}")
        return [], 0

    results = []
    unique_counterparties = set()
    for tx in data.get("data", []):
        if tx.get("to", "").lower() != address.lower():
            continue
        from_address = tx.get("from")
        if not from_address:
            continue
        unique_counterparties.add(from_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue

        decimals = (tx.get("token_info") or {}).get("decimals", 6)
        try:
            amount = int(tx.get("value", 0)) / (10 ** decimals)
        except (TypeError, ValueError):
            amount = 0.0
        tx_time = datetime.fromtimestamp(tx.get("block_timestamp", 0) / 1000, tz=timezone.utc)

        results.append({
            "counterparty": from_address,
            "tx_hash": tx.get("transaction_id"),
            "tx_time": tx_time,
            "amount_label": f"{amount:.6f} USDT",
            "explorer_url": f"https://tronscan.org/#/transaction/{tx.get('transaction_id')}",
        })
    return results, len(unique_counterparties)


def get_incoming_counterparties(chain, address):
    if chain == "ethereum":
        return get_incoming_ethereum(address)
    if chain == "bitcoin":
        return get_incoming_bitcoin(address)
    if chain == "xrp":
        return get_incoming_xrp(address)
    if chain == "tron":
        return get_incoming_tron(address)
    return [], 0


# ====================================================================
# SECTION 3B: SWAP CORRELATION (tracing through instant-swap services)
# ====================================================================

_price_cache = {}  # {(chain, "YYYY-MM-DD"): price_usd_or_None} - avoids repeat lookups in one run


def get_historical_price_usd(chain, when):
    """
    PLAIN ENGLISH: Looks up the USD price of a chain's native currency
    on a given date, using CoinGecko's free historical-price endpoint
    (no API key needed). Day-level granularity only. Returns None if
    the chain isn't supported or the lookup fails - callers should
    treat that as "can't correlate this one", not an error.
    """
    coin_id = COINGECKO_COIN_ID_BY_CHAIN.get(chain)
    if not coin_id:
        return None

    date_str = when.strftime("%d-%m-%Y")
    cache_key = (chain, date_str)
    if cache_key in _price_cache:
        return _price_cache[cache_key]

    try:
        response = requests.get(
            f"https://api.coingecko.com/api/v3/coins/{coin_id}/history",
            params={"date": date_str, "localization": "false"},
            timeout=15,
        )
        data = response.json()
        price = data.get("market_data", {}).get("current_price", {}).get("usd")
    except (requests.exceptions.RequestException, ValueError):
        price = None

    _price_cache[cache_key] = price
    return price


def _parse_amount_and_symbol(amount_label):
    """'23080.283377 XRP' -> (23080.283377, 'XRP'). (None, None) for
    anything not a plain native-currency amount (e.g. issued tokens)."""
    if not amount_label or "issued token" in amount_label or "token payment" in amount_label:
        return None, None
    parts = amount_label.split(" ")
    if len(parts) < 2:
        return None, None
    try:
        return float(parts[0]), parts[1]
    except ValueError:
        return None, None


def find_group_entity_addresses(entity_name):
    """
    PLAIN ENGLISH: Returns every known wallet (address, chain, type)
    sharing this entity's name (case-insensitive) - i.e. every wallet
    you've identified as belonging to the SAME service, potentially on
    different chains. This is how a service's wallets get "grouped"
    for swap correlation: add one known_entities.json entry per chain
    the service uses, all with the same "name".
    """
    all_entries = list(BUILT_IN_KNOWN_ENTITIES)
    if os.path.isfile(KNOWN_ENTITIES_FILE):
        try:
            with open(KNOWN_ENTITIES_FILE, "r", encoding="utf-8") as file_handle:
                all_entries.extend(json.load(file_handle))
        except (json.JSONDecodeError, OSError):
            pass

    target_name_lower = entity_name.strip().lower()
    matches = []
    seen_lowercase = set()
    for entry in all_entries:
        if entry.get("name", "").strip().lower() != target_name_lower:
            continue
        address = entry.get("address")
        if not address or address.lower() in seen_lowercase:
            continue
        chain = entry.get("chain") or detect_chain(address)
        if not chain:
            continue
        matches.append((address, chain, entry.get("type", "exchange")))
        seen_lowercase.add(address.lower())

    return matches


def find_correlated_counterpart(entity_name, reference_amount_label, reference_chain,
                                 reference_time, search_direction):
    """
    PLAIN ENGLISH: Searches every OTHER known wallet belonging to
    entity_name (potentially on a different chain) for a transaction
    that plausibly correlates with reference_amount_label/time, by
    both TIMING (within SWAP_CORRELATION_WINDOW_MINUTES) and USD VALUE
    (within SWAP_CORRELATION_MIN_RATIO-MAX_RATIO of each other).

    search_direction="outgoing": reference event is a DEPOSIT into the
      service - looks for a plausible PAYOUT shortly AFTER it.
    search_direction="incoming": reference event is a PAYOUT out of
      the service - looks for a plausible DEPOSIT shortly BEFORE it.

    Returns candidates sorted best-match-first (closest USD ratio to
    1.0), capped at 5. Returns [] if price data isn't available or no
    plausible candidate is found - this is a heuristic lead-finder,
    not a guarantee something will be found.
    """
    reference_amount, reference_symbol = _parse_amount_and_symbol(reference_amount_label)
    if reference_amount is None:
        return []

    reference_price_usd = get_price_usd_for_amount(reference_chain, reference_symbol, reference_time)
    if reference_price_usd is None:
        return []
    reference_value_usd = reference_amount * reference_price_usd
    if reference_value_usd <= 0:
        return []

    candidates = []
    for address, chain, _entity_type in find_group_entity_addresses(entity_name):
        if search_direction == "outgoing":
            hops, _fanout = get_outgoing_counterparties(chain, address)
        else:
            hops, _fanout = get_incoming_counterparties(chain, address)

        for hop_info in hops:
            tx_time = hop_info["tx_time"]
            if search_direction == "outgoing":
                minutes_diff = (tx_time - reference_time).total_seconds() / 60
            else:
                minutes_diff = (reference_time - tx_time).total_seconds() / 60
            if not (0 <= minutes_diff <= SWAP_CORRELATION_WINDOW_MINUTES):
                continue

            candidate_amount, candidate_symbol = _parse_amount_and_symbol(hop_info["amount_label"])
            if candidate_amount is None:
                continue
            candidate_price_usd = get_price_usd_for_amount(chain, candidate_symbol, tx_time)
            if candidate_price_usd is None:
                continue
            candidate_value_usd = candidate_amount * candidate_price_usd

            # ratio is always "payout value / deposit value", regardless
            # of which side the reference event was on.
            ratio = (
                candidate_value_usd / reference_value_usd if search_direction == "outgoing"
                else reference_value_usd / candidate_value_usd
            )
            if not (SWAP_CORRELATION_MIN_RATIO <= ratio <= SWAP_CORRELATION_MAX_RATIO):
                continue

            candidates.append({
                "chain": chain,
                "counterparty": hop_info["counterparty"],
                "amount_label": hop_info["amount_label"],
                "tx_time": tx_time,
                "tx_hash": hop_info["tx_hash"],
                "explorer_url": hop_info["explorer_url"],
                "minutes_diff": round(minutes_diff, 1),
                "usd_match_ratio": round(ratio, 2),
            })

    candidates.sort(key=lambda candidate: abs(1 - candidate["usd_match_ratio"]))
    return candidates[:5]


def print_swap_correlation_leads(entity_name, candidates, search_direction):
    """Technical View printer for find_correlated_counterpart()'s results."""
    verb = "PAYOUT (money leaving the service)" if search_direction == "outgoing" else "DEPOSIT (money entering the service)"
    timing_word = "after" if search_direction == "outgoing" else "before"

    if not candidates:
        print(f"\n  🔄 No plausible {verb} found for {entity_name} within "
              f"{SWAP_CORRELATION_WINDOW_MINUTES} minutes and a matching USD value.")
        print("     This does NOT rule one out - price data may be missing, funds may have been")
        print("     split across multiple transactions, or the service may have other wallets not")
        print("     yet on file in known_entities.json.")
        return

    print(f"\n  🔄 {len(candidates)} possible {verb} candidate(s) for {entity_name} - "
          f"HEURISTIC LEADS, NOT CONFIRMED. Verify each one manually before relying on it:")
    for index, candidate in enumerate(candidates, start=1):
        print(f"    Candidate {index} (USD value match: {candidate['usd_match_ratio']:.0%}, "
              f"{candidate['minutes_diff']:.1f} min {timing_word}):")
        print(f"      Chain        : {candidate['chain']}")
        print(f"      Counterparty : {candidate['counterparty']}")
        print(f"      Amount       : {candidate['amount_label']}")
        print(f"      Time (UTC)   : {candidate['tx_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      Tx hash      : {candidate['tx_hash']}")
        print(f"      Verify here  : {candidate['explorer_url']}")


def print_swap_correlation_leads_simple(entity_name, candidates, search_direction, aliases=None):
    """Simple/jury-friendly printer for find_correlated_counterpart()'s results."""
    verb = "sent the funds back out" if search_direction == "outgoing" else "the funds first arrived from"

    if not candidates:
        print(f"\n  🔄 We could not find a likely match for where {entity_name} {verb} - "
              f"this doesn't rule it out, it just wasn't found automatically.")
        return

    best = candidates[0]
    label = aliases.get(best["counterparty"].lower(), best["counterparty"]) if aliases else best["counterparty"]
    print(f"\n  🔄 POSSIBLE LEAD (not confirmed): {entity_name} may have {verb} "
          f"{label}, {best['minutes_diff']:.0f} minutes {'later' if search_direction == 'outgoing' else 'earlier'}, "
          f"for a similar value ({best['usd_match_ratio']:.0%} match). "
          f"See Technical View for every candidate and how to verify this yourself.")


def _run_swap_correlation_for_flagged_paths(flagged_end_paths, search_direction, output_style, aliases=None):
    """
    PLAIN ENGLISH: For every flagged trail-end that stopped at a known
    "instant_swap" entity (see ENABLE_SWAP_CORRELATION setting near
    the top of this script), searches for a plausible correlated
    deposit/payout on that service's OTHER known wallets, and prints
    whatever it finds. Does nothing for "exchange"/"mixer" entities -
    the correlation only makes sense for the no-KYC instant-swap
    class of service - or if ENABLE_SWAP_CORRELATION is off.
    """
    if not ENABLE_SWAP_CORRELATION:
        return

    for path, _reason in flagged_end_paths:
        reference_hop = path[-1] if search_direction == "outgoing" else path[0]
        entity_address = reference_hop["to"] if search_direction == "outgoing" else reference_hop["from"]
        entity = check_known_entity(entity_address)
        # "bridge" gets the SAME correlation treatment as "instant_swap" -
        # both are "deposit on one side, payout shortly after on the
        # other (possibly a different chain/address)" patterns. A cross-
        # chain bridge deposit into a known bridge contract, followed by
        # a same-value payout appearing on another known bridge address
        # shortly after, is exactly the timing+value correlation this
        # function already does - no separate mechanism needed.
        if not entity or entity.get("type") not in ("instant_swap", "bridge"):
            continue

        reference_chain = detect_chain(entity_address)
        candidates = find_correlated_counterpart(
            entity["name"], reference_hop["amount_label"], reference_chain,
            reference_hop["tx_time"], search_direction,
        )
        if output_style == "simple":
            print_swap_correlation_leads_simple(entity["name"], candidates, search_direction, aliases)
        else:
            print_swap_correlation_leads(entity["name"], candidates, search_direction)


# ====================================================================
# SECTION 3C: DEPOSIT & CONSOLIDATION MAPPING
# ====================================================================
# WHAT THIS DOES (plain English): exchanges typically give each user
# their OWN one-time deposit address, then periodically SWEEP many of
# those individual deposit addresses into a smaller number of real
# treasury/hot wallets - a "consolidation" transaction. Spotting one
# of these sweeps landing at a KNOWN exchange wallet (known_entities.
# json) does two useful things:
#   1. CONFIRMS the address that sent it really is a deposit address
#      for that exchange - not just an unlabeled wallet.
#   2. On Bitcoin specifically, where one transaction can have MANY
#      inputs, it reveals every OTHER address swept in the SAME
#      transaction too - potentially dozens of previously-unknown
#      deposit addresses for that exchange, discovered in one shot.
# Every discovery is written to DEPOSIT_MAP_FILE and immediately
# folded into KNOWN_ENTITIES, so it's recognized instantly - both for
# the rest of THIS run, and in every future run against this same
# case data.
# ====================================================================

def load_deposit_map():
    if not os.path.isfile(DEPOSIT_MAP_FILE):
        return []
    try:
        with open(DEPOSIT_MAP_FILE, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (json.JSONDecodeError, OSError):
        return []


def save_deposit_map(entries):
    with open(DEPOSIT_MAP_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(entries, file_handle, indent=2)


def register_deposit_address(address, chain, exchange_name, exchange_type,
                              tx_hash, tx_time, discovered_via="direct_consolidation"):
    """
    PLAIN ENGLISH: Records that `address` is a CONFIRMED deposit
    address for `exchange_name` - it was seen sweeping funds into one
    of the exchange's own known wallets. Skips silently if this
    address is already recorded. Also updates the in-memory
    KNOWN_ENTITIES immediately, so the REST OF THIS RUN recognizes it
    too, not just future runs. Returns True if newly added, False if
    it was already known.
    """
    entries = load_deposit_map()
    if any(entry["address"].lower() == address.lower() for entry in entries):
        return False

    entries.append({
        "address": address,
        "chain": chain,
        "exchange_name": exchange_name,
        "exchange_type": exchange_type,
        "discovered_via": discovered_via,
        "consolidation_tx_hash": tx_hash,
        "consolidation_time_utc": (
            tx_time.strftime("%Y-%m-%d %H:%M:%S") if hasattr(tx_time, "strftime") else str(tx_time)
        ),
        "first_seen_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
    })
    save_deposit_map(entries)

    KNOWN_ENTITIES[address.lower()] = {"name": exchange_name, "type": exchange_type}
    return True


def get_bitcoin_tx_input_addresses(tx_hash):
    """
    PLAIN ENGLISH: Fetches a Bitcoin transaction's FULL list of input
    (spending) addresses directly from mempool.space - this is what
    reveals every sibling deposit address swept into an exchange by
    the SAME transaction, not just the one address a trace happened
    to already be following.
    """
    try:
        response = requests.get(f"https://mempool.space/api/tx/{tx_hash}", timeout=15)
        response.raise_for_status()
        tx = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not fetch full transaction {tx_hash}: {error}")
        return []

    addresses = set()
    for tx_input in tx.get("vin", []):
        prevout = tx_input.get("prevout") or {}
        input_address = prevout.get("scriptpubkey_address")
        if input_address:
            addresses.add(input_address)
    return list(addresses)


def register_consolidation_and_siblings(deposit_address, chain, entity, tx_hash, tx_time):
    """
    PLAIN ENGLISH: Shared by both the automatic in-trace detection
    and the manual check tool - registers `deposit_address` as a
    confirmed deposit address for `entity`, then (Bitcoin only) also
    fetches and registers every SIBLING address swept in the same
    transaction. Returns (was_newly_mapped, sibling_addresses_mapped_count).
    """
    newly_mapped = register_deposit_address(
        deposit_address, chain, entity["name"], entity["type"], tx_hash, tx_time,
    )

    sibling_count = 0
    if chain == "bitcoin":
        for sibling_address in get_bitcoin_tx_input_addresses(tx_hash):
            if sibling_address.lower() == deposit_address.lower():
                continue
            if register_deposit_address(sibling_address, "bitcoin", entity["name"], entity["type"],
                                         tx_hash, tx_time, discovered_via="sibling_of_sweep"):
                sibling_count += 1

    return newly_mapped, sibling_count


def manual_check_deposit_consolidation(address):
    """
    PLAIN ENGLISH: Given a SINGLE address (not necessarily one found
    during a trace), checks whether it has recently swept funds into
    a KNOWN exchange wallet - i.e. whether it's confirmable as a
    deposit address for that exchange. This is the tool for "is this
    address genuinely one of Exchange X's deposit addresses?".

    If a match is found, it's registered into the shared deposit map
    exactly like the automatic in-trace detection does (including the
    Bitcoin sibling reveal). Always returns a result dict - a "no
    match found" result is NOT proof the address is unrelated, and
    the returned message says so.
    """
    chain = detect_chain(address)
    if chain is None:
        return {
            "address": address, "chain": None, "match": False, "already_known": False,
            "message": "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.",
        }

    existing = check_known_entity(address)
    if existing:
        return {
            "address": address, "chain": chain, "match": True, "already_known": True,
            "exchange_name": existing["name"], "exchange_type": existing["type"],
            "message": f"Already known: {existing['name']} ({existing['type']}).",
        }

    counterparties, _fanout_count = get_outgoing_counterparties(chain, address)
    for hop_info in counterparties:
        entity = check_known_entity(hop_info["counterparty"])
        if not entity or entity.get("type") != "exchange":
            continue

        newly_mapped, sibling_count = register_consolidation_and_siblings(
            address, chain, entity, hop_info["tx_hash"], hop_info["tx_time"],
        )
        message = f"Confirmed: swept into {entity['name']} ({entity['type']}) via tx {hop_info['tx_hash']}."
        if sibling_count:
            message += f" Also found and mapped {sibling_count} sibling deposit address(es) from the same transaction."

        return {
            "address": address, "chain": chain, "match": True, "already_known": False,
            "exchange_name": entity["name"], "exchange_type": entity["type"],
            "newly_mapped": newly_mapped,
            "consolidation_tx_hash": hop_info["tx_hash"],
            "consolidation_time_utc": hop_info["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
            "explorer_url": hop_info["explorer_url"],
            "sibling_deposit_addresses_found": sibling_count,
            "message": message,
        }

    return {
        "address": address, "chain": chain, "match": False, "already_known": False,
        "message": "No outgoing sweep to a known exchange found in this address's recent "
                   "activity. This does NOT confirm the address is unrelated - it may not "
                   "have been consolidated yet, or the exchange's treasury wallet may not "
                   "be in known_entities.json yet.",
    }


# ====================================================================
# SECTION 4: SHARED CASE WATCHLIST (illicit-wallet targets)
# ====================================================================

def load_known_entities():
    """Returns a dict of {address_lowercase: {"name":..., "type":...}}
    combining BUILT_IN_KNOWN_ENTITIES with KNOWN_ENTITIES_FILE (if present)."""
    entities = {}
    for entry in BUILT_IN_KNOWN_ENTITIES:
        if entry.get("address"):
            entities[entry["address"].lower()] = {
                "name": entry.get("name", "Known entity"),
                "type": entry.get("type", "exchange"),
            }

    if os.path.isfile(KNOWN_ENTITIES_FILE):
        try:
            with open(KNOWN_ENTITIES_FILE, "r", encoding="utf-8") as file_handle:
                file_entries = json.load(file_handle)
            for entry in file_entries:
                if entry.get("address"):
                    entities[entry["address"].lower()] = {
                        "name": entry.get("name", "Known entity"),
                        "type": entry.get("type", "exchange"),
                    }
        except (json.JSONDecodeError, OSError, KeyError) as error:
            print(f"⚠️  Could not read known-entities file: {error}")

    # Fold in every exchange deposit address confirmed by a past
    # consolidation-mapping discovery (SECTION 3C) - once confirmed,
    # it should be recognized immediately in every future run.
    if os.path.isfile(DEPOSIT_MAP_FILE):
        try:
            with open(DEPOSIT_MAP_FILE, "r", encoding="utf-8") as file_handle:
                deposit_entries = json.load(file_handle)
            for entry in deposit_entries:
                if entry.get("address"):
                    entities[entry["address"].lower()] = {
                        "name": entry.get("exchange_name", "Known entity"),
                        "type": entry.get("exchange_type", "exchange"),
                    }
        except (json.JSONDecodeError, OSError, KeyError) as error:
            print(f"⚠️  Could not read deposit map file: {error}")

    return entities


KNOWN_ENTITIES = load_known_entities()
if KNOWN_ENTITIES:
    print(f"🏷️  Loaded {len(KNOWN_ENTITIES)} known entity label(s) "
          f"({os.path.basename(KNOWN_ENTITIES_FILE)} + built-ins).")


def parse_amount_from_label(amount_label):
    """
    PLAIN ENGLISH: Pulls the plain number back out of an amount_label
    like "23080.283377 XRP" or "0.00012345 BTC" -> 23080.283377 /
    0.00012345. Returns None for anything it can't parse as a number
    (e.g. the "token payment" label used for non-XRP token payments,
    where we don't have a comparable native-currency amount).
    """
    if not amount_label:
        return None
    first_token = amount_label.split(" ")[0]
    try:
        return float(first_token)
    except ValueError:
        return None


def check_known_entity(address):
    """Returns {"name":..., "type":...} if address is a known exchange/mixer/
    custodial wallet, otherwise None."""
    return KNOWN_ENTITIES.get(address.lower())


def load_case_watchlist_addresses():
    if not os.path.isfile(CASE_WATCHLIST_FILE):
        return []
    try:
        with open(CASE_WATCHLIST_FILE, "r", encoding="utf-8") as file_handle:
            entries = json.load(file_handle)
        return [entry["address"] for entry in entries if entry.get("address")]
    except (json.JSONDecodeError, OSError, KeyError) as error:
        print(f"⚠️  Could not read shared case watchlist: {error}")
        return []


def build_target_set(include_case_watchlist=True):
    """Combines TARGET_ILLICIT_WALLETS with the shared case watchlist (unless
    include_case_watchlist is False), deduped."""
    targets = list(TARGET_ILLICIT_WALLETS)
    existing_lowercase = {t.lower() for t in targets}

    if include_case_watchlist:
        case_addresses = load_case_watchlist_addresses()
        added_from_case = 0
        for address in case_addresses:
            if address.lower() not in existing_lowercase:
                targets.append(address)
                existing_lowercase.add(address.lower())
                added_from_case += 1

        if added_from_case:
            print(f"🔗 Pulled in {added_from_case} illicit-wallet target(s) from the shared "
                  f"case watchlist ({os.path.basename(CASE_WATCHLIST_FILE)}).")

    return targets, existing_lowercase


# ====================================================================
# SECTION 5: THE FORWARD TRACE (breadth-first search)
# ====================================================================

def trace_forward(victim_wallet, target_lowercase_set, max_hops, starting_amount=None):
    """
    PLAIN ENGLISH: Starting from victim_wallet, follows outgoing
    transactions hop by hop (breadth-first - checking every wallet at
    hop 1 before moving on to hop 2, and so on) until either a target
    illicit wallet is reached or max_hops is used up.

    Any wallet that is a KNOWN EXCHANGE/MIXER (see known_entities.json)
    or has a HIGH FAN-OUT (see HIGH_FANOUT_THRESHOLD) is treated as a
    likely custodial wallet: the trace does NOT try to expand past it
    (that would mean tracing into an unrelated crowd of other
    customers), and the branch is reported separately as a flagged
    trail end - a lead for legal process, not a dead-end null result.

    If starting_amount is given, hops whose amount isn't a plausible
    continuation of that amount (see AMOUNT_MATCH_MIN_RATIO / MAX_RATIO)
    are NOT expanded any further (that keeps the automatic trace from
    following what's probably noise) - but every one of them is still
    fully recorded and reported, never silently dropped. The amount
    actually carried by each hop taken IS expanded is what gets
    checked against on the NEXT hop, so a legitimate split into two
    large pieces is still followed down both branches.

    Returns:
      found_paths          - paths that reached a target illicit wallet
      flagged_end_paths    - list of (path, reason) for branches that
                              stopped at a known/likely custodial wallet
      addresses_visited    - count of unique addresses actually checked
      amount_filtered_paths - list of (path, reason) for every
                              individual hop the amount filter held
                              back from further exploration - each
                              path ends in that specific hop, so you
                              can see exactly which wallet/tx/amount
                              it was and judge it yourself. Empty if
                              starting_amount is None.
    """
    victim_chain = detect_chain(victim_wallet)
    if victim_chain is None:
        print("[!] The victim wallet doesn't look like a valid Ethereum, Bitcoin, "
              "or XRP address. Please double check it.")
        return [], [], 0, []

    found_paths = []
    flagged_end_paths = []
    amount_filtered_paths = []
    visited = {victim_wallet.lower()}
    # Each frontier entry: (address, path_so_far, tracked_amount).
    # tracked_amount is None whenever amount filtering is off.
    frontier = [(victim_wallet, [], starting_amount)]

    for hop_number in range(1, max_hops + 1):
        print(f"\n--- Hop {hop_number}: checking {len(frontier)} wallet(s) ---")
        next_frontier = []

        for address, path_so_far, tracked_amount in frontier:
            entity = check_known_entity(address)
            print(f"  Checking outgoing activity from {address} "
                  + (f"(tracking ~{tracked_amount:g}) " if tracked_amount is not None else "")
                  + "...")
            counterparties, fanout_count = get_outgoing_counterparties(victim_chain, address)
            time.sleep(SECONDS_BETWEEN_REQUESTS)

            high_fanout = fanout_count >= HIGH_FANOUT_THRESHOLD
            if (entity or high_fanout) and path_so_far:
                reason = (
                    f"{entity['name']} (known {entity['type']})" if entity
                    else f"high fan-out wallet ({fanout_count}+ distinct counterparties "
                         f"seen - likely exchange/custodial)"
                )
                print(f"    🔶 TRAIL ENDS: {address} is a {reason} - not tracing "
                      f"further into its counterparties.")
                flagged_end_paths.append((path_so_far, reason))

                # A CONFIRMED (not just high-fanout-guessed) exchange hit
                # means the hop that led here was a genuine deposit sweep -
                # register it (and, on Bitcoin, its sweep siblings) so this
                # and every future run recognizes it immediately.
                if entity and ENABLE_DEPOSIT_CONSOLIDATION_MAPPING and entity.get("type") == "exchange":
                    deposit_hop = path_so_far[-1]
                    newly_mapped, sibling_count = register_consolidation_and_siblings(
                        deposit_hop["from"], victim_chain, entity,
                        deposit_hop["tx_hash"], deposit_hop["tx_time"],
                    )
                    if newly_mapped:
                        print(f"    🗺️  Mapped {deposit_hop['from']} as a confirmed "
                              f"{entity['name']} deposit address.")
                    if sibling_count:
                        print(f"    🗺️  Also mapped {sibling_count} sibling deposit "
                              f"address(es) swept in the SAME transaction.")

            for hop_info in counterparties:
                hop_amount = parse_amount_from_label(hop_info["amount_label"])
                counterparty = hop_info["counterparty"]
                hop_dict = {
                    "from": address,
                    "to": counterparty,
                    "tx_hash": hop_info["tx_hash"],
                    "tx_time": hop_info["tx_time"],
                    "amount_label": hop_info["amount_label"],
                    "explorer_url": hop_info["explorer_url"],
                }

                amount_related = True
                if tracked_amount is not None:
                    if hop_amount is None:
                        amount_related = False
                        reason = ("amount filter is on, but this hop's amount couldn't be "
                                  "parsed/compared (e.g. a non-native token payment) - "
                                  "reviewed manually, not auto-followed")
                    else:
                        ratio = (hop_amount / tracked_amount) if tracked_amount > 0 else 0
                        if ratio < AMOUNT_MATCH_MIN_RATIO or ratio > AMOUNT_MATCH_MAX_RATIO:
                            amount_related = False
                            reason = (f"amount ({hop_amount:g}) is {ratio:.0%} of the "
                                      f"~{tracked_amount:g} being tracked - outside the "
                                      f"{AMOUNT_MATCH_MIN_RATIO:.0%}-{AMOUNT_MATCH_MAX_RATIO:.0%} "
                                      f"match range, so not auto-followed further")

                if not amount_related:
                    amount_filtered_paths.append((path_so_far + [hop_dict], reason))
                    continue  # don't expand past it, but it's fully recorded above

                new_path = path_so_far + [hop_dict]
                # The amount THIS hop actually carried is what gets
                # checked against on the next hop.
                next_tracked_amount = hop_amount if tracked_amount is not None else None

                if counterparty.lower() in target_lowercase_set:
                    print(f"    🚨 MATCH: reached flagged wallet {counterparty} "
                          f"at hop {hop_number}!")
                    found_paths.append(new_path)
                    # Keep searching other branches too - there could
                    # be more than one path or more than one target.
                    continue

                if entity or high_fanout:
                    # Don't expand past a known/likely custodial wallet -
                    # already reported as a flagged trail end above.
                    continue

                if counterparty.lower() not in visited:
                    visited.add(counterparty.lower())
                    next_frontier.append((counterparty, new_path, next_tracked_amount))

        frontier = next_frontier
        if not frontier:
            print("\n  No further un-visited wallets to follow - trail ends here.")
            break

    return found_paths, flagged_end_paths, len(visited), amount_filtered_paths


def trace_backward(start_wallet, target_lowercase_set, max_hops, starting_amount=None):
    """
    PLAIN ENGLISH: The mirror image of trace_forward(). Starting from
    an illicit/flagged wallet, follows INCOMING transactions hop by
    hop (breadth-first) to see where the money actually came from.

    If target_lowercase_set is non-empty, it also flags any path
    that reaches one of those wallets (e.g. a specific victim wallet
    you suspect funded it) as a MATCH - same idea as trace_forward.

    Every other branch is still reported, WITH A REASON, instead of
    silently vanishing:
      - reaches a KNOWN exchange/mixer (known_entities.json)         -> named
      - reaches a wallet with HIGH FAN-IN (HIGH_FANOUT_THRESHOLD)    -> likely custodial
      - simply has no further incoming activity to trace              -> possible true source
      - had incoming activity, but none of it matched the tracked
        amount - see amount_filtered_paths for exactly which hops     -> possible true source
      - hop limit reached while wallets were still un-traced          -> trail continues further back

    None of these are treated as "no link" - they're exactly where to
    aim follow-up work (a subpoena, a bigger MAX_HOPS run, manual
    review) instead of assuming the money trail just stopped existing.

    If starting_amount is given, incoming hops that aren't a plausible
    continuation of the tracked amount (see AMOUNT_MATCH_MIN_RATIO /
    MAX_RATIO) are NOT expanded any further - but every one of them is
    still fully recorded in amount_filtered_paths, never silently
    dropped, same principle as trace_forward.

    Returns (matched_paths, trail_end_paths, unique_addresses_visited,
    amount_filtered_paths). trail_end_paths and amount_filtered_paths
    are both lists of (path, reason) tuples. Every path is a list of
    hop dicts in the SAME chronological order as trace_forward's paths
    (earliest hop first, most recent hop last), so
    print_path()/build_clean_rows() work unchanged.
    """
    start_chain = detect_chain(start_wallet)
    if start_chain is None:
        print("[!] That wallet doesn't look like a valid Ethereum, Bitcoin, "
              "or XRP address. Please double check it.")
        return [], [], 0, []

    matched_paths = []
    trail_end_paths = []
    amount_filtered_paths = []
    visited = {start_wallet.lower()}
    # Each frontier entry: (address, path_so_far_in_chronological_order, tracked_amount)
    frontier = [(start_wallet, [], starting_amount)]

    for hop_number in range(1, max_hops + 1):
        print(f"\n--- Hop {hop_number} back: checking {len(frontier)} wallet(s) ---")
        next_frontier = []

        for address, path_so_far, tracked_amount in frontier:
            entity = check_known_entity(address)
            print(f"  Checking incoming activity into {address} "
                  + (f"(tracking ~{tracked_amount:g}) " if tracked_amount is not None else "")
                  + "...")
            raw_counterparties, fanout_count = get_incoming_counterparties(start_chain, address)
            time.sleep(SECONDS_BETWEEN_REQUESTS)

            high_fanout = fanout_count >= HIGH_FANOUT_THRESHOLD

            # Apply the amount filter up front so "nothing incoming at
            # all" and "incoming activity, but none of it matches the
            # tracked amount" both get reported clearly - and every
            # filtered-out hop still gets fully recorded, not dropped.
            counterparties = []
            for hop_info in raw_counterparties:
                hop_amount = parse_amount_from_label(hop_info["amount_label"])
                hop_dict = {
                    "from": hop_info["counterparty"],
                    "to": address,
                    "tx_hash": hop_info["tx_hash"],
                    "tx_time": hop_info["tx_time"],
                    "amount_label": hop_info["amount_label"],
                    "explorer_url": hop_info["explorer_url"],
                }

                if tracked_amount is not None:
                    if hop_amount is None:
                        reason = ("amount filter is on, but this hop's amount couldn't be "
                                  "parsed/compared (e.g. a non-native token payment) - "
                                  "reviewed manually, not auto-followed")
                        amount_filtered_paths.append(([hop_dict] + path_so_far, reason))
                        continue
                    ratio = (hop_amount / tracked_amount) if tracked_amount > 0 else 0
                    if ratio < AMOUNT_MATCH_MIN_RATIO or ratio > AMOUNT_MATCH_MAX_RATIO:
                        reason = (f"amount ({hop_amount:g}) is {ratio:.0%} of the "
                                  f"~{tracked_amount:g} being tracked - outside the "
                                  f"{AMOUNT_MATCH_MIN_RATIO:.0%}-{AMOUNT_MATCH_MAX_RATIO:.0%} "
                                  f"match range, so not auto-followed further")
                        amount_filtered_paths.append(([hop_dict] + path_so_far, reason))
                        continue

                counterparties.append((hop_info, hop_amount))

            if not counterparties:
                if path_so_far:
                    if entity:
                        reason = f"{entity['name']} (known {entity['type']}) - no incoming activity visible"
                    elif raw_counterparties:  # had activity, just none matching the tracked amount
                        reason = ("had incoming activity, but none of it matched the tracked "
                                  "amount - see the amount-filtered leads below for exactly "
                                  "which transactions those were")
                    else:
                        reason = ("no further incoming activity found - possible true source "
                                  "of funds, or an untracked/off-chain funding method")
                    trail_end_paths.append((path_so_far, reason))
                continue

            if (entity or high_fanout) and path_so_far:
                reason = (
                    f"{entity['name']} (known {entity['type']})" if entity
                    else f"high fan-in wallet ({fanout_count}+ distinct counterparties "
                         f"seen - likely exchange/custodial)"
                )
                print(f"    🔶 TRAIL ENDS: {address} is a {reason} - not tracing "
                      f"further into its counterparties.")
                trail_end_paths.append((path_so_far, reason))

            for hop_info, hop_amount in counterparties:
                counterparty = hop_info["counterparty"]
                # This hop happened BEFORE everything already in
                # path_so_far, so it goes at the FRONT of the path.
                new_path = [{
                    "from": counterparty,
                    "to": address,
                    "tx_hash": hop_info["tx_hash"],
                    "tx_time": hop_info["tx_time"],
                    "amount_label": hop_info["amount_label"],
                    "explorer_url": hop_info["explorer_url"],
                }] + path_so_far
                next_tracked_amount = hop_amount if tracked_amount is not None else None

                if target_lowercase_set and counterparty.lower() in target_lowercase_set:
                    print(f"    🚨 MATCH: traced back to known wallet {counterparty} "
                          f"at hop {hop_number}!")
                    matched_paths.append(new_path)
                    continue

                if entity or high_fanout:
                    # Don't expand past a known/likely custodial wallet -
                    # already reported as a flagged trail end above.
                    continue

                if counterparty.lower() not in visited:
                    visited.add(counterparty.lower())
                    next_frontier.append((counterparty, new_path, next_tracked_amount))
                # Already-visited counterparties are a merge point in
                # the fund graph (e.g. two branches converging back to
                # the same wallet) - not followed again to avoid loops,
                # but the hop that reached them is still real and was
                # already reported at print_path/CSV time via the
                # branch that discovered them first.

        frontier = next_frontier
        if not frontier:
            print("\n  No further un-visited wallets to follow - trail ends here.")
            break
    else:
        # Hop limit reached with wallets still un-traced - report
        # those as trail ends too (the trail may continue further
        # back than MAX_HOPS allowed).
        for address, path_so_far, _tracked_amount in frontier:
            if path_so_far:
                trail_end_paths.append((path_so_far, "hop limit reached - trail may continue further back"))

    return matched_paths, trail_end_paths, len(visited), amount_filtered_paths


def print_trail_end_path(path, path_number, reason=None):
    label = f" - {reason}" if reason else ""
    print(f"\n  SOURCE TRAIL {path_number} ({len(path)} hop(s) back){label}:")
    for hop_index, hop in enumerate(path, start=1):
        print(f"    Hop {hop_index}: {hop['from']}")
        print(f"      --> sent {hop['amount_label']} to {hop['to']}")
        print(f"      Tx time (UTC): {hop['tx_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      Tx hash      : {hop['tx_hash']}")
        print(f"      Verify here  : {hop['explorer_url']}")


def print_path(path, path_number):
    print(f"\n  PATH {path_number} ({len(path)} hop(s)):")
    for hop_index, hop in enumerate(path, start=1):
        print(f"    Hop {hop_index}: {hop['from']}")
        print(f"      --> sent {hop['amount_label']} to {hop['to']}")
        print(f"      Tx time (UTC): {hop['tx_time'].strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"      Tx hash      : {hop['tx_hash']}")
        print(f"      Verify here  : {hop['explorer_url']}")


def format_friendly_datetime(dt):
    """PLAIN ENGLISH: '2026-05-06 15:28:40' -> '06 May 2026 at 03:28 PM UTC'."""
    return dt.strftime("%d %b %Y at %I:%M %p UTC")


def build_friendly_aliases(all_paths, root_wallet):
    """
    PLAIN ENGLISH: Assigns a short, consistent, plain-English label to
    every wallet address across the given paths, so a Simple View
    report can say "Wallet A sent money to Wallet B" instead of
    repeating full 26-42 character addresses everywhere. The SAME
    wallet always gets the SAME label, everywhere it appears.

      - The wallet the trace started from gets a role label
        ("Wallet Under Investigation").
      - Any wallet labeled in known_entities.json gets ITS REAL NAME
        instead of a generic letter - that's more informative, not
        less (e.g. "Binance (exchange)" beats "Wallet C").
      - Everything else gets sequential letters (Wallet A, Wallet B,
        ...) in the order each address first appears.

    Returns an ordered dict: {address_lowercase: friendly_label}
    """
    aliases = {root_wallet.lower(): "Wallet Under Investigation"}
    next_letter_index = [0]  # mutable closure cell

    def next_letter():
        index = next_letter_index[0]
        next_letter_index[0] += 1
        letters = ""
        index += 1
        while index > 0:
            index, remainder = divmod(index - 1, 26)
            letters = chr(65 + remainder) + letters
        return letters

    for path in all_paths:
        for hop in path:
            for address in (hop["from"], hop["to"]):
                key = address.lower()
                if key in aliases:
                    continue
                entity = check_known_entity(address)
                aliases[key] = f"{entity['name']} ({entity['type']})" if entity else f"Wallet {next_letter()}"

    return aliases


def _friendly_label_for_hop_end(address, aliases, target_lowercase_set):
    label = aliases.get(address.lower(), address)
    if target_lowercase_set and address.lower() in target_lowercase_set:
        label = f"🚩 {label} (FLAGGED WALLET)"
    return label


def print_path_simple(path, path_number, aliases, target_lowercase_set=None, reason=None):
    """Simple/jury-friendly equivalent of print_path() / print_trail_end_path()."""
    label_suffix = f" - {reason}" if reason else ""
    print(f"\n  TRAIL {path_number} ({len(path)} step(s)){label_suffix}:")

    # A quick at-a-glance arrow chain first...
    chain_labels = [aliases.get(path[0]["from"].lower(), path[0]["from"])]
    for hop in path:
        chain_labels.append(_friendly_label_for_hop_end(hop["to"], aliases, target_lowercase_set))
    print("    " + "  →  ".join(chain_labels))

    # ...then the step-by-step detail underneath.
    print()
    for step_index, hop in enumerate(path, start=1):
        from_label = aliases.get(hop["from"].lower(), hop["from"])
        to_label = _friendly_label_for_hop_end(hop["to"], aliases, target_lowercase_set)
        print(f"    Step {step_index}: {from_label} sent {hop['amount_label']} to {to_label}")
        print(f"             on {format_friendly_datetime(hop['tx_time'])}")


_DIAGRAM_CSS = """
  body { font-family: -apple-system, "Segoe UI", Arial, sans-serif; background:#f4f5f7; color:#1e1e2e; margin:0; padding:32px; }
  h1 { font-size:20px; margin-bottom:4px; }
  .subtitle { color:#6b7280; font-size:13px; margin-bottom:28px; }
  .section-title { font-size:15px; margin:28px 0 12px; }
  .match-title { color:#b91c1c; }
  .flagged-title { color:#b45309; }
  .filtered-title { color:#92400e; }
  .trail-row { margin-bottom:22px; }
  .reason-label { font-size:12px; color:#6b7280; margin-bottom:6px; font-style:italic; }
  .trail-flow { display:flex; align-items:center; flex-wrap:wrap; gap:0; }
  .wallet-box { background:#fff; border:2px solid #93c5fd; border-radius:10px; padding:10px 14px;
                font-size:13px; font-weight:600; min-width:90px; text-align:center; box-shadow:0 1px 2px rgba(0,0,0,.08); }
  .root-box { border-color:#4338ca; background:#eef2ff; }
  .entity-box { border-color:#0891b2; background:#ecfeff; }
  .flagged-box { border-color:#dc2626; background:#fef2f2; color:#991b1b; }
  .arrow-wrap { display:flex; flex-direction:column; align-items:center; margin:0 10px; min-width:100px; }
  .arrow { font-size:20px; color:#9ca3af; }
  .arrow-label { font-size:11px; text-align:center; color:#374151; margin-bottom:2px; }
  .arrow-date { color:#9ca3af; }
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


def _diagram_box_html(label, box_class="wallet-box"):
    return f'<div class="wallet-box {box_class}">{_escape_html(label)}</div>'


def _diagram_arrow_html(amount_label, friendly_time):
    return (
        '<div class="arrow-wrap">'
        f'<div class="arrow-label">{_escape_html(amount_label)}<br>'
        f'<span class="arrow-date">{_escape_html(friendly_time)}</span></div>'
        '<div class="arrow">&#8594;</div>'
        '</div>'
    )


def _path_to_diagram_row(path, aliases, target_lowercase_set, reason=None):
    """Renders one path as a horizontal row of connected boxes and arrows."""
    root_label = aliases.get(path[0]["from"].lower(), path[0]["from"])
    pieces = [_diagram_box_html(root_label, "root-box")]
    for hop in path:
        to_key = hop["to"].lower()
        to_label = aliases.get(to_key, hop["to"])
        if target_lowercase_set and to_key in target_lowercase_set:
            box_class = "flagged-box"
            to_label = f"🚩 {to_label}"
        elif check_known_entity(hop["to"]):
            box_class = "entity-box"
        else:
            box_class = "wallet-box"
        pieces.append(_diagram_arrow_html(hop["amount_label"], format_friendly_datetime(hop["tx_time"])))
        pieces.append(_diagram_box_html(to_label, box_class))

    reason_html = f'<div class="reason-label">{_escape_html(reason)}</div>' if reason else ""
    return f'<div class="trail-row">{reason_html}<div class="trail-flow">{"".join(pieces)}</div></div>'


def write_visual_html(matched_paths, flagged_end_paths, amount_filtered_paths, aliases,
                       target_lowercase_set, root_wallet, direction, label):
    """
    PLAIN ENGLISH: Writes a self-contained HTML page showing the fund
    trail as connected boxes and arrows (each arrow labeled with the
    amount and date of that transfer) instead of a text table - built
    for showing to a solicitor, victim, or jury. Uses the SAME
    aliases already built for the Simple View text report, so the
    two stay consistent with each other. Open the file in any
    browser; it's also plain HTML so it prints cleanly if needed.

    Returns the saved file path, or None if there was nothing to draw.
    """
    if not (matched_paths or flagged_end_paths or amount_filtered_paths):
        return None

    os.makedirs(CLEAN_OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_wallet = "".join(c for c in root_wallet if c.isalnum())[:20]
    html_path = os.path.join(CLEAN_OUTPUT_DIR, f"fund_trace_diagram_{label}_{safe_wallet}_{timestamp}.html")

    sections = []
    if matched_paths:
        rows = "".join(_path_to_diagram_row(p, aliases, target_lowercase_set) for p in matched_paths)
        sections.append(f'<h2 class="section-title match-title">🚨 Direct link found</h2>{rows}')
    if flagged_end_paths:
        rows = "".join(_path_to_diagram_row(p, aliases, target_lowercase_set, reason)
                        for p, reason in flagged_end_paths)
        sections.append(f'<h2 class="section-title flagged-title">'
                         f'🔶 Trails ending at a known/likely exchange</h2>{rows}')
    if amount_filtered_paths:
        rows = "".join(_path_to_diagram_row(p, aliases, target_lowercase_set, reason)
                        for p, reason in amount_filtered_paths)
        sections.append(f'<h2 class="section-title filtered-title">'
                         f'⚠️ Flagged for manual review (amount mismatch)</h2>{rows}')

    legend_rows = "".join(
        f'<tr><td class="legend-label">{_escape_html(label_text)}</td>'
        f'<td class="legend-address">{_escape_html(address)}</td></tr>'
        for address, label_text in aliases.items()
    )

    html_document = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>Fund Trace Diagram - {_escape_html(root_wallet)}</title>
<style>{_DIAGRAM_CSS}</style></head>
<body>
  <h1>Fund Trace Diagram</h1>
  <div class="subtitle">Wallet under investigation: {_escape_html(root_wallet)} &middot; direction: {_escape_html(direction)}</div>
  {"".join(sections)}
  <h2 class="section-title">Key</h2>
  <table class="legend">{legend_rows}</table>
  <div class="footer-note">Full technical detail (transaction references, exact timestamps, block-explorer links) is available in Technical View / the CSV export alongside this file.</div>
</body></html>"""

    with open(html_path, "w", encoding="utf-8") as file_handle:
        file_handle.write(html_document)

    return html_path


def print_alias_legend(aliases):
    """
    PLAIN ENGLISH: Prints what each plain-English label above stands
    for, in the order each wallet first appeared. Full addresses are
    still shown here (not hidden) so the summary remains independently
    verifiable - Simple View changes how results are PRESENTED, not
    what evidence is available.
    """
    print("\n" + "=" * 78)
    print("KEY - what each label above stands for")
    print("=" * 78)
    print("  (Full addresses are listed here so this summary can still be independently")
    print("   verified. Transaction-level detail - hashes, exact timestamps, explorer")
    print("   links - is available in Technical View.)\n")
    for address, label in aliases.items():
        print(f"  {label:<38} {address}")


def build_clean_rows(paths_found, victim_wallet):
    """
    PLAIN ENGLISH: Flattens every found path into simple rows -
    one row per hop - with just the fields you actually need to
    trace moved funds at a glance: which path, which hop, from,
    to, amount, and the date/time. Used by both the CSV export
    and the plain-text summary below.
    """
    rows = []
    for path_number, path in enumerate(paths_found, start=1):
        for hop_index, hop in enumerate(path, start=1):
            rows.append({
                "path": path_number,
                "hop": hop_index,
                "from": hop["from"],
                "to": hop["to"],
                "amount": hop["amount_label"],
                "tx_time_utc": hop["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "tx_hash": hop["tx_hash"],
                "verify_url": hop["explorer_url"],
            })
    return rows


def dedupe_clean_rows(rows):
    """
    PLAIN ENGLISH: Multiple paths often share the same starting hops
    (the trace branches out from a common point), which means the
    same transaction would otherwise get printed once per path -
    confusing when you're just trying to follow the money. This
    collapses rows with the same transaction hash into ONE row,
    listing every path number that uses it, and keeps the result in
    chronological (tx time) order.
    """
    merged = {}
    order = []
    for row in rows:
        key = row["tx_hash"]
        if key not in merged:
            merged[key] = {**row, "paths": {row["path"]}}
            order.append(key)
        else:
            merged[key]["paths"].add(row["path"])

    deduped = []
    for key in order:
        entry = merged[key]
        entry["paths_label"] = ",".join(str(p) for p in sorted(entry["paths"]))
        deduped.append(entry)

    deduped.sort(key=lambda r: r["tx_time_utc"])
    return deduped


def print_clean_summary(paths_found, victim_wallet):
    """
    PLAIN ENGLISH: Prints a condensed, easy-to-scan table straight to
    the results screen (terminal, or the live output panel in
    threat_intel_dashboard.py) - just From / To / Amount / Time per
    unique hop, no tx hashes or URLs cluttering it up. Hops shared by
    more than one path (a common branching prefix) are listed ONCE,
    with a "Paths" column showing which path number(s) use them - so
    there's no duplicate/confusing repetition. This is IN ADDITION to
    the full detailed report already printed by print_path().
    """
    rows = dedupe_clean_rows(build_clean_rows(paths_found, victim_wallet))

    print("\n" + "=" * 78)
    print("CLEAN SUMMARY - fund movement at a glance (duplicates merged)")
    print("=" * 78)
    print(f"\n  {'Paths':<7}{'From':<36}{'To':<36}{'Amount':<18}{'Time (UTC)'}")
    print("  " + "-" * 105)
    for row in rows:
        print(f"  {row['paths_label']:<7}{row['from']:<36}{row['to']:<36}"
              f"{row['amount']:<18}{row['tx_time_utc']}")


def write_clean_outputs(paths_found, victim_wallet, label="forward"):
    """
    PLAIN ENGLISH: Writes two easy-to-read files alongside the full
    terminal report - a CSV (for Excel/Sheets, sorting, filtering)
    and a plain-text table (for a quick eyeball read or pasting into
    a case note) - each showing only what you need to follow the
    money: from, to, amount, and date/time per hop. `label` is just
    "forward" or "backward" so the two directions don't overwrite
    each other's files when run back-to-back.

    Returns (csv_path, txt_path), or (None, None) if there were no
    paths to write.
    """
    if not paths_found:
        return None, None

    os.makedirs(CLEAN_OUTPUT_DIR, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_wallet = "".join(c for c in victim_wallet if c.isalnum())[:20]
    base_name = f"fund_trace_{label}_{safe_wallet}_{timestamp}"
    csv_path = os.path.join(CLEAN_OUTPUT_DIR, base_name + ".csv")
    txt_path = os.path.join(CLEAN_OUTPUT_DIR, base_name + ".txt")

    rows = dedupe_clean_rows(build_clean_rows(paths_found, victim_wallet))

    # ---- CSV (sortable/filterable in Excel or Google Sheets) ----
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=[
            "paths_label", "from", "to", "amount", "tx_time_utc",
            "tx_hash", "verify_url",
        ], extrasaction="ignore")
        writer.writerow({
            "paths_label": "paths", "from": "from", "to": "to",
            "amount": "amount", "tx_time_utc": "tx_time_utc",
            "tx_hash": "tx_hash", "verify_url": "verify_url",
        })
        writer.writerows(rows)

    # ---- Plain-text clean table (quick read / paste into notes) ----
    with open(txt_path, "w", encoding="utf-8") as txt_file:
        txt_file.write(f"FUND MOVEMENT TRACE - victim wallet {victim_wallet}\n")
        txt_file.write(f"Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}\n")
        txt_file.write("(Hops shared by more than one path are merged - see 'Paths' column)\n")
        txt_file.write("=" * 78 + "\n\n")

        txt_file.write(f"{'Paths':<7}{'From':<36}{'To':<36}\n")
        txt_file.write("-" * 78 + "\n")
        for row in rows:
            txt_file.write(f"{row['paths_label']:<7}{row['from']:<36}{row['to']:<36}\n")
            txt_file.write(f"     Amount : {row['amount']}\n")
            txt_file.write(f"     Time   : {row['tx_time_utc']} UTC\n")
            txt_file.write(f"     Verify : {row['verify_url']}\n\n")

    return csv_path, txt_path


def run_forward_trace(victim_wallet, target_wallets_arg, starting_amount=None):
    print("=" * 60)
    print("LINK TRACER - FORWARD trace from a victim/source wallet")
    print("=" * 60)
    print(f"Victim/source wallet: {victim_wallet}")
    print(f"Max hops            : {MAX_HOPS}")
    print(f"Max fan-out per hop  : {MAX_FANOUT_PER_HOP}")
    print(f"High fan-out flag at : {HIGH_FANOUT_THRESHOLD}+ distinct counterparties")
    if starting_amount is not None:
        print(f"Amount filter        : ON - tracking ~{starting_amount:g}, "
              f"auto-following hops between {AMOUNT_MATCH_MIN_RATIO:.0%} and "
              f"{AMOUNT_MATCH_MAX_RATIO:.0%} of the currently-tracked amount. "
              f"Everything outside that range is still reported below, not discarded.")
    else:
        print("Amount filter        : off (tracing every hop regardless of size)")

    global TARGET_ILLICIT_WALLETS
    if target_wallets_arg:
        TARGET_ILLICIT_WALLETS = target_wallets_arg

    target_wallets, target_lowercase_set = build_target_set(include_case_watchlist=True)
    print(f"Checking against {len(target_wallets)} illicit-wallet target(s).")

    paths_found, flagged_end_paths, addresses_visited, amount_filtered_paths = trace_forward(
        victim_wallet, target_lowercase_set, MAX_HOPS, starting_amount
    )

    print("\n" + "=" * 60)
    print("FORWARD TRACE COMPLETE")
    print("=" * 60)
    print(f"Unique wallets visited: {addresses_visited}")

    all_paths = (paths_found
                 + [path for path, _reason in flagged_end_paths]
                 + [path for path, _reason in amount_filtered_paths])

    if OUTPUT_STYLE == "simple":
        aliases = build_friendly_aliases(all_paths, victim_wallet) if all_paths else {}

        if paths_found:
            print(f"\n🚨 LINK FOUND: money from this wallet reached "
                  f"{len(paths_found)} flagged wallet path(s).")
            for index, path in enumerate(paths_found, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set)
        else:
            print(f"\n✅ No direct on-chain link found within {MAX_HOPS} step(s).")
            print("  This does NOT rule out a link - money can move off-chain, through an")
            print("  exchange, or across a bridge in ways this trace cannot follow.")

        if flagged_end_paths:
            print(f"\n🔶 {len(flagged_end_paths)} trail(s) reached a known or likely exchange/"
                  f"custodial wallet - a lead for legal process, not a dead end:")
            for index, (path, reason) in enumerate(flagged_end_paths, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set, reason=reason)
            _run_swap_correlation_for_flagged_paths(flagged_end_paths, "outgoing", "simple", aliases)

        if amount_filtered_paths:
            print(f"\n⚠️  {len(amount_filtered_paths)} step(s) were set aside for manual review "
                  f"because the amount moved didn't clearly match what's being tracked:")
            for index, (path, reason) in enumerate(amount_filtered_paths, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set, reason=reason)

        if aliases:
            print_alias_legend(aliases)
            print("\n  Full technical detail for everything above - transaction references,")
            print("  exact addresses, and raw timestamps - is available in Technical View.")

            diagram_path = write_visual_html(
                paths_found, flagged_end_paths, amount_filtered_paths,
                aliases, target_lowercase_set, victim_wallet, "forward", label="forward",
            )
            if diagram_path:
                print(f"\n📊 Visual diagram saved (open in any browser): {diagram_path}")
        else:
            print("\n  This does NOT rule out a link - see the LIMITATIONS section at the")
            print("  top of this script. Consider increasing MAX_HOPS, loosening the amount")
            print("  filter (or turning it off), or manually reviewing the wallets visited.")

    else:
        if paths_found:
            print(f"\n🚨 LINK FOUND: {len(paths_found)} path(s) from the victim wallet to a "
                  f"flagged illicit wallet.")
            for index, path in enumerate(paths_found, start=1):
                print_path(path, index)
            print("\n  Every hop above is independently verifiable at the linked block "
                  "explorer URL - check each one before relying on this in a report.")
        else:
            print(f"\nNo direct on-chain path found within {MAX_HOPS} hop(s), "
                  f"same-chain, using the counterparties checked.")

        if flagged_end_paths:
            print(f"\n🔶 {len(flagged_end_paths)} branch(es) ran into a known/likely custodial "
                  f"wallet (exchange/mixer) rather than a dead end - these are actionable leads, "
                  f"not a negative result:")
            for index, (path, reason) in enumerate(flagged_end_paths, start=1):
                print_trail_end_path(path, index, reason)
            _run_swap_correlation_for_flagged_paths(flagged_end_paths, "outgoing", "technical")
            print("\n  For any branch above, the next step is legal process (subpoena/production")
            print("  order) to the named or suspected custodian - on-chain data alone cannot see")
            print("  past it into their internal customer records.")

        if amount_filtered_paths:
            print(f"\n⚠️  {len(amount_filtered_paths)} hop(s) did NOT get auto-followed further "
                  f"because their amount didn't match what's being tracked - but every one is "
                  f"listed below so you can judge them yourself (the filter is a heuristic and "
                  f"can miss legitimate fee-adjusted, combined, or split transfers):")
            for index, (path, reason) in enumerate(amount_filtered_paths, start=1):
                print_trail_end_path(path, index, reason)
            print("\n  If any of these look like they ARE part of the same money, rerun with a")
            print("  lower AMOUNT_MATCH_MIN_RATIO, or without an amount filter at all, using the")
            print("  wallet shown as the new starting point.")

        if all_paths:
            print_clean_summary(all_paths, victim_wallet)

            csv_path, txt_path = write_clean_outputs(all_paths, victim_wallet, label="forward")
            print("\n  📄 Clean summary files also saved for easy tracing (includes every")
            print("  amount-filtered lead above too - nothing is left out of the export):")
            print(f"     CSV (Excel/Sheets) : {csv_path}")
            print(f"     Plain text table   : {txt_path}")
        else:
            print("\n  This does NOT rule out a link - see the LIMITATIONS section at the")
            print("  top of this script. Consider increasing MAX_HOPS, loosening the amount")
            print("  filter (or turning it off), or manually reviewing the wallets visited.")


def run_backward_trace(illicit_wallet, target_wallets_arg, starting_amount=None):
    print("=" * 60)
    print("LINK TRACER - BACKWARD trace from an illicit/flagged wallet")
    print("=" * 60)
    print(f"Illicit/flagged wallet: {illicit_wallet}")
    print(f"Max hops back         : {MAX_HOPS}")
    print(f"Max fan-out per hop    : {MAX_FANOUT_PER_HOP}")
    print(f"High fan-in flag at    : {HIGH_FANOUT_THRESHOLD}+ distinct counterparties")
    if starting_amount is not None:
        print(f"Amount filter          : ON - tracking ~{starting_amount:g}, "
              f"auto-following hops between {AMOUNT_MATCH_MIN_RATIO:.0%} and "
              f"{AMOUNT_MATCH_MAX_RATIO:.0%} of the currently-tracked amount. "
              f"Everything outside that range is still reported below, not discarded.")
    else:
        print("Amount filter          : off (tracing every hop regardless of size)")

    global TARGET_ILLICIT_WALLETS
    if target_wallets_arg:
        TARGET_ILLICIT_WALLETS = target_wallets_arg
        target_wallets, target_lowercase_set = build_target_set(include_case_watchlist=False)
        print(f"Checking against {len(target_wallets)} known source-wallet target(s).")
    else:
        target_wallets, target_lowercase_set = [], set()
        print("No source targets given - will report every backward trail found "
              "up to the hop limit (no specific wallet being checked for).")

    matched_paths, trail_end_paths, addresses_visited, amount_filtered_paths = trace_backward(
        illicit_wallet, target_lowercase_set, MAX_HOPS, starting_amount
    )

    print("\n" + "=" * 60)
    print("BACKWARD TRACE COMPLETE")
    print("=" * 60)
    print(f"Unique wallets visited: {addresses_visited}")

    all_paths = (matched_paths
                 + [path for path, _reason in trail_end_paths]
                 + [path for path, _reason in amount_filtered_paths])

    if OUTPUT_STYLE == "simple":
        aliases = build_friendly_aliases(all_paths, illicit_wallet) if all_paths else {}

        if matched_paths:
            print(f"\n🚨 LINK FOUND: this wallet's funds trace back to "
                  f"{len(matched_paths)} known source wallet path(s).")
            for index, path in enumerate(matched_paths, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set)

        if trail_end_paths:
            print(f"\nℹ️  {len(trail_end_paths)} trail(s) were followed as far back as the "
                  f"evidence allows, each labeled with why it stopped there:")
            for index, (path, reason) in enumerate(trail_end_paths, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set, reason=reason)
            _run_swap_correlation_for_flagged_paths(trail_end_paths, "incoming", "simple", aliases)
            print("\n  Trails ending at a named exchange/mixer are leads for legal process, not")
            print("  negative results. Trails ending with no further activity are your best")
            print("  current candidates for the true source of funds.")

        if amount_filtered_paths:
            print(f"\n⚠️  {len(amount_filtered_paths)} step(s) were set aside for manual review "
                  f"because the amount moved didn't clearly match what's being tracked:")
            for index, (path, reason) in enumerate(amount_filtered_paths, start=1):
                print_path_simple(path, index, aliases, target_lowercase_set, reason=reason)

        if aliases:
            print_alias_legend(aliases)
            print("\n  Full technical detail for everything above - transaction references,")
            print("  exact addresses, and raw timestamps - is available in Technical View.")

            diagram_path = write_visual_html(
                matched_paths, trail_end_paths, amount_filtered_paths,
                aliases, target_lowercase_set, illicit_wallet, "backward", label="backward",
            )
            if diagram_path:
                print(f"\n📊 Visual diagram saved (open in any browser): {diagram_path}")
        else:
            print(f"\n✅ No incoming on-chain activity found within {MAX_HOPS} step(s) back, "
                  f"same-chain.")
            print("  This wallet may have received funds cross-chain, via a mixer/bridge,")
            print("  or simply has no earlier same-chain history to follow.")

    else:
        if matched_paths:
            print(f"\n🚨 LINK FOUND: {len(matched_paths)} path(s) tracing this wallet's funds "
                  f"back to a known source wallet.")
            for index, path in enumerate(matched_paths, start=1):
                print_path(path, index)

        if trail_end_paths:
            print(f"\nℹ️  {len(trail_end_paths)} backward trail(s) followed as far as possible - "
                  f"each labeled with WHY it stopped there (known exchange/mixer, high fan-in "
                  f"custodial wallet, possible true source, or hop limit reached):")
            for index, (path, reason) in enumerate(trail_end_paths, start=1):
                print_trail_end_path(path, index, reason)
            _run_swap_correlation_for_flagged_paths(trail_end_paths, "incoming", "technical")
            print("\n  Branches ending at a named/likely exchange or mixer are leads for legal")
            print("  process, not negative results. Branches ending with no further activity")
            print("  are your best current candidates for the true source of funds.")

        if amount_filtered_paths:
            print(f"\n⚠️  {len(amount_filtered_paths)} hop(s) did NOT get auto-followed further "
                  f"because their amount didn't match what's being tracked - but every one is "
                  f"listed below so you can judge them yourself (the filter is a heuristic and "
                  f"can miss legitimate fee-adjusted, combined, or split transfers):")
            for index, (path, reason) in enumerate(amount_filtered_paths, start=1):
                print_trail_end_path(path, index, reason)
            print("\n  If any of these look like they ARE part of the same money, rerun with a")
            print("  lower AMOUNT_MATCH_MIN_RATIO, or without an amount filter at all, using the")
            print("  wallet shown as the new starting point.")

        if all_paths:
            print("\n  Every hop above is independently verifiable at the linked block "
                  "explorer URL - check each one before relying on this in a report.")

            print_clean_summary(all_paths, illicit_wallet)

            csv_path, txt_path = write_clean_outputs(all_paths, illicit_wallet, label="backward")
            print("\n  📄 Clean summary files also saved for easy tracing (includes every")
            print("  amount-filtered lead above too - nothing is left out of the export):")
            print(f"     CSV (Excel/Sheets) : {csv_path}")
            print(f"     Plain text table   : {txt_path}")
        else:
            print(f"\n✅ No incoming on-chain activity found within {MAX_HOPS} hop(s) back, "
                  f"same-chain.")
            print("  This wallet may have received funds cross-chain, via a mixer/bridge,")
            print("  or simply has no earlier same-chain history to follow.")


def run_link_trace(wallet, target_wallets_arg, direction="forward", starting_amount=None):
    direction = (direction or "forward").strip().lower()
    if direction not in ("forward", "backward", "both"):
        print(f"[!] Unknown direction '{direction}' - defaulting to 'forward'. "
              f"(Valid options: forward, backward, both)")
        direction = "forward"

    if direction in ("forward", "both"):
        run_forward_trace(wallet, target_wallets_arg, starting_amount)
    if direction == "both":
        print("\n")
    if direction in ("backward", "both"):
        run_backward_trace(wallet, target_wallets_arg, starting_amount)


# ====================================================================
# SECTION 6: SCRIPT ENTRY POINT
# ====================================================================
if __name__ == "__main__":
    cli_args = sys.argv[1:]

    active_wallet = cli_args[0].strip() if len(cli_args) >= 1 and cli_args[0].strip() else VICTIM_WALLET
    active_target_wallets = None
    if len(cli_args) >= 2 and cli_args[1].strip():
        active_target_wallets = [part.strip() for part in cli_args[1].split(",") if part.strip()]
    active_direction = cli_args[2].strip() if len(cli_args) >= 3 and cli_args[2].strip() else DIRECTION

    active_starting_amount = STARTING_TRACE_AMOUNT
    if len(cli_args) >= 4 and cli_args[3].strip():
        try:
            active_starting_amount = float(cli_args[3].strip())
        except ValueError:
            print(f"[!] Could not read '{cli_args[3]}' as a starting amount - ignoring it "
                  f"(amount filtering will stay off).")
            active_starting_amount = None

    if is_valid_ethereum_address(active_wallet) and ETHERSCAN_API_KEY == "":
        print("⚠️  Please add your Etherscan API key before tracing an Ethereum wallet.")
        print("    (Bitcoin and XRP wallets don't need one.)")
    else:
        run_link_trace(active_wallet, active_target_wallets, active_direction, active_starting_amount)
