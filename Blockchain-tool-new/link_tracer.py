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
case_watchlist.json file - the same file the desktop dashboard also
reads from/writes to).

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
    wallets: sign up at etherscan.io, go to your account's API Keys
    page, and create one - then either paste it below or set it as the
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
import auth  # only for _get_db_connection - reuses the same DB connection setup as auth.py
from datetime import datetime, timezone, timedelta


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# ====================================================================

ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ")
XRPL_RPC_URL = "https://s1.ripple.com:51234"

# --------------------------------------------------------------
# BITHOMP - optional. Used two ways: (1) XRP explorer links point to
# bithomp.com instead of livenet.xrpl.org, no key needed for that.
# (2) If BITHOMP_API_KEY is set, an XRP address NOT already in
# known_entities gets a live lookup against Bithomp's account/service
# database as a fallback - auto-recognizing labeled exchanges/services
# your own known_entities list hasn't been told about yet. Free tier:
# 10 requests/min, 2,000/day, no card required - get a key at
# https://bithomp.com/developer. Leave BITHOMP_API_KEY unset to skip
# this fallback entirely (known_entities/deposit-map-only detection,
# same as before).
# --------------------------------------------------------------
BITHOMP_API_KEY = os.environ.get("BITHOMP_API_KEY", "")
BITHOMP_API_BASE = "https://bithomp.com/api/v2"
_bithomp_lookup_cache = {}  # {address_lower: result_dict_or_None} - avoids repeat calls within one run/trace

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
# SOLANA. Public RPC only (no key needed, but rate-limited) - covers
# native SOL transfers plus USDT/USDC (SPL token transfers). See the
# module notes near is_valid_solana_address() for two honest
# limitations: address case-sensitivity, and SPL transfers reporting
# a token account rather than the wallet's main address.
# --------------------------------------------------------------
SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com"
SOLANA_TRACE_MAX_SIGNATURES = 25  # per wallet, per hop - public RPC is rate-limited, keep this modest
SOLANA_SECONDS_BETWEEN_REQUESTS = 2.0  # public RPC rate-limits getSignaturesForAddress/getTransaction hard - far stricter than the other chains' APIs
SOLANA_MAX_RETRIES = 3
USDC_SPL_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDT_SPL_MINT = "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB"
SOLANA_STABLECOIN_MINTS = {USDC_SPL_MINT: "USDC", USDT_SPL_MINT: "USDT"}

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
# case_watchlist.json file. Overridden/extended by a second,
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
# How many pages of history to fetch per wallet, per hop, before
# giving up. Without this, only the FIRST page (the most recent
# ~25-50 transactions, or whatever each API's default page is) gets
# checked - which silently misses genuine activity that's simply
# older than that, especially for busy addresses (e.g. a bridge/swap
# collection wallet receiving many small deposits between its
# occasional outgoing sweeps). Raising these finds more history at
# the cost of more API calls per hop - MAX_HOPS x MAX_FANOUT_PER_HOP
# x these page counts is the real cost of a trace, so keep them
# reasonable rather than maxing everything out by default.
# --------------------------------------------------------------
BITCOIN_TRACE_MAX_PAGES = 4   # ~25-50 tx per page (mempool.space)
XRP_TRACE_MAX_PAGES = 4       # 50 tx per page (XRPL)
TRON_TRACE_MAX_PAGES = 4      # 50 tx per page (TronGrid)
ETHEREUM_TRACE_MAX_PAGES = 4  # 1000 tx per page (Etherscan)

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
# KNOWN OP_RETURN PATTERNS - for Bitcoin services that ROTATE their
# receiving address on every transaction (common for bridges/no-KYC
# swap services), so exact-address matching in known_entities.json
# can never keep up. Many of these services embed a consistent
# routing message in the transaction's OP_RETURN output regardless of
# which one-time address received the funds - e.g. bridgers.xyz
# embeds something like "...to:USDT(TRON):<destination>" in every
# transaction it processes. Matching on THAT pattern recognizes the
# service even on an address never seen before.
# --------------------------------------------------------------
KNOWN_OP_RETURN_PATTERNS_FILE = os.path.join(TOOLKIT_DATA_DIR, "known_op_return_patterns.json")

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
# EXACT AMOUNT MODE - when you know the specific suspect figure (a
# stolen sum, say) and want ONLY that amount followed, not the wider
# 10%-105% band above. Still allows a razor-thin buffer for on-chain
# network fees (funds moving hop to hop always lose a tiny bit to
# fees) - this is NOT a meaningful tolerance, just floating-point/fee
# rounding safety. The amount can never GROW under this mode, since
# that would mean unrelated funds joined in, breaking the "trace only
# this exact sum" assumption entirely.
# --------------------------------------------------------------
EXACT_AMOUNT_MATCH_MIN_RATIO = 0.995
EXACT_AMOUNT_MATCH_MAX_RATIO = 1.001

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
COINGECKO_COIN_ID_BY_CHAIN = {"ethereum": "ethereum", "bitcoin": "bitcoin", "xrp": "ripple", "solana": "solana"}

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

_BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def _base58_decode(s):
    num = 0
    for char in s:
        digit = _BASE58_ALPHABET.find(char)
        if digit == -1:
            raise ValueError("invalid base58 character")
        num = num * 58 + digit
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big") if num else b""
    leading_zeros = len(s) - len(s.lstrip("1"))
    return b"\x00" * leading_zeros + combined


def is_valid_solana_address(address):
    """Solana addresses have no distinguishing prefix (unlike Bitcoin's
    bc1/1/3, XRP's r, Tron's T) - the only real check is that it's valid
    base58 decoding to exactly 32 bytes (a public key). Checked LAST in
    detect_chain(), after every other chain's format check, since a
    plausible-looking base58 string could otherwise be mistaken for a
    Solana address."""
    if not (32 <= len(address) <= 44):
        return False
    if not all(c in _BASE58_ALPHABET for c in address):
        return False
    try:
        return len(_base58_decode(address)) == 32
    except ValueError:
        return False

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

def detect_chain(address):
    if is_valid_ethereum_address(address):
        return "ethereum"
    if is_valid_bitcoin_address(address):
        return "bitcoin"
    if is_valid_xrp_address(address):
        return "xrp"
    if is_valid_tron_address(address):
        return "tron"
    if is_valid_solana_address(address):
        return "solana"
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
    per_page = 1000
    all_txs = []

    for page_number in range(1, ETHEREUM_TRACE_MAX_PAGES + 1):
        params = {
            "chainid": "1", "module": "account", "action": "txlist",
            "address": address, "sort": "desc", "apikey": ETHERSCAN_API_KEY,
            "page": page_number, "offset": per_page,
        }
        try:
            response = requests.get(url, params=params, timeout=15)
            data = response.json()
        except requests.exceptions.RequestException as error:
            print(f"    ⚠️  Could not reach Etherscan: {error}")
            break

        if data.get("status") != "1":
            if data.get("message") != "No transactions found":
                print(f"    ⚠️  Etherscan error: {data.get('message')}")
            break

        page = data.get("result", [])
        all_txs.extend(page)
        if len(page) < per_page:
            break  # that was the last page
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx in all_txs:
        if tx.get("from", "").lower() != address.lower():
            continue
        to_address = tx.get("to", "")
        if not to_address:
            continue  # contract creation, no simple recipient
        unique_counterparties.add(to_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue
        eth_value = int(tx.get("value", 0)) / 1_000_000_000_000_000_000
        hop_info = {
            "counterparty": to_address,
            "tx_hash": tx.get("hash"),
            "tx_time": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc),
            "amount_label": f"{eth_value:.6f} ETH",
            "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
        }
        pattern_match = find_message_pattern_match_in_eth_tx(tx)
        if pattern_match:
            hop_info["pattern_match"] = pattern_match
        results.append(hop_info)
    return results, len(unique_counterparties)


def get_outgoing_bitcoin(address):
    all_txs = []
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        page = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach mempool.space: {error}")
        return [], 0

    all_txs.extend(page)
    pages_fetched = 1
    while page and pages_fetched < BITCOIN_TRACE_MAX_PAGES:
        last_txid = page[-1].get("txid")
        if not last_txid:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)
        next_url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
        try:
            response = requests.get(next_url, timeout=15)
            response.raise_for_status()
            page = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not fetch further history: {error}")
            break
        if not page:
            break
        all_txs.extend(page)
        pages_fetched += 1

    results = []
    unique_counterparties = set()
    for tx in all_txs:
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

        # Check ONCE per transaction (not per output) whether this tx's
        # OP_RETURN matches a known service signature - see SECTION on
        # KNOWN OP_RETURN PATTERNS. This is what lets a rotating-address
        # service (a new address every transaction) still get recognized.
        pattern_match = find_op_return_pattern_match_in_tx(tx)

        for output in tx.get("vout", []):
            recipient = output.get("scriptpubkey_address")
            # Skip change back to the same address - not a new hop.
            if not recipient or recipient.lower() == address.lower():
                continue
            unique_counterparties.add(recipient.lower())
            if len(results) < MAX_FANOUT_PER_HOP:
                hop_info = {
                    "counterparty": recipient,
                    "tx_hash": tx.get("txid"),
                    "tx_time": tx_time,
                    "amount_label": f"{output.get('value', 0) / 100_000_000:.8f} BTC",
                    "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                }
                if pattern_match:
                    hop_info["pattern_match"] = pattern_match
                results.append(hop_info)
    return results, len(unique_counterparties)


RIPPLE_EPOCH_OFFSET_SECONDS = 946684800


def get_outgoing_xrp(address):
    all_txs = []
    marker = None
    pages_fetched = 0
    has_more_pages = False

    while pages_fetched < XRP_TRACE_MAX_PAGES:
        params = {
            "account": address, "ledger_index_min": -1, "ledger_index_max": -1,
            "limit": 50, "forward": False,
        }
        if marker:
            params["marker"] = marker
        try:
            response = requests.post(XRPL_RPC_URL, json={"method": "account_tx", "params": [params]}, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not reach the XRP Ledger node: {error}")
            break

        result = data.get("result", {})
        if result.get("status") != "success":
            print(f"    ⚠️  XRP Ledger error: {result.get('error_message') or result.get('error')}")
            break

        all_txs.extend(result.get("transactions", []))
        pages_fetched += 1
        marker = result.get("marker")
        has_more_pages = bool(marker) and pages_fetched >= XRP_TRACE_MAX_PAGES
        if not marker:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx_entry in all_txs:
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
            hop_info = {
                "counterparty": destination,
                "tx_hash": tx.get("hash"),
                "tx_time": tx_time,
                "amount_label": amount_label,
                "explorer_url": f"https://bithomp.com/explorer/{tx.get('hash')}",
            }
            pattern_match = find_message_pattern_match_in_xrp_tx(tx)
            if pattern_match:
                hop_info["pattern_match"] = pattern_match
            results.append(hop_info)

    fanout_count = len(unique_counterparties) + (HIGH_FANOUT_THRESHOLD if has_more_pages else 0)
    return results, fanout_count


def get_outgoing_tron(address):
    """
    PLAIN ENGLISH: Fetches this address's recent USDT (TRC-20) transfer
    history from TronGrid and returns the ones where THIS address was
    the sender. Same return shape as every other chain's outgoing
    lookup, so it plugs straight into the existing trace logic.
    """
    all_txs = []
    fingerprint = None
    pages_fetched = 0

    while pages_fetched < TRON_TRACE_MAX_PAGES:
        url = f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20"
        params = {"contract_address": USDT_TRC20_CONTRACT, "limit": 50, "only_confirmed": "true"}
        if fingerprint:
            params["fingerprint"] = fingerprint
        headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
        try:
            response = requests.get(url, params=params, headers=headers, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not reach TronGrid: {error}")
            break

        if data.get("success") is False:
            print(f"    ⚠️  TronGrid error: {data.get('error', 'unknown error')}")
            break

        page = data.get("data", [])
        all_txs.extend(page)
        pages_fetched += 1
        fingerprint = (data.get("meta") or {}).get("fingerprint")
        if not fingerprint or not page:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx in all_txs:
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

def _solana_rpc_call(method, params):
    for attempt in range(SOLANA_MAX_RETRIES):
        try:
            response = requests.post(SOLANA_RPC_URL, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not reach the Solana RPC: {error}")
            return None

        if "error" in data:
            message = data["error"].get("message", str(data["error"]))
            if "Too many requests" in message and attempt < SOLANA_MAX_RETRIES - 1:
                wait = SOLANA_SECONDS_BETWEEN_REQUESTS * (attempt + 2)  # back off progressively harder
                print(f"    ⏳ Solana RPC rate-limited - waiting {wait:.1f}s and retrying...")
                time.sleep(wait)
                continue
            print(f"    ⚠️  Solana RPC error: {message}")
            return None

        return data.get("result")
    return None


def _get_solana_signatures(address, limit):
    all_signatures = []
    before = None
    while len(all_signatures) < limit:
        params_options = {"limit": min(50, limit - len(all_signatures))}
        if before:
            params_options["before"] = before
        result = _solana_rpc_call("getSignaturesForAddress", [address, params_options])
        if not result:
            break
        all_signatures.extend(result)
        if len(result) < params_options["limit"]:
            break
        before = result[-1]["signature"]
        time.sleep(SOLANA_SECONDS_BETWEEN_REQUESTS)
    return all_signatures[:limit]


def _parse_solana_tx_hops(tx, signature, address, want_direction):
    """Returns hop dicts for this ONE transaction, native SOL (via
    instructions) and SPL USDT/USDC (via pre/post token balance diff -
    more reliable than instruction parsing, since it correctly resolves
    to the wallet OWNER rather than the intermediate token account)."""
    hops = []
    if not tx or not tx.get("blockTime"):
        return hops
    tx_time = datetime.fromtimestamp(tx["blockTime"], tz=timezone.utc)
    explorer_url = f"https://solscan.io/tx/{signature}"
    meta = tx.get("meta") or {}

    # ---- Native SOL, via top-level + inner "system transfer" instructions ----
    message = (tx.get("transaction") or {}).get("message") or {}
    inner = meta.get("innerInstructions", []) or []
    all_instructions = list(message.get("instructions", [])) + [ix for group in inner for ix in group.get("instructions", [])]
    for ix in all_instructions:
        parsed = ix.get("parsed")
        if not isinstance(parsed, dict) or parsed.get("type") != "transfer" or ix.get("program") != "system":
            continue
        info = parsed.get("info", {})
        source, destination, lamports = info.get("source"), info.get("destination"), info.get("lamports", 0)
        if want_direction == "outgoing" and source == address and destination:
            hops.append({"counterparty": destination, "tx_hash": signature, "tx_time": tx_time,
                         "amount_label": f"{lamports / 1_000_000_000:.9f} SOL", "explorer_url": explorer_url})
        elif want_direction == "incoming" and destination == address and source:
            hops.append({"counterparty": source, "tx_hash": signature, "tx_time": tx_time,
                         "amount_label": f"{lamports / 1_000_000_000:.9f} SOL", "explorer_url": explorer_url})

    # ---- USDT/USDC (SPL), via pre/post token balance diff per owner ----
    pre_balances = {(b["owner"], b["mint"]): b for b in meta.get("preTokenBalances", []) if b.get("mint") in SOLANA_STABLECOIN_MINTS}
    post_balances = {(b["owner"], b["mint"]): b for b in meta.get("postTokenBalances", []) if b.get("mint") in SOLANA_STABLECOIN_MINTS}

    for (owner, mint), post_entry in post_balances.items():
        if owner != address:
            continue
        pre_entry = pre_balances.get((owner, mint))
        pre_amount = float((pre_entry or {}).get("uiTokenAmount", {}).get("uiAmount") or 0)
        post_amount = float(post_entry.get("uiTokenAmount", {}).get("uiAmount") or 0)
        delta = post_amount - pre_amount
        if abs(delta) < 1e-9:
            continue
        symbol = SOLANA_STABLECOIN_MINTS[mint]

        if want_direction == "outgoing" and delta < 0:
            counterparty = next((o for (o, m) in post_balances if m == mint and o != address), None)
            if counterparty:
                hops.append({"counterparty": counterparty, "tx_hash": signature, "tx_time": tx_time,
                             "amount_label": f"{abs(delta):.6f} {symbol}", "explorer_url": explorer_url})
        elif want_direction == "incoming" and delta > 0:
            counterparty = next((o for (o, m) in post_balances if m == mint and o != address), None)
            if counterparty:
                hops.append({"counterparty": counterparty, "tx_hash": signature, "tx_time": tx_time,
                             "amount_label": f"{delta:.6f} {symbol}", "explorer_url": explorer_url})

    return hops


def _get_solana_hops(address, want_direction):
    signatures = _get_solana_signatures(address, SOLANA_TRACE_MAX_SIGNATURES)
    results = []
    unique_counterparties = set()
    for sig_entry in signatures:
        signature = sig_entry.get("signature")
        if not signature or sig_entry.get("err"):
            continue  # skip failed transactions
        tx = _solana_rpc_call("getTransaction", [signature, {"encoding": "jsonParsed", "maxSupportedTransactionVersion": 0}])
        time.sleep(SOLANA_SECONDS_BETWEEN_REQUESTS)
        for hop in _parse_solana_tx_hops(tx, signature, address, want_direction):
            unique_counterparties.add(hop["counterparty"].lower())
            if len(results) < MAX_FANOUT_PER_HOP:
                results.append(hop)
    return results, len(unique_counterparties)


def get_outgoing_solana(address):
    return _get_solana_hops(address, "outgoing")


def get_incoming_solana(address):
    return _get_solana_hops(address, "incoming")


def get_outgoing_counterparties(chain, address):
    if chain == "ethereum":
        return get_outgoing_ethereum(address)
    if chain == "bitcoin":
        return get_outgoing_bitcoin(address)
    if chain == "xrp":
        return get_outgoing_xrp(address)
    if chain == "tron":
        return get_outgoing_tron(address)
    if chain == "solana":
        return get_outgoing_solana(address)
    return [], 0


# ====================================================================
# SECTION 3B: PER-CHAIN "WHO SENT TO THIS ADDRESS?" LOOKUPS (REVERSE)
# Same return shape as Section 3, but counterparty is the SENDER,
# not the recipient - this is what powers backward tracing.
# ====================================================================

def get_incoming_ethereum(address):
    url = "https://api.etherscan.io/v2/api"
    per_page = 1000
    all_txs = []

    for page_number in range(1, ETHEREUM_TRACE_MAX_PAGES + 1):
        params = {
            "chainid": "1", "module": "account", "action": "txlist",
            "address": address, "sort": "desc", "apikey": ETHERSCAN_API_KEY,
            "page": page_number, "offset": per_page,
        }
        try:
            response = requests.get(url, params=params, timeout=15)
            data = response.json()
        except requests.exceptions.RequestException as error:
            print(f"    ⚠️  Could not reach Etherscan: {error}")
            break

        if data.get("status") != "1":
            if data.get("message") != "No transactions found":
                print(f"    ⚠️  Etherscan error: {data.get('message')}")
            break

        page = data.get("result", [])
        all_txs.extend(page)
        if len(page) < per_page:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx in all_txs:
        if tx.get("to", "").lower() != address.lower():
            continue
        from_address = tx.get("from", "")
        if not from_address:
            continue
        unique_counterparties.add(from_address.lower())
        if len(results) >= MAX_FANOUT_PER_HOP:
            continue
        eth_value = int(tx.get("value", 0)) / 1_000_000_000_000_000_000
        hop_info = {
            "counterparty": from_address,
            "tx_hash": tx.get("hash"),
            "tx_time": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc),
            "amount_label": f"{eth_value:.6f} ETH",
            "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
        }
        pattern_match = find_message_pattern_match_in_eth_tx(tx)
        if pattern_match:
            hop_info["pattern_match"] = pattern_match
        results.append(hop_info)
    return results, len(unique_counterparties)


def get_incoming_bitcoin(address):
    """
    NOTE: a Bitcoin transaction can combine multiple people's coins
    into one set of inputs. Where a payment TO this address came from
    a transaction with more than one input address, ALL of those
    input addresses are reported as possible senders rather than
    guessing which one is "the real" one. Treat multi-input
    attributions as leads to verify by hand.
    """
    all_txs = []
    url = f"https://mempool.space/api/address/{address}/txs"
    try:
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        page = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach mempool.space: {error}")
        return [], 0

    all_txs.extend(page)
    pages_fetched = 1
    while page and pages_fetched < BITCOIN_TRACE_MAX_PAGES:
        last_txid = page[-1].get("txid")
        if not last_txid:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)
        next_url = f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
        try:
            response = requests.get(next_url, timeout=15)
            response.raise_for_status()
            page = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not fetch further history: {error}")
            break
        if not page:
            break
        all_txs.extend(page)
        pages_fetched += 1

    results = []
    unique_counterparties = set()
    for tx in all_txs:
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
        pattern_match = find_op_return_pattern_match_in_tx(tx)

        for sender in senders:
            unique_counterparties.add(sender.lower())
            if len(results) < MAX_FANOUT_PER_HOP:
                hop_info = {
                    "counterparty": sender,
                    "tx_hash": tx.get("txid"),
                    "tx_time": tx_time,
                    "amount_label": amount_label,
                    "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                }
                if pattern_match:
                    hop_info["pattern_match"] = pattern_match
                results.append(hop_info)
    return results, len(unique_counterparties)


def get_incoming_xrp(address):
    all_txs = []
    marker = None
    pages_fetched = 0
    has_more_pages = False

    while pages_fetched < XRP_TRACE_MAX_PAGES:
        params = {
            "account": address, "ledger_index_min": -1, "ledger_index_max": -1,
            "limit": 50, "forward": False,
        }
        if marker:
            params["marker"] = marker
        try:
            response = requests.post(XRPL_RPC_URL, json={"method": "account_tx", "params": [params]}, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not reach the XRP Ledger node: {error}")
            break

        result = data.get("result", {})
        if result.get("status") != "success":
            print(f"    ⚠️  XRP Ledger error: {result.get('error_message') or result.get('error')}")
            break

        all_txs.extend(result.get("transactions", []))
        pages_fetched += 1
        marker = result.get("marker")
        has_more_pages = bool(marker) and pages_fetched >= XRP_TRACE_MAX_PAGES
        if not marker:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx_entry in all_txs:
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
            hop_info = {
                "counterparty": sender,
                "tx_hash": tx.get("hash"),
                "tx_time": tx_time,
                "amount_label": amount_label,
                "explorer_url": f"https://bithomp.com/explorer/{tx.get('hash')}",
            }
            pattern_match = find_message_pattern_match_in_xrp_tx(tx)
            if pattern_match:
                hop_info["pattern_match"] = pattern_match
            results.append(hop_info)

    fanout_count = len(unique_counterparties) + (HIGH_FANOUT_THRESHOLD if has_more_pages else 0)
    return results, fanout_count


def get_incoming_tron(address):
    """Same as get_outgoing_tron but for INCOMING USDT transfers (this
    address as the recipient) - powers backward tracing."""
    all_txs = []
    fingerprint = None
    pages_fetched = 0

    while pages_fetched < TRON_TRACE_MAX_PAGES:
        url = f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20"
        params = {"contract_address": USDT_TRC20_CONTRACT, "limit": 50, "only_confirmed": "true"}
        if fingerprint:
            params["fingerprint"] = fingerprint
        headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
        try:
            response = requests.get(url, params=params, headers=headers, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            print(f"    ⚠️  Could not reach TronGrid: {error}")
            break

        if data.get("success") is False:
            print(f"    ⚠️  TronGrid error: {data.get('error', 'unknown error')}")
            break

        page = data.get("data", [])
        all_txs.extend(page)
        pages_fetched += 1
        fingerprint = (data.get("meta") or {}).get("fingerprint")
        if not fingerprint or not page:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    results = []
    unique_counterparties = set()
    for tx in all_txs:
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
    if chain == "solana":
        return get_incoming_solana(address)
    return [], 0


# ====================================================================
# GAS-FUNDING-SOURCE CLUSTERING
# ====================================================================
# WHAT THIS DOES (plain English): most wallets need a small amount of
# the chain's native currency before they can do ANYTHING else - ETH
# to pay gas on Ethereum, XRP to meet the ledger's reserve requirement
# to even activate an account. A common real-world pattern: someone
# controlling many wallets (a scammer spreading funds across
# addresses, a service generating many deposit addresses) funds each
# new wallet's initial gas from the SAME source wallet. If several
# "unrelated" addresses all trace back to the same funding source,
# that's a genuine clustering signal - not proof of common ownership,
# but a real, commonly-used forensic lead.
#
# CURRENTLY SUPPORTED: Ethereum and XRP only. Bitcoin has no
# equivalent concept (fees come directly out of what's being spent,
# not a separate funding step). Tron's native TRX funding isn't
# covered - this toolkit's Tron support is scoped to USDT-TRC20
# transfers only, and native TRX transfers use a different TronGrid
# endpoint this doesn't currently fetch.
# ====================================================================

def find_first_funding_transaction_ethereum(address):
    """
    PLAIN ENGLISH: Finds this address's VERY FIRST incoming ETH
    transaction (value > 0, not a zero-value contract call) - the
    "gas funding" event. Returns None if it can't be determined (no
    ETH ever received, or the first activity was something else
    entirely, like receiving an ERC-20 token with no ETH funding at all).
    """
    url = "https://api.etherscan.io/v2/api"
    try:
        response = requests.get(url, params={
            "chainid": "1", "module": "account", "action": "txlist", "address": address,
            "sort": "asc", "page": 1, "offset": 50, "apikey": ETHERSCAN_API_KEY,
        }, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        print(f"    ⚠️  Could not reach Etherscan: {error}")
        return None

    if data.get("status") != "1":
        return None

    for tx in data.get("result", []):
        if tx.get("to", "").lower() != address.lower():
            continue
        try:
            eth_value = int(tx.get("value", 0)) / 1_000_000_000_000_000_000
        except (TypeError, ValueError):
            continue
        if eth_value <= 0:
            continue  # a zero-value contract call, not actual funding
        from_address = tx.get("from")
        if not from_address:
            continue
        return {
            "funding_address": from_address,
            "amount_label": f"{eth_value:.6f} ETH",
            "tx_time": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc),
            "tx_hash": tx.get("hash"),
            "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
        }
    return None


def find_first_funding_transaction_xrp(address):
    """Same idea as the Ethereum version, but for XRP's account
    activation - the transaction that first funded this address past
    the ledger's reserve requirement."""
    try:
        response = requests.post(XRPL_RPC_URL, json={"method": "account_tx", "params": [{
            "account": address, "ledger_index_min": -1, "ledger_index_max": -1,
            "limit": 20, "forward": True,  # oldest first - the opposite of the tracer's usual newest-first fetches
        }]}, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        print(f"    ⚠️  Could not reach the XRP Ledger node: {error}")
        return None

    result = data.get("result", {})
    if result.get("status") != "success":
        return None

    for tx_entry in result.get("transactions", []):
        if not tx_entry.get("validated"):
            continue
        tx = tx_entry.get("tx", {})
        meta = tx_entry.get("meta", {})
        if tx.get("TransactionType") != "Payment":
            continue
        if tx.get("Destination", "").lower() != address.lower():
            continue
        if meta.get("TransactionResult") != "tesSUCCESS":
            continue
        delivered = meta.get("delivered_amount", tx.get("Amount"))
        if not isinstance(delivered, str):
            continue  # an issued-token payment, not XRP itself - not a funding/activation event
        from_address = tx.get("Account")
        if not from_address:
            continue
        ripple_ts = tx.get("date")
        tx_time = (
            datetime.fromtimestamp(ripple_ts + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc)
            if ripple_ts is not None else datetime.now(timezone.utc)
        )
        return {
            "funding_address": from_address,
            "amount_label": f"{int(delivered) / 1_000_000:.6f} XRP",
            "tx_time": tx_time,
            "tx_hash": tx.get("hash"),
            "explorer_url": f"https://bithomp.com/explorer/{tx.get('hash')}",
        }
    return None


def find_first_funding_transaction(chain, address):
    """Dispatches to the right chain's funding-source lookup. Returns
    None for chains without one (Bitcoin, Tron) or if none was found."""
    if chain == "ethereum":
        return find_first_funding_transaction_ethereum(address)
    if chain == "xrp":
        return find_first_funding_transaction_xrp(address)
    return None


def check_common_funding_source(addresses):
    """
    PLAIN ENGLISH: Given a LIST of addresses, finds each one's
    gas-funding source and groups the addresses that share the SAME
    one. A shared funding source is a real clustering lead - it
    suggests common control - but it is NOT proof; verify manually,
    the same way any other heuristic lead in this toolkit should be.

    Returns {"per_address": [...], "clusters": [...]} - per_address
    has one entry per input address (chain, funding details or a
    reason none was found); clusters groups addresses that share an
    identical funding source address, skipping any group of size 1
    (a funding source shared by nobody else isn't a cluster).
    """
    per_address = []
    for raw_address in addresses:
        address = raw_address.strip()
        if not address:
            continue
        chain = detect_chain(address)
        if chain is None:
            per_address.append({
                "address": address, "chain": None, "funding": None,
                "message": "Not a recognized address for any supported chain.",
            })
            continue
        if chain not in ("ethereum", "xrp"):
            per_address.append({
                "address": address, "chain": chain, "funding": None,
                "message": f"Gas-funding lookup isn't supported for {chain} yet - "
                           f"see the module notes for why.",
            })
            continue

        funding = find_first_funding_transaction(chain, address)
        if funding is None:
            per_address.append({
                "address": address, "chain": chain, "funding": None,
                "message": "No funding transaction found - this may be the true "
                           "original funding source itself, or its earliest activity "
                           "wasn't a native-currency transfer.",
            })
        else:
            per_address.append({"address": address, "chain": chain, "funding": funding, "message": None})
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    # Group by (chain, funding source address) - a shared funding
    # source only means something if it's genuinely the SAME chain's
    # SAME address, not a coincidental format collision across chains.
    groups = {}
    for entry in per_address:
        if entry["funding"] is None:
            continue
        key = (entry["chain"], entry["funding"]["funding_address"].lower())
        groups.setdefault(key, []).append(entry["address"])

    clusters = [
        {"chain": chain, "funding_address": funding_addr, "addresses": member_addresses}
        for (chain, funding_addr), member_addresses in groups.items()
        if len(member_addresses) > 1
    ]

    return {"per_address": per_address, "clusters": clusters}


def get_incoming_counterparties(chain, address):
    if chain == "ethereum":
        return get_incoming_ethereum(address)
    if chain == "bitcoin":
        return get_incoming_bitcoin(address)
    if chain == "xrp":
        return get_incoming_xrp(address)
    if chain == "tron":
        return get_incoming_tron(address)
    if chain == "solana":
        return get_incoming_solana(address)
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


def manual_check_swap_correlation(address, direction="both"):
    """
    PLAIN ENGLISH: Given a SINGLE wallet (not necessarily one found
    during a multi-hop trace), checks whether it went THROUGH a known
    non-KYC instant-swap service or cross-chain bridge - i.e. answers
    "did this wallet deposit into one of these, and if so where did
    the money likely come back out (possibly a different chain)?" and/
    or "did this wallet receive a payout FROM one, and if so where did
    the money likely come IN from?".

    This is the standalone version of what a full link_trace already
    does automatically when it happens to hit a flagged instant_swap/
    bridge entity mid-trace - but here you don't have to run a whole
    multi-hop trace first just to check one specific wallet.

    direction:
      "outgoing" - only checks whether this wallet DEPOSITED into a
                   known service (looking for a payout on the other side).
      "incoming" - only checks whether this wallet RECEIVED a payout
                   FROM a known service (looking for the deposit that funded it).
      "both"     - checks both directions (default).

    Returns a dict with "deposits_found" and/or "payouts_found" lists -
    each entry names the service, the hop that touched it, and any
    correlated candidates on the other side (same shape as
    find_correlated_counterpart's results - HEURISTIC LEADS, not proof).
    """
    chain = detect_chain(address)
    if chain is None:
        return {
            "address": address, "chain": None,
            "message": "Not a recognized Ethereum, Bitcoin, XRP, or Tron address.",
        }

    deposits_found = []
    payouts_found = []

    if direction in ("outgoing", "both"):
        outgoing_hops, _fanout = get_outgoing_counterparties(chain, address)
        seen_entities = set()
        for hop_info in outgoing_hops:
            entity = check_known_entity(hop_info["counterparty"]) or hop_info.get("pattern_match")
            if not entity or entity.get("type") not in ("instant_swap", "bridge"):
                continue
            if entity["name"] in seen_entities:
                continue  # one correlation attempt per distinct service is enough
            seen_entities.add(entity["name"])

            candidates = find_correlated_counterpart(
                entity["name"], hop_info["amount_label"], chain, hop_info["tx_time"], "outgoing",
            )
            deposits_found.append({
                "service_name": entity["name"],
                "service_type": entity["type"],
                "deposit_tx_hash": hop_info["tx_hash"],
                "deposit_time_utc": hop_info["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "deposit_amount": hop_info["amount_label"],
                "explorer_url": hop_info["explorer_url"],
                "candidates": [
                    {
                        "chain": c["chain"], "counterparty": c["counterparty"], "amount": c["amount_label"],
                        "tx_time_utc": c["tx_time"].strftime("%Y-%m-%d %H:%M:%S"), "tx_hash": c["tx_hash"],
                        "explorer_url": c["explorer_url"], "minutes_after": c["minutes_diff"],
                        "usd_match_ratio": c["usd_match_ratio"],
                    }
                    for c in candidates
                ],
            })

    if direction in ("incoming", "both"):
        incoming_hops, _fanout = get_incoming_counterparties(chain, address)
        seen_entities = set()
        for hop_info in incoming_hops:
            entity = check_known_entity(hop_info["counterparty"]) or hop_info.get("pattern_match")
            if not entity or entity.get("type") not in ("instant_swap", "bridge"):
                continue
            if entity["name"] in seen_entities:
                continue
            seen_entities.add(entity["name"])

            candidates = find_correlated_counterpart(
                entity["name"], hop_info["amount_label"], chain, hop_info["tx_time"], "incoming",
            )
            payouts_found.append({
                "service_name": entity["name"],
                "service_type": entity["type"],
                "payout_tx_hash": hop_info["tx_hash"],
                "payout_time_utc": hop_info["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
                "payout_amount": hop_info["amount_label"],
                "explorer_url": hop_info["explorer_url"],
                "candidates": [
                    {
                        "chain": c["chain"], "counterparty": c["counterparty"], "amount": c["amount_label"],
                        "tx_time_utc": c["tx_time"].strftime("%Y-%m-%d %H:%M:%S"), "tx_hash": c["tx_hash"],
                        "explorer_url": c["explorer_url"], "minutes_before": c["minutes_diff"],
                        "usd_match_ratio": c["usd_match_ratio"],
                    }
                    for c in candidates
                ],
            })

    return {
        "address": address,
        "chain": chain,
        "deposits_found": deposits_found,
        "payouts_found": payouts_found,
        "message": (
            "No deposits or payouts through a known instant-swap/bridge service found in this "
            "wallet's recent activity. This does NOT rule one out - it may not be in this wallet's "
            "recent history window, or the service's wallet may not be in known_entities.json yet."
            if not deposits_found and not payouts_found else
            f"Found {len(deposits_found)} deposit(s) into and {len(payouts_found)} payout(s) from "
            f"known instant-swap/bridge service(s)."
        ),
    }


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


# ====================================================================
# KNOWN OP_RETURN PATTERNS - recognizing a service by its embedded
# routing message rather than by address, for Bitcoin services that
# rotate their receiving address on every transaction.
# ====================================================================

def load_known_op_return_patterns():
    if not os.path.isfile(KNOWN_OP_RETURN_PATTERNS_FILE):
        return []
    try:
        with open(KNOWN_OP_RETURN_PATTERNS_FILE, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (json.JSONDecodeError, OSError):
        return []


def save_known_op_return_patterns(patterns):
    with open(KNOWN_OP_RETURN_PATTERNS_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(patterns, file_handle, indent=2)


def decode_op_return_data(scriptpubkey_hex):
    """
    PLAIN ENGLISH: Decodes a Bitcoin OP_RETURN output's raw script into
    the plain-text message embedded in it, if any. Returns None for
    anything that isn't a well-formed OP_RETURN push (not an error -
    most Bitcoin outputs simply aren't OP_RETURN at all).
    """
    try:
        data = bytes.fromhex(scriptpubkey_hex)
    except (ValueError, TypeError):
        return None

    if not data or data[0] != 0x6A:  # 0x6A = OP_RETURN opcode
        return None

    position = 1
    if position >= len(data):
        return None

    opcode = data[position]
    if opcode == 0x4C:  # OP_PUSHDATA1 - next 1 byte is the length
        if position + 1 >= len(data):
            return None
        length = data[position + 1]
        position += 2
    elif opcode == 0x4D:  # OP_PUSHDATA2 - next 2 bytes (little-endian) are the length
        if position + 2 >= len(data):
            return None
        length = int.from_bytes(data[position + 1:position + 3], "little")
        position += 3
    elif opcode <= 0x4B:  # direct push of `opcode` bytes
        length = opcode
        position += 1
    else:
        return None  # an opcode we don't handle (rare for OP_RETURN in practice)

    payload = data[position:position + length]
    if len(payload) != length:
        return None  # truncated/malformed

    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return payload.decode("utf-8", errors="replace")


def check_op_return_patterns(decoded_text):
    """Returns {"name", "type"} for the first known pattern found as a
    substring of decoded_text, or None if nothing matches."""
    if not decoded_text:
        return None
    for entry in load_known_op_return_patterns():
        pattern = entry.get("pattern", "")
        if pattern and pattern in decoded_text:
            return {"name": entry.get("name", "Known service"), "type": entry.get("type", "bridge")}
    return None


def find_op_return_pattern_match_in_tx(tx):
    """
    PLAIN ENGLISH: Scans a Bitcoin transaction's outputs for an
    OP_RETURN message matching a known pattern. Returns
    {"name", "type", "decoded_text"} for the first match, or None.
    """
    for output in tx.get("vout", []):
        if output.get("scriptpubkey_type") != "op_return":
            continue
        decoded = decode_op_return_data(output.get("scriptpubkey", ""))
        if decoded is None:
            continue
        match = check_op_return_patterns(decoded)
        if match:
            match["decoded_text"] = decoded
            return match
    return None


def decode_eth_input_data(input_hex):
    """
    PLAIN ENGLISH: Decodes an Ethereum transaction's "input" field as
    plain text, if it actually IS plain text. Most transactions either
    have empty input ("0x" - a plain transfer) or binary contract-call
    data (a function selector + encoded arguments) that will correctly
    FAIL to decode as UTF-8 - that's expected and fine, it just means
    this particular transaction isn't carrying a text memo. Returns
    None for either of those ordinary cases, not an error.
    """
    if not input_hex or input_hex in ("0x", "0x0"):
        return None
    hex_part = input_hex[2:] if input_hex.startswith("0x") else input_hex
    try:
        data = bytes.fromhex(hex_part)
    except ValueError:
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None  # binary contract-call data, not a text memo


def find_message_pattern_match_in_eth_tx(tx):
    """Same idea as find_op_return_pattern_match_in_tx, for Ethereum's
    transaction "input" field instead of Bitcoin's OP_RETURN output."""
    decoded = decode_eth_input_data(tx.get("input", ""))
    if decoded is None:
        return None
    match = check_op_return_patterns(decoded)
    if match:
        match["decoded_text"] = decoded
    return match


def decode_xrp_memos(tx):
    """Decodes every Memo attached to an XRP transaction as plain
    text, skipping any that aren't valid hex or valid UTF-8 (XRPL
    allows arbitrary binary memo data - this only surfaces the
    human-readable ones)."""
    decoded_memos = []
    for memo_wrapper in tx.get("Memos", []):
        memo_data_hex = (memo_wrapper.get("Memo") or {}).get("MemoData")
        if not memo_data_hex:
            continue
        try:
            decoded_memos.append(bytes.fromhex(memo_data_hex).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            continue
    return decoded_memos


def find_message_pattern_match_in_xrp_tx(tx):
    """Same idea again, for XRP's official Memos field - XRPL's
    direct equivalent to Bitcoin's OP_RETURN."""
    for decoded in decode_xrp_memos(tx):
        match = check_op_return_patterns(decoded)
        if match:
            match["decoded_text"] = decoded
            return match
    return None


# NOTE ON TRON: standard USDT-TRC20 transfers are ABI-encoded smart
# contract calls (a function selector + the recipient address + the
# amount, all as fixed-width binary), not a free-text field - there is
# no equivalent memo mechanism to decode here, unlike Bitcoin's
# OP_RETURN, Ethereum's input data, or XRP's Memos. If a specific
# service turns out to use some OTHER Tron-side signature (e.g. a
# secondary dust-amount transaction, or a non-standard contract with
# its own memo parameter), that would need its own dedicated decoder -
# there's no generic mechanism to build here the way there is for the
# other three chains.


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
        if not entity or entity.get("type") not in ("exchange", "instant_swap"):
            continue

        newly_mapped, sibling_count = register_consolidation_and_siblings(
            address, chain, entity, hop_info["tx_hash"], hop_info["tx_time"],
        )
        message = f"Confirmed: swept into {entity['name']} ({entity['type']}) via tx {hop_info['tx_hash']}."
        if sibling_count:
            message += f" Also found and mapped {sibling_count} sibling deposit address(es) from the same transaction."

        # The point of this whole function: don't stop at confirming
        # the INPUT side - immediately search this SAME service's
        # other known addresses for a correlated OUTPUT too, using the
        # amount/time actually observed in THIS deposit. One check,
        # one result, instead of running Deposit Map then separately
        # running Swap/Bridge Check and manually connecting the two.
        # This only runs for a freshly-discovered match (where we have
        # a real transaction's amount/time to search from) - the
        # "already known" shortcut above has no such context and isn't
        # touched, so it keeps working exactly as it always has.
        raw_candidates = find_correlated_counterpart(
            entity["name"], hop_info["amount_label"], chain, hop_info["tx_time"], "outgoing",
        )
        output_candidates = [
            {
                "chain": c["chain"], "counterparty": c["counterparty"], "amount": c["amount_label"],
                "tx_time_utc": c["tx_time"].strftime("%Y-%m-%d %H:%M:%S"), "tx_hash": c["tx_hash"],
                "explorer_url": c["explorer_url"], "minutes_after": c["minutes_diff"],
                "usd_match_ratio": c["usd_match_ratio"],
            }
            for c in raw_candidates
        ]
        message += (
            f" Found {len(output_candidates)} possible output candidate(s) from the same service - "
            f"heuristic lead(s), not confirmed." if output_candidates else
            " No plausible output candidate found within the correlation window - this doesn't rule one out."
        )

        return {
            "address": address, "chain": chain, "match": True, "already_known": False,
            "exchange_name": entity["name"], "exchange_type": entity["type"],
            "newly_mapped": newly_mapped,
            "consolidation_tx_hash": hop_info["tx_hash"],
            "consolidation_time_utc": hop_info["tx_time"].strftime("%Y-%m-%d %H:%M:%S"),
            "explorer_url": hop_info["explorer_url"],
            "sibling_deposit_addresses_found": sibling_count,
            "output_candidates": output_candidates,
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
# SECTION 3D: TRANSACTION HASH LOOKUP (any chain, given just a hash)
# ====================================================================
# WHAT THIS DOES (plain English): given a single transaction hash -
# from another tool, a screenshot, a colleague, wherever - fetches its
# full details directly, without needing to rediscover it via a
# multi-hop trace. This is the direct answer to "I already know the
# exact transaction that matters, I just want its details."
#
# IMPORTANT LIMITATION, stated plainly: unlike wallet addresses,
# Bitcoin, XRP, and Tron transaction hashes are ALL just 64 hex
# characters with no distinguishing prefix - they are structurally
# identical. Only Ethereum's "0x" prefix makes a hash unambiguous by
# format alone. For anything else, this has to actually ASK each of
# the other three chains in turn until one of them recognizes it -
# there's no way to know which chain a bare 64-hex-character hash
# belongs to just by looking at it.
# ====================================================================

def get_bitcoin_transaction_by_hash(tx_hash):
    """Returns full details for a Bitcoin transaction, or None if mempool.space doesn't recognize this hash."""
    url = f"https://mempool.space/api/tx/{tx_hash}"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 404:
            return None
        response.raise_for_status()
        tx = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    status = tx.get("status", {})
    tx_time = None
    if status.get("confirmed") and status.get("block_time"):
        tx_time = datetime.fromtimestamp(status["block_time"], tz=timezone.utc)

    inputs = [
        {"address": (tx_input.get("prevout") or {}).get("scriptpubkey_address"),
         "amount": f"{(tx_input.get('prevout') or {}).get('value', 0) / 100_000_000:.8f} BTC"}
        for tx_input in tx.get("vin", [])
    ]
    outputs = [
        {"address": output.get("scriptpubkey_address"), "amount": f"{output.get('value', 0) / 100_000_000:.8f} BTC"}
        for output in tx.get("vout", [])
    ]
    total_btc = sum(output.get("value", 0) for output in tx.get("vout", [])) / 100_000_000

    return {
        "chain": "bitcoin", "found": True, "tx_hash": tx_hash,
        "confirmed": status.get("confirmed", False),
        "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S") if tx_time else None,
        "total_amount": f"{total_btc:.8f} BTC",
        "inputs": inputs, "outputs": outputs,
        "explorer_url": f"https://mempool.space/tx/{tx_hash}",
    }


def get_ethereum_transaction_by_hash(tx_hash):
    """Returns details for an Ethereum transaction, or None if Etherscan doesn't recognize this hash."""
    url = "https://api.etherscan.io/v2/api"
    try:
        response = requests.get(url, params={
            "chainid": "1", "module": "proxy", "action": "eth_getTransactionByHash",
            "txhash": tx_hash, "apikey": ETHERSCAN_API_KEY,
        }, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    tx = data.get("result")
    if not tx or not isinstance(tx, dict):
        return None

    block_number_hex = tx.get("blockNumber")
    tx_time_utc = None
    confirmed = block_number_hex is not None
    if confirmed:
        try:
            block_response = requests.get(url, params={
                "chainid": "1", "module": "proxy", "action": "eth_getBlockByNumber",
                "tag": block_number_hex, "boolean": "false", "apikey": ETHERSCAN_API_KEY,
            }, timeout=15)
            block_data = block_response.json().get("result") or {}
            timestamp_hex = block_data.get("timestamp")
            if timestamp_hex:
                tx_time_utc = datetime.fromtimestamp(int(timestamp_hex, 16), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        except (requests.exceptions.RequestException, ValueError):
            pass  # timestamp is a nice-to-have, don't fail the whole lookup over it

    try:
        eth_value = int(tx.get("value", "0x0"), 16) / 1_000_000_000_000_000_000
    except (TypeError, ValueError):
        eth_value = 0.0

    return {
        "chain": "ethereum", "found": True, "tx_hash": tx_hash,
        "confirmed": confirmed,
        "tx_time_utc": tx_time_utc,
        "from": tx.get("from"), "to": tx.get("to"),
        "total_amount": f"{eth_value:.6f} ETH",
        "explorer_url": f"https://etherscan.io/tx/{tx_hash}",
    }


def get_xrp_transaction_by_hash(tx_hash):
    """Returns details for an XRP transaction, or None if the XRPL node doesn't recognize this hash."""
    try:
        response = requests.post(XRPL_RPC_URL, json={"method": "tx", "params": [{"transaction": tx_hash}]}, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    result = data.get("result", {})
    if result.get("status") != "success" or result.get("error"):
        return None

    meta = result.get("meta", {})
    delivered = meta.get("delivered_amount", result.get("Amount"))
    if isinstance(delivered, str):
        amount_label = f"{int(delivered) / 1_000_000:.6f} XRP"
    elif isinstance(delivered, dict):
        amount_label = f"{delivered.get('value')} {delivered.get('currency')} (issued token)"
    else:
        amount_label = "unknown"

    ripple_ts = result.get("date")
    tx_time_utc = None
    if ripple_ts is not None:
        tx_time_utc = datetime.fromtimestamp(ripple_ts + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return {
        "chain": "xrp", "found": True, "tx_hash": tx_hash,
        "confirmed": bool(result.get("validated", False)),
        "tx_time_utc": tx_time_utc,
        "from": result.get("Account"), "to": result.get("Destination"),
        "total_amount": amount_label,
        "explorer_url": f"https://bithomp.com/explorer/{tx_hash}",
    }


def get_tron_transaction_by_hash(tx_hash):
    """Returns details for a Tron transaction (USDT-TRC20 transfer, if decodable), or None if TronGrid doesn't recognize this hash."""
    headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}
    try:
        response = requests.get(f"{TRONGRID_BASE_URL}/v1/transactions/{tx_hash}", headers=headers, timeout=15)
        data = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return None

    tx_list = data.get("data", [])
    if not tx_list:
        return None
    tx = tx_list[0]

    block_timestamp = tx.get("block_timestamp") or tx.get("raw_data", {}).get("timestamp")
    tx_time_utc = None
    if block_timestamp:
        tx_time_utc = datetime.fromtimestamp(block_timestamp / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Try to decode this as a USDT-TRC20 transfer via the events endpoint -
    # the base transaction endpoint only shows the raw contract CALL, not
    # the human-readable transfer (from/to/amount).
    from_address, to_address, amount_label = None, None, "(see explorer for detail - not a decodable USDT transfer)"
    try:
        events_response = requests.get(
            f"{TRONGRID_BASE_URL}/v1/transactions/{tx_hash}/events", headers=headers, timeout=15,
        )
        events = events_response.json().get("data", [])
        for event in events:
            if event.get("event_name") == "Transfer" and event.get("contract_address") == USDT_TRC20_CONTRACT:
                result_data = event.get("result", {})
                from_address = result_data.get("from")
                to_address = result_data.get("to")
                raw_value = result_data.get("value")
                if raw_value is not None:
                    amount_label = f"{int(raw_value) / 1_000_000:.6f} USDT"
                break
    except (requests.exceptions.RequestException, ValueError):
        pass  # fall back to the generic "see explorer" message above

    return {
        "chain": "tron", "found": True, "tx_hash": tx_hash,
        "confirmed": bool(tx.get("ret", [{}])[0].get("contractRet") == "SUCCESS") if tx.get("ret") else None,
        "tx_time_utc": tx_time_utc,
        "from": from_address, "to": to_address,
        "total_amount": amount_label,
        "explorer_url": f"https://tronscan.org/#/transaction/{tx_hash}",
    }


def lookup_transaction_across_chains(tx_hash):
    """
    PLAIN ENGLISH: Given a transaction hash of UNKNOWN chain, finds
    which chain it actually belongs to and returns its full details.

    Ethereum hashes ("0x" + 64 hex characters) are unambiguous and
    only Ethereum is checked. Everything else (a bare 64 hex-character
    string) is checked against Bitcoin, then XRP, then Tron in turn,
    since those three chains' hashes are format-identical - there's no
    way to know which one it is without asking each of them.
    """
    cleaned = tx_hash.strip()

    if cleaned.lower().startswith("0x") and len(cleaned) == 66:
        result = get_ethereum_transaction_by_hash(cleaned)
        if result:
            return result
        return {
            "found": False, "tx_hash": cleaned,
            "message": "This looks like an Ethereum-style hash, but Etherscan doesn't recognize it. "
                       "Double-check it, or it may not be confirmed/indexed yet.",
        }

    is_bare_hex_64 = len(cleaned) == 64 and all(character in "0123456789abcdefABCDEF" for character in cleaned)
    if not is_bare_hex_64:
        return {
            "found": False, "tx_hash": cleaned,
            "message": "That doesn't look like a valid transaction hash for any supported chain "
                       "(Ethereum: 0x + 64 hex characters. Bitcoin/XRP/Tron: 64 hex characters, no prefix).",
        }

    for chain_name, lookup_function in [
        ("bitcoin", get_bitcoin_transaction_by_hash),
        ("xrp", get_xrp_transaction_by_hash),
        ("tron", get_tron_transaction_by_hash),
    ]:
        result = lookup_function(cleaned)
        if result:
            return result

    return {
        "found": False, "tx_hash": cleaned,
        "message": "Checked Bitcoin, XRP, and Tron - none of them recognize this hash. "
                   "Double-check it's correct and fully confirmed.",
    }


# ====================================================================
# SECTION 3E: SEARCH A WALLET NEAR A SPECIFIC DATE/TIME
# ====================================================================
# WHAT THIS DOES (plain English): the automatic hop-by-hop trace only
# ever looks at the MOST RECENT pages of a wallet's history (a
# deliberate cost/time tradeoff - see BITCOIN_TRACE_MAX_PAGES etc.).
# For a high-volume wallet (a major exchange's hot wallet, say), a
# transaction from months or years ago can be buried behind literally
# millions of newer ones and never get reached that way. If you
# already know roughly WHEN the transaction you care about happened
# (from another tool, a screenshot, a colleague, an old note), this
# searches around that specific date/time directly instead.
#
# IMPORTANT LIMITATION, stated plainly: chains differ in how well
# this actually works.
#   - Ethereum: GOOD. Etherscan can convert a date straight to the
#     nearest block, then fetch only that block range - fast and
#     reliable regardless of how busy the wallet is.
#   - Tron: GOOD. TronGrid accepts a direct time-range filter.
#   - Bitcoin and XRP: NO direct date-range query exists in their
#     public APIs. This has to paginate backward from "now," the same
#     as everywhere else, just with a much higher page ceiling and a
#     smarter stopping point (once it's gone PAST your target date).
#     For a wallet busy enough, this can still fail to reach an old
#     date within a reasonable number of pages - if that happens,
#     this says so honestly rather than pretending it searched
#     further than it did.
# ====================================================================

DATE_SEARCH_MAX_PAGES_FAST_CHAINS = 10    # Ethereum/Tron - direct range queries, cheap to go deeper
DATE_SEARCH_MAX_PAGES_SLOW_CHAINS = 50    # Bitcoin/XRP - blind pagination, hard safety cap


def search_ethereum_near_date(address, target_datetime, window_hours=24):
    """Uses Etherscan's timestamp->block conversion to jump straight to
    the right neighborhood, then fetches only that block range."""
    url = "https://api.etherscan.io/v2/api"
    window_start = target_datetime - timedelta(hours=window_hours / 2)
    window_end = target_datetime + timedelta(hours=window_hours / 2)

    def _block_at(when):
        try:
            response = requests.get(url, params={
                "chainid": "1", "module": "block", "action": "getblocknobytime",
                "timestamp": int(when.timestamp()), "closest": "before", "apikey": ETHERSCAN_API_KEY,
            }, timeout=15)
            return int(response.json().get("result"))
        except (requests.exceptions.RequestException, ValueError, TypeError):
            return None

    start_block = _block_at(window_start)
    end_block = _block_at(window_end)
    if start_block is None or end_block is None:
        return {"chain": "ethereum", "found_any": False,
                "message": "Could not convert that date to a block range via Etherscan."}

    try:
        response = requests.get(url, params={
            "chainid": "1", "module": "account", "action": "txlist", "address": address,
            "startblock": start_block, "endblock": max(end_block, start_block), "sort": "asc",
            "apikey": ETHERSCAN_API_KEY,
        }, timeout=15)
        data = response.json()
    except requests.exceptions.RequestException as error:
        return {"chain": "ethereum", "found_any": False, "message": f"Could not reach Etherscan: {error}"}

    if data.get("status") != "1":
        return {"chain": "ethereum", "found_any": False,
                "message": data.get("message", "No transactions found in that window.")}

    matches = [{
        "tx_hash": tx.get("hash"),
        "from": tx.get("from"), "to": tx.get("to"),
        "amount": f"{int(tx.get('value', 0)) / 1_000_000_000_000_000_000:.6f} ETH",
        "tx_time_utc": datetime.fromtimestamp(int(tx["timeStamp"]), tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "explorer_url": f"https://etherscan.io/tx/{tx.get('hash')}",
    } for tx in data.get("result", [])]

    return {"chain": "ethereum", "found_any": len(matches) > 0, "matches": matches, "search_was_complete": True}


def search_tron_near_date(address, target_datetime, window_hours=24):
    """TronGrid accepts a direct millisecond time-range filter - no need to paginate at all."""
    window_start_ms = int((target_datetime - timedelta(hours=window_hours / 2)).timestamp() * 1000)
    window_end_ms = int((target_datetime + timedelta(hours=window_hours / 2)).timestamp() * 1000)
    headers = {"TRON-PRO-API-KEY": TRON_API_KEY} if TRON_API_KEY else {}

    try:
        response = requests.get(
            f"{TRONGRID_BASE_URL}/v1/accounts/{address}/transactions/trc20",
            params={
                "contract_address": USDT_TRC20_CONTRACT, "limit": 200,
                "min_timestamp": window_start_ms, "max_timestamp": window_end_ms,
                "only_confirmed": "true",
            },
            headers=headers, timeout=15,
        )
        data = response.json()
    except (requests.exceptions.RequestException, ValueError) as error:
        return {"chain": "tron", "found_any": False, "message": f"Could not reach TronGrid: {error}"}

    if data.get("success") is False:
        return {"chain": "tron", "found_any": False, "message": data.get("error", "unknown TronGrid error")}

    matches = []
    for tx in data.get("data", []):
        decimals = (tx.get("token_info") or {}).get("decimals", 6)
        try:
            amount = int(tx.get("value", 0)) / (10 ** decimals)
        except (TypeError, ValueError):
            amount = 0.0
        matches.append({
            "tx_hash": tx.get("transaction_id"),
            "from": tx.get("from"), "to": tx.get("to"),
            "amount": f"{amount:.6f} USDT",
            "tx_time_utc": datetime.fromtimestamp(tx.get("block_timestamp", 0) / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "explorer_url": f"https://tronscan.org/#/transaction/{tx.get('transaction_id')}",
        })

    return {"chain": "tron", "found_any": len(matches) > 0, "matches": matches, "search_was_complete": True}


def search_bitcoin_near_date(address, target_datetime, window_hours=24):
    """
    No direct date-range API exists for a Bitcoin address on
    mempool.space - paginates backward from 'now' (newest-first),
    stopping once transactions are older than the target window, up
    to a hard safety cap. Honestly reports if that cap was hit before
    reaching the target date, for a wallet too busy to reach it this way.
    """
    window_start = target_datetime - timedelta(hours=window_hours / 2)
    window_end = target_datetime + timedelta(hours=window_hours / 2)
    matches = []
    last_txid = None
    pages_fetched = 0
    reached_target_era = False

    while pages_fetched < DATE_SEARCH_MAX_PAGES_SLOW_CHAINS:
        url = (f"https://mempool.space/api/address/{address}/txs/chain/{last_txid}"
               if last_txid else f"https://mempool.space/api/address/{address}/txs")
        try:
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            page = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            return {"chain": "bitcoin", "found_any": len(matches) > 0, "matches": matches,
                    "search_was_complete": False, "message": f"Stopped early - network error: {error}"}
        if not page:
            reached_target_era = True  # ran out of history entirely - that counts as "covered"
            break

        pages_fetched += 1
        oldest_on_page = None
        for tx in page:
            block_time = tx.get("status", {}).get("block_time")
            if block_time is None:
                continue
            tx_time = datetime.fromtimestamp(block_time, tz=timezone.utc)
            oldest_on_page = tx_time if oldest_on_page is None else min(oldest_on_page, tx_time)
            if window_start <= tx_time <= window_end:
                total_value = sum(o.get("value", 0) for o in tx.get("vout", []))
                matches.append({
                    "tx_hash": tx.get("txid"), "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "amount": f"{total_value / 100_000_000:.8f} BTC",
                    "explorer_url": f"https://mempool.space/tx/{tx.get('txid')}",
                })

        if oldest_on_page and oldest_on_page < window_start:
            reached_target_era = True
            break

        last_txid = page[-1].get("txid")
        if not last_txid:
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    message = None
    if not reached_target_era:
        message = (f"Reached the {DATE_SEARCH_MAX_PAGES_SLOW_CHAINS}-page safety limit before getting back to "
                   f"that date - this wallet is too high-volume to reliably reach it this way. Results above "
                   f"are only what was found in the pages actually checked, not a complete search of that date.")
    return {"chain": "bitcoin", "found_any": len(matches) > 0, "matches": matches,
            "search_was_complete": reached_target_era, "message": message}


def search_xrp_near_date(address, target_datetime, window_hours=24):
    """Same approach and same honesty caveat as Bitcoin - XRPL's public
    account_tx API has no direct date-range filter, only a marker-based
    cursor paginating backward from 'now'."""
    window_start = target_datetime - timedelta(hours=window_hours / 2)
    window_end = target_datetime + timedelta(hours=window_hours / 2)
    matches = []
    marker = None
    pages_fetched = 0
    reached_target_era = False

    while pages_fetched < DATE_SEARCH_MAX_PAGES_SLOW_CHAINS:
        params = {"account": address, "ledger_index_min": -1, "ledger_index_max": -1, "limit": 100, "forward": False}
        if marker:
            params["marker"] = marker
        try:
            response = requests.post(XRPL_RPC_URL, json={"method": "account_tx", "params": [params]}, timeout=15)
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as error:
            return {"chain": "xrp", "found_any": len(matches) > 0, "matches": matches,
                    "search_was_complete": False, "message": f"Stopped early - network error: {error}"}

        result = data.get("result", {})
        if result.get("status") != "success":
            break

        page = result.get("transactions", [])
        if not page:
            reached_target_era = True
            break

        pages_fetched += 1
        oldest_on_page = None
        for tx_entry in page:
            if not tx_entry.get("validated"):
                continue
            tx = tx_entry.get("tx", {})
            ripple_ts = tx.get("date")
            if ripple_ts is None:
                continue
            tx_time = datetime.fromtimestamp(ripple_ts + RIPPLE_EPOCH_OFFSET_SECONDS, tz=timezone.utc)
            oldest_on_page = tx_time if oldest_on_page is None else min(oldest_on_page, tx_time)
            if window_start <= tx_time <= window_end:
                meta = tx_entry.get("meta", {})
                delivered = meta.get("delivered_amount", tx.get("Amount"))
                amount_label = f"{int(delivered) / 1_000_000:.6f} XRP" if isinstance(delivered, str) else "token payment"
                matches.append({
                    "tx_hash": tx.get("hash"), "tx_time_utc": tx_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "amount": amount_label,
                    "explorer_url": f"https://bithomp.com/explorer/{tx.get('hash')}",
                })

        if oldest_on_page and oldest_on_page < window_start:
            reached_target_era = True
            break

        marker = result.get("marker")
        if not marker:
            reached_target_era = True
            break
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    message = None
    if not reached_target_era:
        message = (f"Reached the {DATE_SEARCH_MAX_PAGES_SLOW_CHAINS}-page safety limit before getting back to "
                   f"that date - this wallet is too high-volume to reliably reach it this way. Results above "
                   f"are only what was found in the pages actually checked, not a complete search of that date.")
    return {"chain": "xrp", "found_any": len(matches) > 0, "matches": matches,
            "search_was_complete": reached_target_era, "message": message}


def search_wallet_near_date(address, target_datetime_iso, window_hours=24):
    """
    PLAIN ENGLISH: Given a wallet address and a target date/time (ISO
    format string, e.g. "2025-05-15T15:00:00"), searches that address's
    activity within +/- window_hours/2 of that moment. Auto-detects
    the chain from the address format (unambiguous, unlike tx hashes).
    """
    chain = detect_chain(address)
    if chain is None:
        return {"found_any": False, "message": "Not a recognized Ethereum, Bitcoin, XRP, or Tron address."}

    try:
        target_datetime = datetime.fromisoformat(target_datetime_iso).replace(tzinfo=timezone.utc)
    except ValueError:
        return {"found_any": False, "message": "Could not parse that date/time."}

    search_function = {
        "ethereum": search_ethereum_near_date,
        "tron": search_tron_near_date,
        "bitcoin": search_bitcoin_near_date,
        "xrp": search_xrp_near_date,
    }[chain]

    result = search_function(address, target_datetime, window_hours)
    result["address"] = address
    result["target_datetime_utc"] = target_datetime.strftime("%Y-%m-%d %H:%M:%S")
    result["window_hours"] = window_hours
    return result


# ====================================================================
# SECTION 4: SHARED CASE WATCHLIST (illicit-wallet targets)
# ====================================================================

def load_known_entities():
    """Returns a dict of {address_lowercase: {"name":..., "type":...}}
    combining BUILT_IN_KNOWN_ENTITIES with the known_entities table in
    Postgres, then folding in the deposit map file on top (unchanged)."""
    entities = {}
    for entry in BUILT_IN_KNOWN_ENTITIES:
        if entry.get("address"):
            entities[entry["address"].lower()] = {
                "name": entry.get("name", "Known entity"),
                "type": entry.get("type", "exchange"),
            }

    try:
        with auth._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT address, name, type FROM known_entities;")
                for address, name, entity_type in cur.fetchall():
                    entities[address.lower()] = {"name": name, "type": entity_type}
    except Exception as error:
        print(f"⚠️  Could not read known_entities from the database: {error}")

    # Fold in every exchange deposit address confirmed by a past
    # consolidation-mapping discovery (SECTION 3C) - unchanged, still file-based.
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


def _lookup_bithomp_service(address):
    """
    PLAIN ENGLISH: Asks Bithomp whether this XRP address has a known
    username/service label attached (e.g. an exchange's labeled hot
    wallet) - a fallback for addresses not yet in your own curated
    known_entities. Returns {"name":..., "type": "exchange", "source":
    "bithomp"} if Bithomp has a label, or None (not an error - most
    ordinary addresses simply have no label). Cached in-memory per
    run so a trace hitting the same address repeatedly doesn't burn
    through the free tier's 10 requests/minute limit.
    """
    if not BITHOMP_API_KEY:
        return None

    cache_key = address.lower()
    if cache_key in _bithomp_lookup_cache:
        return _bithomp_lookup_cache[cache_key]

    result = None
    try:
        response = requests.get(
            f"{BITHOMP_API_BASE}/address/{address}",
            params={"username": "true", "service": "true"},
            headers={"x-bithomp-token": BITHOMP_API_KEY},
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            label = (data.get("service") or {}).get("name") or data.get("username")
            if label:
                result = {"name": label, "type": "exchange", "source": "bithomp"}
        elif response.status_code == 429:
            print("    ⚠️  Bithomp rate limit hit - skipping label lookups for the rest of this run.")
            # Cache a "no result" for every future call this run too, rather
            # than hammering an already-rate-limited endpoint repeatedly.
    except (requests.exceptions.RequestException, ValueError) as error:
        print(f"    ⚠️  Could not reach Bithomp: {error}")

    _bithomp_lookup_cache[cache_key] = result
    return result


def check_known_entity(address):
    """Returns {"name":..., "type":...} if address is a known exchange/mixer/
    custodial wallet, otherwise None. For XRP addresses specifically, falls
    back to a live Bithomp label lookup if not already in known_entities
    and BITHOMP_API_KEY is set - see _lookup_bithomp_service()."""
    entity = KNOWN_ENTITIES.get(address.lower())
    if entity:
        return entity
    if BITHOMP_API_KEY and detect_chain(address) == "xrp":
        return _lookup_bithomp_service(address)
    return None


def load_case_watchlist_addresses():
    try:
        with auth._get_db_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT address FROM case_watchlist;")
                return [row[0] for row in cur.fetchall()]
    except Exception as error:
        print(f"⚠️  Could not read shared case watchlist from the database: {error}")
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

def trace_forward(victim_wallet, target_lowercase_set, max_hops, starting_amount=None, exact_amount_only=False, continue_past_match=False):
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
    # Each frontier entry: (address, path_so_far, tracked_amount, is_post_match).
    # tracked_amount is None whenever amount filtering is off.
    # is_post_match is True once a lineage has already passed through a
    # confirmed target match (continue_past_match mode) - see below for
    # why that needs its own tracking.
    frontier = [(victim_wallet, [], starting_amount, False)]

    for hop_number in range(1, max_hops + 1):
        print(f"\n--- Hop {hop_number}: checking {len(frontier)} wallet(s) ---")
        next_frontier = []

        for address, path_so_far, tracked_amount, is_post_match in frontier:
            entity = check_known_entity(address)
            if not entity and path_so_far:
                entity = path_so_far[-1].get("pattern_match")
            print(f"  Checking outgoing activity from {address} "
                  + (f"(tracking ~{tracked_amount:g}) " if tracked_amount is not None else "")
                  + "...")
            counterparties, fanout_count = get_outgoing_counterparties(victim_chain, address)
            time.sleep(SECONDS_BETWEEN_REQUESTS)

            high_fanout = fanout_count >= HIGH_FANOUT_THRESHOLD
            if (entity or high_fanout) and path_so_far:
                short_reason = (
                    f"{entity['name']} (known {entity['type']})" if entity
                    else f"high fan-out wallet ({fanout_count}+ distinct counterparties "
                         f"seen - likely exchange/custodial)"
                )
                print(f"    🔶 TRAIL ENDS: {address} is a {short_reason} - not tracing "
                      f"further into its counterparties.")
                # The address is included here (not just the name) because
                # this reason text is what actually gets shown in the API/
                # frontend - a name alone ("Binance") isn't enough to
                # verify or cross-reference against a block explorer.
                flagged_end_paths.append((path_so_far, f"{short_reason} - {address}"))

                # A CONFIRMED (not just high-fanout-guessed) hit against a
                # known exchange OR instant-swap service means the hop
                # that led here was a genuine deposit sweep - both kinds
                # of service consolidate per-user deposit addresses into
                # their own treasury wallets this same way, then pay out
                # from a DIFFERENT wallet. Register the deposit address
                # (and, on Bitcoin, its sweep siblings) so this and every
                # future run recognizes it immediately.
                if entity and ENABLE_DEPOSIT_CONSOLIDATION_MAPPING and entity.get("type") in ("exchange", "instant_swap"):
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
                if "pattern_match" in hop_info:
                    hop_dict["pattern_match"] = hop_info["pattern_match"]

                amount_related = True
                if tracked_amount is not None:
                    if hop_amount is None:
                        amount_related = False
                        reason = ("amount filter is on, but this hop's amount couldn't be "
                                  "parsed/compared (e.g. a non-native token payment) - "
                                  "reviewed manually, not auto-followed")
                    else:
                        ratio = (hop_amount / tracked_amount) if tracked_amount > 0 else 0
                        min_ratio = EXACT_AMOUNT_MATCH_MIN_RATIO if exact_amount_only else AMOUNT_MATCH_MIN_RATIO
                        max_ratio = EXACT_AMOUNT_MATCH_MAX_RATIO if exact_amount_only else AMOUNT_MATCH_MAX_RATIO
                        if ratio < min_ratio or ratio > max_ratio:
                            amount_related = False
                            reason = (f"amount ({hop_amount:g}) is {ratio:.0%} of the "
                                      f"~{tracked_amount:g} being tracked - outside the "
                                      f"{min_ratio:.1%}-{max_ratio:.1%} "
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
                    if not continue_past_match:
                        # Keep searching other branches too - there could
                        # be more than one path or more than one target.
                        continue
                    # else: don't stop here - fall through below so this
                    # wallet's OWN onward activity gets explored on the
                    # next hop too, same as any other wallet would be.
                    if entity or high_fanout:
                        continue
                    if counterparty.lower() not in visited:
                        visited.add(counterparty.lower())
                        next_frontier.append((counterparty, new_path, next_tracked_amount, True))
                    continue

                if is_post_match:
                    # This hop is part of a chain that already passed
                    # through a confirmed match earlier - report it
                    # explicitly rather than letting it silently vanish
                    # the way an ordinary unremarkable dead-end would.
                    # Without this, "continue past match" would still
                    # LOOK like it stopped at the match, even though it
                    # kept exploring - the exploration just had nowhere
                    # to show up.
                    found_paths.append(new_path)

                if entity or high_fanout:
                    # Don't expand past a known/likely custodial wallet -
                    # already reported as a flagged trail end above.
                    continue

                if counterparty.lower() not in visited:
                    visited.add(counterparty.lower())
                    next_frontier.append((counterparty, new_path, next_tracked_amount, is_post_match))

        frontier = next_frontier
        if not frontier:
            print("\n  No further un-visited wallets to follow - trail ends here.")
            break

    return found_paths, flagged_end_paths, len(visited), amount_filtered_paths


def trace_backward(start_wallet, target_lowercase_set, max_hops, starting_amount=None, exact_amount_only=False, continue_past_match=False):
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
    # Each frontier entry: (address, path_so_far_in_chronological_order,
    # tracked_amount, is_post_match) - see trace_forward's matching
    # comment for why is_post_match exists.
    frontier = [(start_wallet, [], starting_amount, False)]

    for hop_number in range(1, max_hops + 1):
        print(f"\n--- Hop {hop_number} back: checking {len(frontier)} wallet(s) ---")
        next_frontier = []

        for address, path_so_far, tracked_amount, is_post_match in frontier:
            entity = check_known_entity(address)
            if not entity and path_so_far:
                entity = path_so_far[0].get("pattern_match")
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
                if "pattern_match" in hop_info:
                    hop_dict["pattern_match"] = hop_info["pattern_match"]

                if tracked_amount is not None:
                    if hop_amount is None:
                        reason = ("amount filter is on, but this hop's amount couldn't be "
                                  "parsed/compared (e.g. a non-native token payment) - "
                                  "reviewed manually, not auto-followed")
                        amount_filtered_paths.append(([hop_dict] + path_so_far, reason))
                        continue
                    ratio = (hop_amount / tracked_amount) if tracked_amount > 0 else 0
                    min_ratio = EXACT_AMOUNT_MATCH_MIN_RATIO if exact_amount_only else AMOUNT_MATCH_MIN_RATIO
                    max_ratio = EXACT_AMOUNT_MATCH_MAX_RATIO if exact_amount_only else AMOUNT_MATCH_MAX_RATIO
                    if ratio < min_ratio or ratio > max_ratio:
                        reason = (f"amount ({hop_amount:g}) is {ratio:.0%} of the "
                                  f"~{tracked_amount:g} being tracked - outside the "
                                  f"{min_ratio:.1%}-{max_ratio:.1%} "
                                  f"match range, so not auto-followed further")
                        amount_filtered_paths.append(([hop_dict] + path_so_far, reason))
                        continue

                counterparties.append((hop_info, hop_amount))

            if not counterparties:
                if path_so_far:
                    if entity:
                        reason = f"{entity['name']} (known {entity['type']}) - {address} - no incoming activity visible"
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
                short_reason = (
                    f"{entity['name']} (known {entity['type']})" if entity
                    else f"high fan-in wallet ({fanout_count}+ distinct counterparties "
                         f"seen - likely exchange/custodial)"
                )
                print(f"    🔶 TRAIL ENDS: {address} is a {short_reason} - not tracing "
                      f"further into its counterparties.")
                trail_end_paths.append((path_so_far, f"{short_reason} - {address}"))

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
                    if not continue_past_match:
                        continue
                    # else: fall through - keep tracing even further back
                    # from this confirmed wallet too.
                    if entity or high_fanout:
                        continue
                    if counterparty.lower() not in visited:
                        visited.add(counterparty.lower())
                        next_frontier.append((counterparty, new_path, next_tracked_amount, True))
                    continue

                if is_post_match:
                    # Same reasoning as trace_forward - report every hop
                    # of a chain that already passed through a confirmed
                    # match, not just the match itself, or continuing
                    # further back would silently explore without ever
                    # showing what it found.
                    matched_paths.append(new_path)

                if entity or high_fanout:
                    # Don't expand past a known/likely custodial wallet -
                    # already reported as a flagged trail end above.
                    continue

                if counterparty.lower() not in visited:
                    visited.add(counterparty.lower())
                    next_frontier.append((counterparty, new_path, next_tracked_amount, is_post_match))
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
