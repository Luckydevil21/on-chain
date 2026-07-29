"""
====================================================================
 CRYPTO ADDRESS WATCHER - Pattern-Matching Extraction (No AI/API needed)
====================================================================

WHAT THIS SCRIPT DOES (plain English):
This script visits a list of public sources you provide (security
blogs/RSS feeds, public Telegram channels, and optionally X/Twitter
accounts), pulls the recent text from each one, and scans that text
using pattern-matching rules to find anything that looks like a real
cryptocurrency wallet address (Bitcoin, Ethereum, etc.).

This does NOT require any AI service, API key, or subscription for
the extraction step - it works by checking text against the strict,
publicly documented technical format that every real crypto address
must follow (e.g. an Ethereum address is always "0x" followed by
exactly 40 specific characters). This makes it fast, free, and 100%
predictable - the same address will always be caught the same way.

Every run prints a FULL REPORT of everything found, whether or not
any of it is new. Addresses that are brand new (not on your
KNOWN_ADDRESSES list) are clearly flagged with a 🚨 marker inside
that report, and if there's at least one, a big unmissable alert
banner is also shown. Everything - new and previously known - gets
saved into a clean Excel spreadsheet for the team.

IMPORTANT SCOPE NOTE:
Actual ransomware "leak sites" typically live on the dark web (Tor
.onion addresses) and are deliberately built to block automated
scraping. This script is designed for PUBLIC, surface-web sources
(research blogs, public Telegram previews, X/Twitter) - the same
kind of OSINT sources analysts monitor daily. For direct dark-web
leak-site monitoring, your team should use a specialized commercial
platform (e.g. Flare.io) built and hardened specifically for that.

HOW TO RUN THIS SCRIPT (step-by-step, no coding knowledge needed):

STEP 1 - Install Python (if you don't already have it):
    Download from https://www.python.org/downloads/
    (During install, tick the box "Add Python to PATH")

STEP 2 - Install the required libraries. Open your terminal
    (Command Prompt / Terminal app) and type this ONE line:

        pip install requests feedparser beautifulsoup4 openpyxl pandas

STEP 3 - (Optional) Add an X/Twitter Bearer Token if you want to
    monitor X accounts. This requires a paid X API plan. If you
    skip this, just leave TWITTER_HANDLES_TO_MONITOR empty - the
    script will simply skip that source and keep working fine.

STEP 4 - Edit the source lists below (RSS feeds, Telegram channels,
    Twitter handles, and your baseline "already seen" addresses).

STEP 5 - Run it:

        python crypto_address_watcher.py

    A file called "crypto_addresses_report.xlsx" will be created
    in the same folder, and a full report will print to the screen
    every time you run it.

NO API KEY IS REQUIRED TO RUN THIS SCRIPT.
====================================================================
"""

import sys

# PLAIN ENGLISH: Windows' older default text encoding (cp1252) cannot
# display emoji like 🚨 and can crash the script with a "charmap
# codec" error. This line switches the script's output to modern
# UTF-8 text encoding, which supports emoji, on any operating system.
# It's wrapped in a safety check because very old Python versions
# don't support this - if that happens, the script just continues
# normally without emoji rather than crashing.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# ---- Built-in libraries (already included with Python, no install needed) ----
import os
import re
import json
import time
from datetime import datetime, timezone

# ---- External libraries (install with the pip command in STEP 2) ----
import requests                # Lets Python fetch web pages, like a browser
import feedparser              # Parses RSS/Atom feeds from security blogs
from bs4 import BeautifulSoup  # Reads and extracts text out of raw HTML
import pandas as pd            # Builds and saves our final Excel report


# ====================================================================
# SECTION 1: SETTINGS YOU CAN EDIT
# (Everything an analyst needs to change lives in this block)
# ====================================================================

# --------------------------------------------------------------
# Public security-research blog RSS feeds. Most security blogs have
# an RSS feed URL, often ending in /feed or /rss.
# --------------------------------------------------------------
RSS_FEED_URLS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed/",
]

# --------------------------------------------------------------
# Public Telegram channel usernames (the part after t.me/). This
# script reads the PUBLIC web preview of these channels, so no
# Telegram login or bot token is required - only public channels
# work this way.
# --------------------------------------------------------------
TELEGRAM_CHANNELS_TO_MONITOR = [
    "cryptosignals",
    "tradercryptotrading",
    "cryptobot",
    "crypto",
    "whale_alert_io",
    "CRYPTO_jokker",
    "crypto_scalp_signals",
    "NoName057",
    "Cryptobot",
    "airdropbot",
    "CRYPTO_RECOVERY_WALLET_FINDER",
    "wallet",
    "iCY6vlRlkfEzNjc5"
]

# --------------------------------------------------------------
# OPTIONAL: X/Twitter handles to monitor (without the @ symbol).
# Requires a paid X API Bearer Token below. Leave both empty to
# skip X/Twitter monitoring entirely.
# --------------------------------------------------------------
TWITTER_BEARER_TOKEN = ""          # PASTE_YOUR_X_API_BEARER_TOKEN_HERE (optional)
TWITTER_HANDLES_TO_MONITOR = [ "vashist7560",
                              "Fxxiill"
    # "vxunderground",      # EXAMPLE - uncomment and edit to use
]

# --------------------------------------------------------------
# OPTIONAL: Your free Etherscan API key. If you provide this, the
# script will look up EXTRA blockchain details for every Ethereum-
# style address it finds - current balance, how many transactions
# it has made, and when it was last active. Leave this blank to
# skip that step and run exactly as before (Bitcoin addresses are
# not affected either way - Etherscan only covers Ethereum-style).
#
# To get a free key:
#   1. Go to https://etherscan.io/register
#   2. Create a free account
#   3. Go to https://etherscan.io/myapikey
#   4. Click "Add" to generate a key, then paste it below
# --------------------------------------------------------------
ETHERSCAN_API_KEY = os.environ.get(
    "ETHERSCAN_API_KEY", "DSYVYN6A6E1FKWNGIPZRYDUR349XEUWYCZ"
)    # PASTE_YOUR_ETHERSCAN_API_KEY_HERE (optional), or set the env var instead

# --------------------------------------------------------------
# Addresses we already know about / have already logged. Any
# address found that is NOT in this list is treated as "NEW" and
# will be flagged in the report. Start this list with any addresses
# your team has already documented.
# --------------------------------------------------------------
KNOWN_ADDRESSES = [
    "0xae2fc483527b8ef99eb5d9b44875f005ba1fae13",
    "0x74d1cdAB3D434C610beFa65C3bB30F602846939e",
    "bc1qwq5k2qw2s0wj3fjx9hpvtqgww9k63qywp4xelx",
    "rEb8TK3gBgk5auZkwc6sHnwrGVJH8DuaLh",
    
]

# --------------------------------------------------------------
# Shared "case watchlist" file. Every NEW address this script finds
# gets appended here automatically. wallet_watcher.py reads from
# this same file, so a newly-discovered address starts getting
# monitored for movement without you having to copy/paste it
# anywhere - this is what links the two tools together.
# --------------------------------------------------------------
CASE_WATCHLIST_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "case_watchlist.json"
)

# --------------------------------------------------------------
# Where to save the final Excel report.
# --------------------------------------------------------------
OUTPUT_EXCEL_FILE = "crypto_addresses_report.xlsx"

# --------------------------------------------------------------
# Pause (in seconds) between web requests, to be a polite,
# well-behaved script and avoid getting rate-limited/blocked.
# --------------------------------------------------------------
SECONDS_BETWEEN_REQUESTS = 1.0

# --------------------------------------------------------------
# How many characters of surrounding text to capture as "context"
# around each address we find (helps analysts understand WHY the
# address was mentioned without reading the whole article).
# --------------------------------------------------------------
CONTEXT_CHARACTERS = 80


# ====================================================================
# SECTION 2: THE LOGIC (you shouldn't need to edit anything below)
# ====================================================================

# --------------------------------------------------------------
# These are the pattern-matching rules ("regular expressions") that
# define what a real crypto address looks like. Each one is paired
# with a human-readable label for the coin type it matches.
#   - Ethereum-style: "0x" + exactly 40 hex characters (used by ETH,
#     BNB Smart Chain, Polygon, and many others)
#   - Bitcoin Legacy/SegWit: starts with "1" or "3", 25-34 characters
#   - Bitcoin Native SegWit ("bech32"): starts with "bc1"
# --------------------------------------------------------------
ADDRESS_PATTERNS = [
    (r"0x[a-fA-F0-9]{40}", "Ethereum-style (ETH/BNB/etc.)"),
    (r"\bbc1[a-z0-9]{25,39}\b", "Bitcoin (Native SegWit)"),
    (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", "Bitcoin (Legacy/SegWit)"),
    (r"\br[a-km-zA-HJ-NP-Z1-9]{24,34}\b", "XRP (Ripple)"),
]


def fetch_rss_articles(feed_url):
    """
    PLAIN ENGLISH: This function visits a security blog's RSS feed
    (a standard, machine-readable summary of a blog's recent posts)
    and pulls out the title and text summary of each recent article.
    """
    articles = []
    try:
        # feedparser handles all the technical work of reading the
        # RSS/Atom format for us and gives back a clean list of entries.
        parsed_feed = feedparser.parse(feed_url)

        # LOOP: go through every article entry the feed returned.
        for entry in parsed_feed.entries:
            title = entry.get("title", "")
            summary = entry.get("summary", "")
            link = entry.get("link", feed_url)
            # Combine the title and summary into one block of text to
            # scan for addresses.
            combined_text = f"{title}\n{summary}"
            articles.append({"source": link, "text": combined_text})

    except Exception as error:
        print(f"  ⚠️  Could not read RSS feed {feed_url}: {error}")

    return articles


def fetch_telegram_channel_posts(channel_username):
    """
    PLAIN ENGLISH: Public Telegram channels have a public "preview"
    web page at https://t.me/s/<channel_name> that anyone can view
    in a browser, with no login required. This function downloads
    that page and extracts the text of each recent message.
    """
    posts = []
    preview_url = f"https://t.me/s/{channel_username}"

    try:
        # This line fetches the raw HTML of the public preview page,
        # the same way your browser would when you visit the URL.
        response = requests.get(preview_url, timeout=15)

        # BeautifulSoup reads that raw HTML and lets us search through
        # it easily, similar to how you'd use Ctrl+F on a webpage.
        soup = BeautifulSoup(response.text, "html.parser")

        # Telegram's preview page wraps each message's text in an
        # element with the class "tgme_widget_message_text". This
        # loop finds every one of those on the page.
        message_elements = soup.find_all(class_="tgme_widget_message_text")

        for element in message_elements:
            message_text = element.get_text(separator=" ", strip=True)
            posts.append({"source": preview_url, "text": message_text})

    except Exception as error:
        print(f"  ⚠️  Could not read Telegram channel '{channel_username}': {error}")

    return posts


def fetch_twitter_posts(handle, bearer_token):
    """
    PLAIN ENGLISH: This function asks X/Twitter's official API for a
    given account's recent posts. NOTE: this requires a paid X API
    plan and a valid Bearer Token - if you don't have one, just leave
    TWITTER_HANDLES_TO_MONITOR empty and this function will be skipped.
    """
    posts = []

    # CONDITIONAL: if no token was provided, there's nothing we can
    # do, so skip cleanly instead of sending a request that will fail.
    if not bearer_token:
        return posts

    headers = {"Authorization": f"Bearer {bearer_token}"}

    try:
        # Step A: look up the account's internal numeric user ID from
        # their @handle (the API requires the ID, not the handle).
        user_lookup_url = f"https://api.twitter.com/2/users/by/username/{handle}"
        user_response = requests.get(user_lookup_url, headers=headers, timeout=15)
        user_data = user_response.json()
        user_id = user_data.get("data", {}).get("id")

        if not user_id:
            print(f"  ⚠️  Could not find X/Twitter user '{handle}'.")
            return posts

        # Step B: fetch that user's most recent posts.
        tweets_url = f"https://api.twitter.com/2/users/{user_id}/tweets"
        params = {"max_results": 20}
        tweets_response = requests.get(tweets_url, headers=headers, params=params, timeout=15)
        tweets_data = tweets_response.json()

        for tweet in tweets_data.get("data", []):
            posts.append({"source": f"https://x.com/{handle}", "text": tweet.get("text", "")})

    except Exception as error:
        print(f"  ⚠️  Could not read X/Twitter account '{handle}': {error}")

    return posts


def extract_addresses_with_patterns(text, source):
    """
    PLAIN ENGLISH: This is the core extraction step. Instead of using
    AI, we scan the text directly against the strict technical rules
    that define what a real crypto address looks like (defined in
    ADDRESS_PATTERNS above). For every match found, we also grab a
    short snippet of surrounding text as "context", so an analyst can
    see why the address was mentioned without reading the full article.
    """
    findings = []

    # CONDITIONAL: skip empty text, nothing to scan.
    if not text or not text.strip():
        return findings

    # LOOP: check the text against each of our known address patterns
    # one at a time (Ethereum-style, then the two Bitcoin formats).
    for pattern, coin_type in ADDRESS_PATTERNS:

        # re.finditer scans the ENTIRE text and returns every place
        # the pattern matches, not just the first one.
        for match in re.finditer(pattern, text):
            matched_address = match.group()

            # Work out where in the text this match starts and ends,
            # so we can grab some surrounding words as context.
            start_position = max(0, match.start() - CONTEXT_CHARACTERS)
            end_position = min(len(text), match.end() + CONTEXT_CHARACTERS)
            context_snippet = text[start_position:end_position].strip()
            # Clean up messy whitespace/line breaks in the snippet.
            context_snippet = re.sub(r"\s+", " ", context_snippet)

            findings.append({
                "address": matched_address,
                "coin_type": coin_type,
                "context": context_snippet,
                "source": source,
                "found_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            })

    return findings


def group_findings_by_address(all_findings, known_lowercase_baseline):
    """
    PLAIN ENGLISH: This function takes the raw, line-by-line list of
    every match found (which can include the SAME address appearing
    many times across different sources) and consolidates it into
    one entry per unique address. Each entry keeps track of every
    place that address was seen, and whether it's a brand new
    address or one we already knew about BEFORE this run started.
    """
    grouped = {}

    # LOOP: go through every single match found across every source.
    for finding in all_findings:
        address_key = finding["address"].lower()

        # CONDITIONAL: if this is the first time we've seen this
        # particular address in this run, start a new entry for it.
        if address_key not in grouped:
            grouped[address_key] = {
                "address": finding["address"],
                "coin_type": finding["coin_type"],
                "is_new": address_key not in known_lowercase_baseline,
                "sightings": [],
            }

        # Record this particular sighting (source + context), even if
        # we've seen this same address before elsewhere in this run.
        grouped[address_key]["sightings"].append({
            "source": finding["source"],
            "context": finding["context"],
        })

    return grouped


# ====================================================================
# SECTION 2B: SHARED CASE WATCHLIST (links this script to wallet_watcher.py)
# ====================================================================

# Maps this script's human-readable coin_type labels (from
# ADDRESS_PATTERNS above) to the plain chain name wallet_watcher.py
# expects when it re-checks these addresses.
COIN_TYPE_TO_CHAIN = {
    "Ethereum-style (ETH/BNB/etc.)": "ethereum",
    "Bitcoin (Native SegWit)": "bitcoin",
    "Bitcoin (Legacy/SegWit)": "bitcoin",
    "XRP (Ripple)": "xrp",
}


def load_case_watchlist():
    """
    PLAIN ENGLISH: Reads the shared case_watchlist.json file (if it
    exists yet) and returns its contents as a list of entries. Starts
    as an empty list the very first time this script runs.
    """
    if not os.path.isfile(CASE_WATCHLIST_FILE):
        return []
    try:
        with open(CASE_WATCHLIST_FILE, "r", encoding="utf-8") as file_handle:
            return json.load(file_handle)
    except (json.JSONDecodeError, OSError) as error:
        print(f"  ⚠️  Could not read {CASE_WATCHLIST_FILE}: {error}")
        print("     (Leaving the existing file untouched rather than overwriting it.)")
        return None  # None signals "don't touch this file" to the caller


def save_case_watchlist(entries):
    """PLAIN ENGLISH: Writes the case watchlist back out to disk, pretty-printed."""
    with open(CASE_WATCHLIST_FILE, "w", encoding="utf-8") as file_handle:
        json.dump(entries, file_handle, indent=2)


def sync_new_addresses_to_case_watchlist(grouped_findings):
    """
    PLAIN ENGLISH: Takes every address this run flagged as NEW (i.e.
    not already on your KNOWN_ADDRESSES baseline) and appends it to
    the shared case_watchlist.json file, so wallet_watcher.py will
    automatically start monitoring it for movement - no manual
    copy/pasting between tools required.

    Addresses already on the case watchlist are skipped (no
    duplicates). Returns the list of addresses actually added this run.
    """
    existing_entries = load_case_watchlist()
    if existing_entries is None:
        return []  # File exists but is corrupted - don't risk overwriting it

    existing_addresses_lowercase = {entry["address"].lower() for entry in existing_entries}
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    newly_added = []
    for entry in grouped_findings.values():
        if not entry["is_new"]:
            continue
        address_lower = entry["address"].lower()
        if address_lower in existing_addresses_lowercase:
            continue

        chain = COIN_TYPE_TO_CHAIN.get(entry["coin_type"], "unknown")
        first_sighting = entry["sightings"][0] if entry["sightings"] else {}

        existing_entries.append({
            "address": entry["address"],
            "chain": chain,
            "coin_type": entry["coin_type"],
            "first_seen_utc": run_timestamp,
            "discovered_via": "crypto_address_watcher.py",
            "source": first_sighting.get("source", ""),
            "context": first_sighting.get("context", ""),
        })
        existing_addresses_lowercase.add(address_lower)
        newly_added.append(entry["address"])

    if newly_added:
        save_case_watchlist(existing_entries)

    return newly_added


def get_etherscan_wallet_details(address, api_key):
    """
    PLAIN ENGLISH: This function asks Etherscan for extra details about
    ONE Ethereum-style address: its current balance, how many
    transactions it has ever made, and when it was last active. This
    is the same public blockchain data anyone can look up by hand on
    etherscan.io - we're just automating the lookup.

    Returns a dictionary of details, or a dictionary noting the
    lookup failed (so the rest of the report can keep running even if
    one lookup has a problem).
    """
    details = {
        "eth_balance": None,
        "tx_count": None,
        "last_activity_utc": None,
        "lookup_note": "",
    }

    url = "https://api.etherscan.io/v2/api"

    try:
        # ---- Step A: current balance ----
        # module=account & action=balance returns the wallet's current
        # ETH balance, given in "Wei" (the smallest unit of ETH) - we
        # divide by 10^18 to convert it into normal, human-readable ETH.
        balance_params = {
            "module": "account",
            "action": "balance",
            "address": address,
            "tag": "latest",
            "apikey": api_key,
        }
        balance_response = requests.get(url, params=balance_params, timeout=15)
        balance_data = balance_response.json()

        if balance_data.get("status") == "1":
            raw_wei = int(balance_data.get("result", 0))
            details["eth_balance"] = raw_wei / 1_000_000_000_000_000_000

        # ---- Step B: transaction history (for count + last activity) ----
        # module=account & action=txlist, sorted newest-first, gives us
        # the wallet's transaction history. The FIRST result in a
        # "desc" sort is the most recent transaction.
        tx_params = {
            "module": "account",
            "action": "txlist",
            "address": address,
            "sort": "desc",
            "apikey": api_key,
        }
        tx_response = requests.get(url, params=tx_params, timeout=15)
        tx_data = tx_response.json()

        if tx_data.get("status") == "1":
            transactions = tx_data.get("result", [])
            details["tx_count"] = len(transactions)

            # CONDITIONAL: only try to read the most recent transaction
            # if the wallet actually has at least one.
            if transactions:
                most_recent_timestamp = int(transactions[0]["timeStamp"])
                most_recent_datetime = datetime.fromtimestamp(
                    most_recent_timestamp, tz=timezone.utc
                )
                details["last_activity_utc"] = most_recent_datetime.strftime("%Y-%m-%d %H:%M:%S")
        else:
            details["tx_count"] = 0

    except Exception as error:
        details["lookup_note"] = f"Lookup failed: {error}"

    return details


def enrich_ethereum_addresses(grouped_findings, api_key):
    """
    PLAIN ENGLISH: This goes through every unique address found this
    run and, for any that are Ethereum-style, adds balance/activity
    details onto that address's entry using get_etherscan_wallet_details
    above. Bitcoin addresses are skipped, since Etherscan only covers
    Ethereum and Ethereum-compatible chains.
    """
    # CONDITIONAL: if no API key was provided, skip this whole step
    # and say so clearly, rather than silently doing nothing.
    if not api_key:
        print("\n(Etherscan enrichment skipped - no ETHERSCAN_API_KEY configured.)")
        return

    ethereum_entries = [
        entry for entry in grouped_findings.values()
        if entry["coin_type"].startswith("Ethereum-style")
    ]

    # CONDITIONAL: nothing to enrich if no Ethereum-style addresses
    # were found this run.
    if not ethereum_entries:
        return

    print(f"\nLooking up Etherscan details for {len(ethereum_entries)} Ethereum-style address(es)...")

    # LOOP: enrich one Ethereum-style address at a time.
    for entry in ethereum_entries:
        details = get_etherscan_wallet_details(entry["address"], api_key)
        entry.update(details)
        # Small pause between lookups to stay within Etherscan's free
        # rate limit and avoid getting temporarily blocked.
        time.sleep(SECONDS_BETWEEN_REQUESTS)


def print_known_baseline(known_addresses_list):
    """
    PLAIN ENGLISH: This prints your KNOWN_ADDRESSES list at the start
    of every run, so you can always see exactly what the script is
    using as its "already seen" baseline. Note: this list only shows
    addresses YOU have added to KNOWN_ADDRESSES at the top of the
    script - it does not mean those addresses were found anywhere in
    today's scan. Whether they were actually mentioned in today's
    sources is shown separately, in the main scan report below.
    """
    print("\n" + "-" * 60)
    print(f"Known-address baseline loaded: {len(known_addresses_list)} address(es)")
    if known_addresses_list:
        for address in known_addresses_list:
            print(f"  - {address}")
    else:
        print("  (KNOWN_ADDRESSES is empty - every address found today will count as new)")
    print("-" * 60)


def print_full_scan_report(grouped_findings):
    """
    PLAIN ENGLISH: This prints the main report every time the script
    runs, regardless of whether anything new was found. It lists
    EVERY unique address discovered this run, grouped by coin type,
    with a 🚨 NEW marker next to anything that wasn't already on our
    KNOWN_ADDRESSES list before this run started.
    """
    print("\n" + "=" * 60)
    print("CRYPTO ADDRESS SCAN REPORT")
    print("=" * 60)

    total_unique = len(grouped_findings)
    new_count = sum(1 for entry in grouped_findings.values() if entry["is_new"])
    already_known_count = total_unique - new_count

    print(f"Unique addresses found this run : {total_unique}")
    print(f"  - Brand new                   : {new_count}")
    print(f"  - Already on your known list  : {already_known_count}")

    # CONDITIONAL: if nothing was found at all, say so plainly and
    # stop here - no point printing empty sections below.
    if total_unique == 0:
        print("\nNo crypto addresses were found in any source this run.")
        print("(This is different from your KNOWN_ADDRESSES baseline above, which is")
        print(" just the reference list - it only appears here if actually re-mentioned.)")
        print("=" * 60)
        return

    # Group entries by coin type so the report reads cleanly, e.g.
    # all Ethereum-style addresses together, then all Bitcoin ones.
    coin_types_present = sorted({entry["coin_type"] for entry in grouped_findings.values()})

    # LOOP: print one section per coin type found.
    for coin_type in coin_types_present:
        entries_of_this_type = [
            entry for entry in grouped_findings.values() if entry["coin_type"] == coin_type
        ]
        print(f"\n--- {coin_type} ({len(entries_of_this_type)} unique address(es)) ---")

        # LOOP: print every unique address of this coin type.
        for entry in entries_of_this_type:
            # CONDITIONAL: prefix brand-new addresses with a clear
            # visual marker so they stand out inside the full list.
            new_marker = "🚨 NEW -> " if entry["is_new"] else "         "
            print(f"{new_marker}{entry['address']}")

            # CONDITIONAL: if this entry has Etherscan enrichment data
            # attached (added by enrich_ethereum_addresses), show it
            # right under the address.
            if "eth_balance" in entry:
                if entry.get("lookup_note"):
                    print(f"              Etherscan: {entry['lookup_note']}")
                else:
                    balance = entry.get("eth_balance")
                    tx_count = entry.get("tx_count")
                    last_activity = entry.get("last_activity_utc")
                    balance_text = f"{balance:.6f} ETH" if balance is not None else "unknown"
                    tx_text = tx_count if tx_count is not None else "unknown"
                    activity_text = last_activity if last_activity else "no transactions found"
                    print(f"              Balance   : {balance_text}")
                    print(f"              Tx count  : {tx_text}")
                    print(f"              Last active: {activity_text} (UTC)")

            # Show up to 2 example sightings (source + context) per
            # address, so the report stays readable even if an
            # address was mentioned dozens of times.
            for sighting in entry["sightings"][:2]:
                print(f"              Source : {sighting['source']}")
                print(f"              Context: {sighting['context']}")
            if len(entry["sightings"]) > 2:
                remaining = len(entry["sightings"]) - 2
                print(f"              ...and {remaining} more mention(s) of this address")

    print("\n" + "=" * 60)


def print_new_address_alert_banner(grouped_findings):
    """
    PLAIN ENGLISH: In addition to the full report above, this prints
    one extra, extremely visible banner - but ONLY listing the
    brand-new addresses - so a busy analyst scanning the terminal
    can't miss that something needs attention, even if they don't
    read the full report line by line.
    """
    new_entries = [entry for entry in grouped_findings.values() if entry["is_new"]]

    # CONDITIONAL: only show this extra banner if there's actually
    # something new to flag.
    if not new_entries:
        return

    print("\n" + "🚨" * 20)
    print("🚨  ALERT: NEW CRYPTO ADDRESS(ES) DISCOVERED  🚨")
    print("🚨" * 20)
    for entry in new_entries:
        first_sighting = entry["sightings"][0]
        print(f"  Address : {entry['address']}")
        print(f"  Type    : {entry['coin_type']}")
        print(f"  Context : {first_sighting['context']}")
        print(f"  Source  : {first_sighting['source']}")
        print("  " + "-" * 40)
    print("🚨" * 20 + "\n")


def run_crypto_address_watch():
    """
    PLAIN ENGLISH: This is the main function that ties the whole
    workflow together: gather text from all sources, scan each piece
    of text for address patterns, build the full report, flag
    brand-new addresses, and save everything to an Excel report.
    """

    print("=" * 60)
    print("Starting crypto address watch (pattern-matching mode)")
    print("=" * 60)

    # Show the user exactly what "known addresses" baseline is loaded,
    # right at the start, before any scanning happens.
    print_known_baseline(KNOWN_ADDRESSES)

    # This list will hold EVERY block of text we gather from every
    # source, before we scan each one for addresses.
    all_text_blocks = []

    # ---- Gather text from RSS/blog feeds ----
    print("\nFetching RSS/blog feeds...")
    for feed_url in RSS_FEED_URLS:
        articles = fetch_rss_articles(feed_url)
        all_text_blocks.extend(articles)
        print(f"  {feed_url} -> {len(articles)} article(s) found")
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    # ---- Gather text from public Telegram channel previews ----
    print("\nFetching Telegram channel previews...")
    for channel in TELEGRAM_CHANNELS_TO_MONITOR:
        posts = fetch_telegram_channel_posts(channel)
        all_text_blocks.extend(posts)
        print(f"  {channel} -> {len(posts)} message(s) found")
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    # ---- Gather text from X/Twitter (only runs if a token was set) ----
    print("\nFetching X/Twitter accounts...")
    for handle in TWITTER_HANDLES_TO_MONITOR:
        posts = fetch_twitter_posts(handle, TWITTER_BEARER_TOKEN)
        all_text_blocks.extend(posts)
        print(f"  @{handle} -> {len(posts)} post(s) found")
        time.sleep(SECONDS_BETWEEN_REQUESTS)

    print(f"\nTotal text blocks collected from all sources: {len(all_text_blocks)}")
    print("Scanning each text block for crypto addresses...")

    # This list will hold every individual address match found across
    # every source (the same address can appear here more than once).
    all_findings = []

    # MAIN LOOP: run the pattern-matching scan on every single text
    # block we collected, one at a time.
    for block in all_text_blocks:
        findings = extract_addresses_with_patterns(block["text"], block["source"])
        all_findings.extend(findings)

    print(f"Scanning complete. {len(all_findings)} total address match(es) found.")

    # Build the set of addresses we already knew about BEFORE this run
    # started (lowercased for consistent comparison, since crypto
    # addresses aren't case-sensitive in most formats). We snapshot
    # this now, before grouping, so "new" always means "new compared
    # to your saved list" - not "new compared to earlier in this run".
    known_lowercase_baseline = {addr.lower() for addr in KNOWN_ADDRESSES}

    # Consolidate every match into one entry per unique address, and
    # tag each one as new or already-known.
    grouped_findings = group_findings_by_address(all_findings, known_lowercase_baseline)

    # OPTIONAL STEP: if an Etherscan API key was provided, look up
    # extra blockchain details (balance, transaction count, last
    # activity) for every Ethereum-style address found this run. This
    # happens BEFORE the report is printed, so those details show up
    # inside it.
    enrich_ethereum_addresses(grouped_findings, ETHERSCAN_API_KEY)

    # ALWAYS print the full report, regardless of whether anything
    # new was found - this is the main change from before: previously
    # we only printed anything when new addresses turned up.
    print_full_scan_report(grouped_findings)

    # On top of the full report, still show one extra, highly visible
    # banner - but only when there's genuinely something new to flag.
    print_new_address_alert_banner(grouped_findings)

    # ---- Push newly-found addresses into the shared case watchlist ----
    # PLAIN ENGLISH: This is what lets wallet_watcher.py automatically
    # start monitoring anything found here, without you having to
    # copy/paste addresses between tools.
    newly_added_to_case_watchlist = sync_new_addresses_to_case_watchlist(grouped_findings)
    if newly_added_to_case_watchlist:
        print(f"\n🔗 Added {len(newly_added_to_case_watchlist)} new address(es) to the shared "
              f"case watchlist ({os.path.basename(CASE_WATCHLIST_FILE)}):")
        for address in newly_added_to_case_watchlist:
            print(f"    {address}")
        print("   wallet_watcher.py will pick these up automatically next time it runs.")

    # ---- Save a report EVERY run, even if zero addresses were found ----
    # PLAIN ENGLISH: Previously, this only saved an Excel file when at
    # least one address was found - which meant a "clean" run (nothing
    # suspicious found) left no record at all. Now we always save a
    # report with tabs, so there's a consistent audit trail:
    #   1) "Findings"       - every address found this run (or empty)
    #   2) "Wallet_Details"  - Etherscan balance/activity per unique
    #                          Ethereum-style address (if a key is set)
    #   3) "Known_Baseline" - your KNOWN_ADDRESSES list, for reference
    #   4) "Scan_Summary"   - when this ran and the overall totals
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    if all_findings:
        findings_dataframe = pd.DataFrame(all_findings)
    else:
        # Even with zero results, we still create a properly-headed
        # (but empty) table, so the file structure never changes and
        # is safe to open in Excel or feed into other tools later.
        findings_dataframe = pd.DataFrame(
            columns=["address", "coin_type", "context", "source", "found_at_utc"]
        )

    # Build one row per unique address with its Etherscan enrichment
    # data (if any was looked up), for a clean, address-per-row view -
    # separate from "Findings", which has one row per individual
    # mention and can contain the same address multiple times.
    wallet_detail_rows = []
    for entry in grouped_findings.values():
        wallet_detail_rows.append({
            "address": entry["address"],
            "coin_type": entry["coin_type"],
            "is_new": entry["is_new"],
            "times_mentioned": len(entry["sightings"]),
            "eth_balance": entry.get("eth_balance"),
            "tx_count": entry.get("tx_count"),
            "last_activity_utc": entry.get("last_activity_utc"),
            "lookup_note": entry.get("lookup_note", ""),
        })
    wallet_details_dataframe = pd.DataFrame(wallet_detail_rows) if wallet_detail_rows else pd.DataFrame(
        columns=["address", "coin_type", "is_new", "times_mentioned",
                 "eth_balance", "tx_count", "last_activity_utc", "lookup_note"]
    )

    known_baseline_dataframe = pd.DataFrame(
        {"known_address": KNOWN_ADDRESSES}
    )

    summary_dataframe = pd.DataFrame([{
        "run_timestamp_utc": run_timestamp,
        "text_blocks_scanned": len(all_text_blocks),
        "total_address_matches": len(all_findings),
        "unique_addresses_found": len(grouped_findings),
        "new_addresses_found": sum(1 for entry in grouped_findings.values() if entry["is_new"]),
        "known_baseline_size": len(KNOWN_ADDRESSES),
        "etherscan_enrichment_enabled": bool(ETHERSCAN_API_KEY),
        "new_addresses_synced_to_case_watchlist": len(newly_added_to_case_watchlist),
    }])

    # openpyxl lets us write multiple tabs into one Excel file.
    with pd.ExcelWriter(OUTPUT_EXCEL_FILE, engine="openpyxl") as writer:
        findings_dataframe.to_excel(writer, sheet_name="Findings", index=False)
        wallet_details_dataframe.to_excel(writer, sheet_name="Wallet_Details", index=False)
        known_baseline_dataframe.to_excel(writer, sheet_name="Known_Baseline", index=False)
        summary_dataframe.to_excel(writer, sheet_name="Scan_Summary", index=False)

    print(f"📊 Report saved to: {OUTPUT_EXCEL_FILE}")
    print("   (tabs: Findings, Wallet_Details, Known_Baseline, Scan_Summary)")

    new_count = sum(1 for entry in grouped_findings.values() if entry["is_new"])

    print("\n" + "=" * 60)
    print("RUN COMPLETE")
    print(f"Text blocks scanned      : {len(all_text_blocks)}")
    print(f"Total address matches    : {len(all_findings)}")
    print(f"Unique addresses found   : {len(grouped_findings)}")
    print(f"New addresses found      : {new_count}")
    print("=" * 60)


# ====================================================================
# SECTION 3: SCRIPT ENTRY POINT
# This is the part that actually runs when you type
# "python crypto_address_watcher.py" in your terminal.
# ====================================================================
if __name__ == "__main__":
    run_crypto_address_watch()
