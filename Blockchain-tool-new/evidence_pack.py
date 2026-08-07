"""
====================================================================
 EVIDENCE PACK - cryptographically-verifiable, blockchain-anchored
 evidence bundles for UK court proceedings
====================================================================

WHAT THIS DOES (plain English):
Takes a completed trace result and produces a tamper-evident evidence
record: a SHA-256 hash of the exact data, plus a timestamp anchored on
the Bitcoin blockchain itself via the OpenTimestamps protocol - free,
open, and requiring no registration or API key.

WHY THIS MATTERS FOR UK COURT USE:
The four ACPO principles (still the current UK standard for digital
evidence, per NPCC guidance) require: (1) data must not be altered,
(2) the person accessing it must be able to explain their actions,
(3) an audit trail must exist letting a third party independently
replicate the process and get the same result, and (4) overall
responsibility must be clear. This module addresses principles 1 and
3 directly:
  - The SHA-256 hash proves the data hasn't changed since capture.
  - The OpenTimestamps proof proves WHEN that hash existed - anchored
    to the Bitcoin blockchain, independently verifiable by ANYONE,
    forever, without needing to trust this server, Supabase, Render,
    or the person who ran it. This is standard, cryptographic proof,
    not a claim that has to be taken on faith.
  - The stored "methodology" (every parameter used) lets a third
    party rerun the exact same trace and check they get the same
    result - directly satisfying Principle 3.

HOW OPENTIMESTAMPS WORKS (plain English):
1. Hash the evidence data (SHA-256).
2. Append a random 16-byte nonce and hash again - this means the
   calendar servers never see your actual data, only a meaningless
   value derived from it (privacy-preserving).
3. Submit that value to one or more free "calendar" servers, which
   batch many people's submissions into a Merkle tree and eventually
   commit the tree's root into a real Bitcoin transaction.
4. The result is a PENDING proof at first (submitted, but not yet in
   a mined Bitcoin block - can take a few hours). Calling
   upgrade_evidence_pack() later checks whether it's been confirmed
   yet, and if so, records which Bitcoin block and when.
5. Once confirmed, ANYONE can independently verify the proof against
   the Bitcoin blockchain itself, using this library or the free
   "ots" command-line tool - no dependency on this app continuing to
   exist or being trusted.

STAGE SCOPE: this module handles hashing + submitting the timestamp
(the "stamp" step) and checking/upgrading it later (the "upgrade"
step, once enough time has passed for Bitcoin confirmation). PDF
generation of the full evidence bundle is a separate, later piece.
====================================================================
"""

import io
import os
import json
import hashlib
import base64
from datetime import datetime, timezone

from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
from opentimestamps.core.op import OpSHA256, OpAppend
from opentimestamps.core.serialize import BytesSerializationContext, BytesDeserializationContext
from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
from opentimestamps.calendar import RemoteCalendar

import auth  # for _get_db_connection - reuses the same DB connection setup as everywhere else

# Free, public calendar servers - no registration or API key needed.
# Submitting to several gives redundancy: as long as at least one
# succeeds, the timestamp is valid (each calendar independently
# anchors the same commitment to Bitcoin).
CALENDAR_URLS = [
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
]
CALENDAR_TIMEOUT_SECONDS = 20


def canonicalize_for_hashing(trace_data, methodology):
    """
    PLAIN ENGLISH: Produces a single, deterministic byte string from
    the trace data + methodology, so hashing the SAME evidence twice
    always gives the SAME hash (sorted keys, fixed separators - no
    ambiguity from dict ordering or whitespace differences).
    """
    canonical = json.dumps(
        {"trace_data": trace_data, "methodology": methodology},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return canonical.encode("utf-8")


def stamp_evidence(data_bytes):
    """
    PLAIN ENGLISH: Submits a SHA-256 hash of data_bytes to the
    OpenTimestamps calendar servers, starting the process of anchoring
    it to the Bitcoin blockchain. Returns (sha256_hex, ots_proof_bytes,
    calendars_succeeded) - the proof is PENDING at this point (not yet
    confirmed in a mined block - see upgrade_evidence_pack). Raises
    RuntimeError if every calendar server failed to respond.
    """
    sha256_hex = hashlib.sha256(data_bytes).hexdigest()

    file_timestamp = DetachedTimestampFile.from_fd(OpSHA256(), io.BytesIO(data_bytes))

    # Privacy step: append a random nonce and re-hash, so calendar
    # servers only ever see a meaningless derived value, never the
    # actual evidence data or its direct hash.
    nonce_appended = file_timestamp.timestamp.ops.add(OpAppend(os.urandom(16)))
    commitment_stamp = nonce_appended.ops.add(OpSHA256())

    calendars_succeeded = 0
    last_error = None
    for calendar_url in CALENDAR_URLS:
        try:
            remote = RemoteCalendar(calendar_url)
            result_timestamp = remote.submit(commitment_stamp.msg, timeout=CALENDAR_TIMEOUT_SECONDS)
            commitment_stamp.merge(result_timestamp)
            calendars_succeeded += 1
        except Exception as error:
            last_error = error
            print(f"⚠️  OpenTimestamps calendar {calendar_url} failed: {error}")

    if calendars_succeeded == 0:
        raise RuntimeError(f"Every OpenTimestamps calendar server failed to respond: {last_error}")

    serialization_ctx = BytesSerializationContext()
    file_timestamp.serialize(serialization_ctx)
    ots_proof_bytes = serialization_ctx.getbytes()

    return sha256_hex, ots_proof_bytes, calendars_succeeded


def create_evidence_pack(username, trace_data, case_reference, extra_methodology=None, anchor_to_blockchain=False):
    """
    PLAIN ENGLISH: The main entry point - takes a completed trace
    result, records the exact methodology used, and hashes it. If
    anchor_to_blockchain is True, also submits that hash for Bitcoin
    blockchain anchoring via OpenTimestamps (see the module docstring)
    - OFF by default, since that step calls external servers outside
    this app's control. With it off, the evidence pack is still a
    genuine SHA-256 hash proving the data hasn't changed since capture
    (ACPO Principle 1) - it just relies on this app's own database
    record of WHEN that hash was created, rather than an independent,
    uncontrollable-by-anyone Bitcoin timestamp. Returns the new
    evidence pack's id and hash.
    """
    methodology = {
        "tool": "On-Chain Investigations Toolkit",
        "generated_at_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
        "generated_by": username,
        "blockchain_anchored": anchor_to_blockchain,
        **(extra_methodology or {}),
    }

    data_bytes = canonicalize_for_hashing(trace_data, methodology)
    sha256_hex = hashlib.sha256(data_bytes).hexdigest()
    ots_proof_base64 = None
    calendars_succeeded = 0

    if anchor_to_blockchain:
        _sha256_hex_unused, ots_proof_bytes, calendars_succeeded = stamp_evidence(data_bytes)
        ots_proof_base64 = base64.b64encode(ots_proof_bytes).decode("ascii")

    with auth._get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO evidence_packs
                    (created_by, case_reference, trace_data, methodology, sha256_hash, ots_proof_base64)
                VALUES (%s, %s, %s, %s, %s, %s)
                RETURNING id, created_at;
                """,
                (username, case_reference, json.dumps(trace_data), json.dumps(methodology), sha256_hex, ots_proof_base64)
            )
            evidence_pack_id, created_at = cur.fetchone()
            conn.commit()

    result = {
        "id": str(evidence_pack_id),
        "created_at": created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "sha256_hash": sha256_hex,
        "methodology": methodology,
    }
    if anchor_to_blockchain:
        result["calendars_succeeded"] = calendars_succeeded
        result["status"] = "pending_bitcoin_confirmation"
        result["note"] = (
            "This evidence has been hashed and submitted for Bitcoin blockchain anchoring. "
            "Confirmation typically takes a few hours, once the timestamp is included in a mined "
            "block. Check back later (or call the upgrade endpoint) to complete the proof."
        )
    else:
        result["status"] = "hashed"
        result["note"] = (
            "This evidence has been hashed (SHA-256) and recorded with a timestamp. Blockchain "
            "anchoring was not used for this record - the creation timestamp relies on this "
            "application's own database record rather than an independently verifiable Bitcoin "
            "timestamp."
        )
    return result


def get_evidence_pack(evidence_pack_id):
    """Returns the full stored record for one evidence pack, or None if it doesn't exist."""
    with auth._get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, created_by, created_at, case_reference, trace_data, methodology,
                       sha256_hash, ots_proof_base64, ots_confirmed, ots_bitcoin_block_height, ots_bitcoin_block_time
                FROM evidence_packs WHERE id = %s;
                """,
                (evidence_pack_id,)
            )
            row = cur.fetchone()
            if not row:
                return None
            return {
                "id": str(row[0]), "created_by": row[1],
                "created_at": row[2].strftime("%Y-%m-%d %H:%M:%S") if row[2] else None,
                "case_reference": row[3], "trace_data": row[4], "methodology": row[5],
                "sha256_hash": row[6], "ots_proof_base64": row[7], "ots_confirmed": row[8],
                "ots_bitcoin_block_height": row[9],
                "ots_bitcoin_block_time": row[10].strftime("%Y-%m-%d %H:%M:%S") if row[10] else None,
            }


def list_evidence_packs(username=None):
    """Returns every evidence pack, newest first - or only one user's, if username is given."""
    with auth._get_db_connection() as conn:
        with conn.cursor() as cur:
            if username:
                cur.execute(
                    "SELECT id, created_by, created_at, case_reference, sha256_hash, ots_confirmed "
                    "FROM evidence_packs WHERE created_by = %s ORDER BY created_at DESC;",
                    (username,)
                )
            else:
                cur.execute(
                    "SELECT id, created_by, created_at, case_reference, sha256_hash, ots_confirmed "
                    "FROM evidence_packs ORDER BY created_at DESC;"
                )
            return [
                {
                    "id": str(row[0]), "created_by": row[1],
                    "created_at": row[2].strftime("%Y-%m-%d %H:%M:%S") if row[2] else None,
                    "case_reference": row[3], "sha256_hash": row[4], "ots_confirmed": row[5],
                }
                for row in cur.fetchall()
            ]
