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


# ====================================================================
# PDF GENERATION - the actual court-ready document
# ====================================================================
# Built with reportlab's Platypus layer (flowable, auto-paginating
# document elements) rather than raw canvas drawing - a trace with
# many hops needs to flow across as many pages as it takes, with
# repeating table headers, which Platypus handles automatically.
# ====================================================================

def _hop_rows_for_table(hops, cell_style):
    """Converts a list of hop dicts into table rows for reportlab, with a header row.
    Long values (addresses, hashes) are wrapped in Paragraph objects so they WRAP within
    the column width instead of overflowing into the next cell."""
    rows = [["From", "To", "Amount", "Time (UTC)", "Tx Hash"]]
    for hop in hops:
        from reportlab.platypus import Paragraph
        tx_hash = hop.get("tx_hash", "") or ""
        rows.append([
            Paragraph(hop.get("from_address", ""), cell_style),
            Paragraph(hop.get("to_address", ""), cell_style),
            Paragraph(hop.get("amount", ""), cell_style),
            Paragraph(hop.get("tx_time_utc", ""), cell_style),
            Paragraph(tx_hash, cell_style),
        ])
    return rows


def _path_group_flowables(title, paths, styles, path_key="hops"):
    """Builds the heading + table(s) for one group of paths (matched / flagged / amount-filtered)."""
    from reportlab.platypus import Paragraph, Table, TableStyle, Spacer
    from reportlab.lib import colors
    from reportlab.lib.units import mm

    flowables = []
    if not paths:
        return flowables

    flowables.append(Paragraph(title, styles["Heading2"]))
    for index, path in enumerate(paths, start=1):
        reason = path.get("reason")
        label = f"Path {index}" + (f" — {reason}" if reason else "")
        flowables.append(Paragraph(label, styles["Heading4"]))

        table_data = _hop_rows_for_table(path.get(path_key, []), styles["TableCell"])
        table = Table(table_data, repeatRows=1, colWidths=[36*mm, 36*mm, 24*mm, 26*mm, 48*mm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c232c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f5f7")]),
        ]))
        flowables.append(table)
        flowables.append(Spacer(1, 6*mm))

    return flowables


def generate_evidence_pack_pdf(evidence_pack_id):
    """
    PLAIN ENGLISH: Builds the actual court-ready PDF for one evidence
    pack - cover sheet, methodology, integrity/hash section (honestly
    reflecting whether blockchain anchoring was used or not), the full
    trace results with every hop, and a confidence-level explanation.
    Returns PDF bytes, or None if the evidence pack doesn't exist.
    """
    import io as _io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

    pack = get_evidence_pack(evidence_pack_id)
    if not pack:
        return None

    trace_data = pack["trace_data"]
    methodology = pack["methodology"]

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="SmallGrey", fontSize=8, textColor=colors.HexColor("#666666")))
    styles.add(ParagraphStyle(name="TableCell", fontName="Courier", fontSize=6.5, leading=8, wordWrap="CJK"))

    buffer = _io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=18*mm, bottomMargin=18*mm, leftMargin=16*mm, rightMargin=16*mm,
    )
    story = []

    # ---- Cover ----
    story.append(Paragraph("Blockchain Evidence Report", styles["Title"]))
    story.append(Paragraph("On-Chain Investigations Toolkit", styles["SmallGrey"]))
    story.append(Spacer(1, 8*mm))

    cover_rows = [
        ["Case reference", pack.get("case_reference") or "(none given)"],
        ["Wallet / transaction traced", trace_data.get("wallet", "")],
        ["Direction", trace_data.get("direction", "")],
        ["Chain", trace_data.get("chain", "")],
        ["Generated by", pack["created_by"]],
        ["Generated (UTC)", pack["created_at"]],
        ["Evidence pack ID", pack["id"]],
    ]
    cover_table = Table(cover_rows, colWidths=[55*mm, 115*mm])
    cover_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(cover_table)
    story.append(Spacer(1, 8*mm))

    # ---- Integrity / methodology ----
    story.append(Paragraph("Data Integrity", styles["Heading2"]))
    story.append(Paragraph(
        "The trace data underlying this report is fixed at the SHA-256 hash below. Any change to the "
        "underlying data - even a single character - would produce a completely different hash, so this "
        "value proves the data has not been altered since this report was generated.",
        styles["Normal"],
    ))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(f"SHA-256: {pack['sha256_hash']}", styles["Mono"]))
    story.append(Spacer(1, 3*mm))

    if methodology.get("blockchain_anchored"):
        story.append(Paragraph(
            "This hash was additionally submitted to the Bitcoin blockchain via the OpenTimestamps "
            "protocol, anchoring proof of its existence at this time independently of this "
            "application, Anthropic, or any server operated by the investigator. This can be "
            "independently verified by any third party using the stored proof.",
            styles["Normal"],
        ))
    else:
        story.append(Paragraph(
            "Blockchain anchoring was not used for this evidence pack. The creation timestamp above "
            "relies on this application's own database record.",
            styles["Normal"],
        ))
    story.append(Spacer(1, 6*mm))

    story.append(Paragraph("Methodology", styles["Heading2"]))
    method_rows = [[key.replace("_", " ").title(), str(value)] for key, value in methodology.items()]
    method_table = Table(method_rows, colWidths=[55*mm, 115*mm])
    method_table.setStyle(TableStyle([
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    story.append(method_table)
    story.append(Spacer(1, 4*mm))
    story.append(Paragraph(
        "These are the exact parameters used to produce the trace below. An independent third party "
        "running this same tool with these same parameters, against the same blockchain data, should "
        "obtain the same result.",
        styles["SmallGrey"],
    ))

    story.append(PageBreak())

    # ---- Confidence key ----
    story.append(Paragraph("How to Read This Report", styles["Heading2"]))
    story.append(Paragraph(
        "<b>Direct link found</b>: an on-chain path was traced from the starting wallet to a specifically "
        "targeted/flagged wallet. <b>Flagged trail end</b>: the trace reached a known exchange, mixer, "
        "or other custodial service and stopped there by design - a lead for further legal process "
        "(e.g. a production order), not proof of anything beyond that point. <b>Amount-filtered</b>: a "
        "hop whose value did not clearly match the amount being tracked - recorded for manual review, "
        "not automatically treated as the same money. Nothing in this report should be treated as "
        "conclusive proof of ownership or intent without independent verification of each transaction "
        "at the linked block explorer.",
        styles["Normal"],
    ))
    story.append(Spacer(1, 6*mm))

    # ---- Trace results ----
    story.extend(_path_group_flowables("Direct Links Found", trace_data.get("matched_paths", []), styles))
    story.extend(_path_group_flowables("Flagged Trail Ends (Known Services)", trace_data.get("flagged_end_paths", []), styles))
    story.extend(_path_group_flowables("Flagged for Manual Review (Amount Mismatch)", trace_data.get("amount_filtered_paths", []), styles))

    if not any([trace_data.get("matched_paths"), trace_data.get("flagged_end_paths"), trace_data.get("amount_filtered_paths")]):
        story.append(Paragraph(
            "No on-chain activity was found within the configured hop limit. This does not rule out a "
            "link - see the Methodology section for the exact parameters used, and consider whether a "
            "wider search (more hops, no amount filter) is appropriate.",
            styles["Normal"],
        ))

    # ---- Clean summary ----
    clean_summary = trace_data.get("clean_summary", [])
    if clean_summary:
        story.append(PageBreak())
        story.append(Paragraph("Clean Summary (Deduplicated)", styles["Heading2"]))
        summary_rows = [["From", "To", "Amount", "Time (UTC)"]] + [
            [
                Paragraph(row.get("from", ""), styles["TableCell"]),
                Paragraph(row.get("to", ""), styles["TableCell"]),
                Paragraph(row.get("amount", ""), styles["TableCell"]),
                Paragraph(row.get("tx_time_utc", ""), styles["TableCell"]),
            ]
            for row in clean_summary
        ]
        summary_table = Table(summary_rows, repeatRows=1, colWidths=[50*mm, 50*mm, 30*mm, 40*mm])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c232c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f5f7")]),
        ]))
        story.append(summary_table)

    doc.build(story)
    return buffer.getvalue()
