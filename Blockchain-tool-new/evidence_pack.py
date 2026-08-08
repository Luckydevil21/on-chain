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


def _compile_factual_findings(trace_data):
    """
    PLAIN ENGLISH: Pulls together a strictly FACTUAL bullet list from
    the trace data - what was found, mechanically, with no evaluative
    interpretation (no "this is consistent with layering behaviour" -
    that kind of judgment belongs to the instructed analyst, not this
    tool). Used in the "Automatically Compiled Findings" section,
    which is explicitly kept separate from "Expert Conclusions".
    """
    findings = []
    root_entity = trace_data.get("root_known_entity")
    if root_entity:
        findings.append(f"The traced wallet itself is registered as a known entity: {root_entity.get('name')} ({root_entity.get('type')}).")

    for group_name, paths in [("direct link", trace_data.get("matched_paths", [])),
                               ("flagged trail end", trace_data.get("flagged_end_paths", []))]:
        for path in paths:
            hops = path.get("hops", [])
            if not hops:
                continue
            last_hop = hops[-1]
            entity = last_hop.get("to_known_entity") or last_hop.get("matched_pattern")
            if entity:
                findings.append(
                    f"A {group_name} traced through {len(hops)} hop(s) reached an address "
                    f"registered/recognized as: {entity.get('name')} ({entity.get('type')})."
                )
            coinjoin = last_hop.get("coinjoin_match")
            if coinjoin:
                findings.append(
                    f"A {group_name} reached a transaction structurally consistent with a Wasabi/WabiSabi "
                    f"CoinJoin heuristic ({coinjoin.get('equal_output_count')} outputs of "
                    f"{coinjoin.get('equal_output_value_btc')} BTC each) - a pattern-based indicator, not confirmed."
                )
            embedded = last_hop.get("embedded_destination")
            if embedded:
                findings.append(
                    f"The transaction's own memo stated a destination address: {embedded.get('address')} "
                    f"({embedded.get('chain')}) - the service's own stated routing, not a timing/amount heuristic."
                )

    addresses_visited = trace_data.get("addresses_visited")
    if addresses_visited is not None:
        findings.append(f"{addresses_visited} unique address(es) were examined in the course of this trace.")

    return findings


def generate_evidence_pack_pdf(evidence_pack_id):
    """
    PLAIN ENGLISH: Builds a full expert-analyst-report-style PDF,
    structured similarly to a professional blockchain forensic report
    prepared for legal use (report particulars, methodology, chain of
    custody, transaction trail, findings, appendices).

    IMPORTANT BOUNDARY, deliberately enforced throughout this function:
    everything FACTUAL (what the trace actually found, hashes,
    parameters used) is auto-populated. Everything requiring the
    instructed analyst's own INDEPENDENT PROFESSIONAL JUDGMENT (the
    CPR Part 35 declaration, expert conclusions, case background from
    the instruction letter) is rendered as a clearly-marked template
    for the analyst to complete and sign - never fabricated or
    presented as if this tool had reached its own "expert" opinion.
    That distinction is the entire point of expert evidence; software
    output is not a substitute for it.

    Returns PDF bytes, or None if the evidence pack doesn't exist.
    """
    import io as _io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak

    pack = get_evidence_pack(evidence_pack_id)
    if not pack:
        return None

    trace_data = pack["trace_data"]
    methodology = pack["methodology"]

    # Report-specific fields, supplied optionally at generation time (see
    # api_server.py's CreateEvidencePackRequest) - bracketed placeholders
    # when not given, exactly mirroring how a real instruction letter's
    # details would need to be filled in before a report goes out.
    instructed_by = methodology.get("instructed_by") or "[INSTRUCTING SOLICITOR / CLIENT NAME]"
    analyst_name = methodology.get("analyst_name") or "[ANALYST NAME]"
    analyst_certification = methodology.get("analyst_certification") or "[ANALYST CERTIFICATION(S)]"
    background_notes = methodology.get("background_notes") or (
        "[Insert background and scope of instruction here, drawn from the instruction letter - "
        "what the analyst was asked to investigate, and any limitations on scope.]"
    )
    report_reference = pack.get("case_reference") or f"EP-{pack['id'][:8].upper()}"

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Mono", fontName="Courier", fontSize=9, leading=12))
    styles.add(ParagraphStyle(name="SmallGrey", fontSize=8, textColor=colors.HexColor("#666666")))
    styles.add(ParagraphStyle(name="TableCell", fontName="Courier", fontSize=6.5, leading=8, wordWrap="CJK"))
    styles.add(ParagraphStyle(name="CenterBold", fontName="Helvetica-Bold", fontSize=10, alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="Placeholder", fontSize=9, textColor=colors.HexColor("#b45309"), fontName="Helvetica-Oblique"))
    styles.add(ParagraphStyle(name="WarningBanner", fontName="Helvetica-Bold", fontSize=9, textColor=colors.HexColor("#991b1b"),
                               backColor=colors.HexColor("#fef2f2"), borderPadding=8, alignment=TA_CENTER))

    buffer = _io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=16*mm, bottomMargin=16*mm, leftMargin=16*mm, rightMargin=16*mm,
    )
    story = []

    def spacer(h=4):
        return Spacer(1, h * mm)

    def heading(text):
        return Paragraph(text, styles["Heading2"])

    def key_value_table(rows, col_widths=(55*mm, 115*mm)):
        table = Table(rows, colWidths=list(col_widths))
        table.setStyle(TableStyle([
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cccccc")),
        ]))
        return table

    # ================================================================
    # COVER / REPORT PARTICULARS
    # ================================================================
    story.append(Paragraph("BLOCKCHAIN FORENSIC ANALYSIS REPORT", styles["Title"]))
    story.append(Paragraph("STRICTLY CONFIDENTIAL — SUBJECT TO LEGAL PRIVILEGE", styles["CenterBold"]))
    story.append(spacer(6))
    story.append(Paragraph(
        "This report has been produced by the On-Chain Investigations Toolkit as a DRAFT for the "
        "instructed analyst's review. It is not a finished, signed expert report until the analyst has "
        "reviewed every section, completed the placeholders below, and applied their own independent "
        "professional judgment throughout.",
        styles["WarningBanner"],
    ))
    story.append(spacer(6))

    story.append(heading("1. Report Particulars"))
    story.append(key_value_table([
        ["Report reference", report_reference],
        ["Date of report", datetime.now(timezone.utc).strftime("%d %B %Y")],
        ["Prepared by", analyst_name],
        ["Certification(s)", analyst_certification],
        ["Instructed by", instructed_by],
        ["Classification", "Strictly Confidential — Subject to Legal Privilege"],
        ["Blockchain(s) analysed", trace_data.get("chain", "")],
        ["Analysis tool", "On-Chain Investigations Toolkit"],
        ["Evidence pack ID", pack["id"]],
    ]))
    story.append(spacer(6))

    # ================================================================
    # ANALYST DECLARATION — template only, never auto-completed
    # ================================================================
    story.append(heading("2. Analyst Declaration & Qualifications"))
    story.append(Paragraph(
        "⚠ TO BE REVIEWED AND SIGNED BY THE INSTRUCTED ANALYST. The declaration below is standard "
        "template wording, consistent with CPR Part 35 expert duties - it is NOT a claim made by this "
        "software, and must not be relied upon until the named analyst has personally reviewed this "
        "entire report and confirms it to be true.",
        styles["Placeholder"],
    ))
    story.append(spacer(3))
    declaration_text = (
        f"I, {analyst_name}, hereby declare that: (1) I hold the following certification(s): "
        f"{analyst_certification}. (2) I have been instructed as set out in Section 4 below. "
        "(3) The contents of this report are true to the best of my knowledge and belief; the analysis "
        "has been conducted objectively and without bias, and I have not reached conclusions beyond "
        "what the on-chain evidence supports. (4) All on-chain data referenced was obtained via the "
        "On-Chain Investigations Toolkit. The blockchain is an immutable public ledger; the underlying "
        "data cannot be altered or retrospectively changed. (5) I understand my duty is to the court "
        "and not to the party instructing me, and this report has been prepared in accordance with CPR "
        "Part 35 and the duties of an expert witness. (6) I confirm I have not been influenced by the "
        "outcome sought by the instructing party."
    )
    story.append(Paragraph(declaration_text, styles["Normal"]))
    story.append(spacer(8))
    story.append(Paragraph("Signed: _________________________________     Date: _______________", styles["Normal"]))
    story.append(spacer(6))

    # ================================================================
    # EXECUTIVE SUMMARY — auto-generated, strictly factual
    # ================================================================
    story.append(heading("3. Executive Summary"))
    matched = trace_data.get("matched_paths", [])
    flagged = trace_data.get("flagged_end_paths", [])
    filtered = trace_data.get("amount_filtered_paths", [])
    summary_parts = [
        f"This report sets out the findings of a blockchain trace analysis of the wallet/transaction "
        f"{trace_data.get('wallet', '')} on {trace_data.get('chain', 'the specified chain')}, traced "
        f"{trace_data.get('direction', 'forward')}. {trace_data.get('addresses_visited', 0)} unique "
        f"address(es) were examined."
    ]
    if matched:
        summary_parts.append(f"{len(matched)} direct link(s) to a specifically targeted wallet were found.")
    if flagged:
        summary_parts.append(f"{len(flagged)} trail(s) reached a known or suspected custodial service, detailed in Section 7.")
    if filtered:
        summary_parts.append(f"{len(filtered)} hop(s) were set aside for manual review due to an amount mismatch against the tracked value.")
    if not (matched or flagged or filtered):
        summary_parts.append("No on-chain activity was found within the configured hop limit.")
    story.append(Paragraph(" ".join(summary_parts), styles["Normal"]))
    story.append(spacer(6))

    # ================================================================
    # BACKGROUND & SCOPE — placeholder, from instruction letter
    # ================================================================
    story.append(heading("4. Background & Scope of Instruction"))
    if methodology.get("background_notes"):
        story.append(Paragraph(background_notes, styles["Normal"]))
    else:
        story.append(Paragraph(background_notes, styles["Placeholder"]))
    story.append(spacer(6))
    story.append(PageBreak())

    # ================================================================
    # METHODOLOGY & CHAIN OF CUSTODY — auto-generated, factual
    # ================================================================
    story.append(heading("5. Methodology & Chain of Custody"))
    story.append(Paragraph(
        "All analysis was conducted using the On-Chain Investigations Toolkit. The blockchain(s) "
        "analysed are public, immutable ledgers; every transaction referenced is independently "
        "verifiable by any party using the transaction identifiers and wallet addresses documented "
        "in this report, via a public block explorer.",
        styles["Normal"],
    ))
    story.append(spacer(3))
    method_rows = [[key.replace("_", " ").title(), str(value)] for key, value in methodology.items()
                   if key not in ("instructed_by", "analyst_name", "analyst_certification", "background_notes")]
    story.append(key_value_table(method_rows))
    story.append(spacer(3))
    story.append(Paragraph(
        "These are the exact parameters used to produce this trace. An independent third party running "
        "the same tool with these same parameters, against the same blockchain data, should obtain the "
        "same result - see the Data Integrity subsection below for the cryptographic proof this data has "
        "not been altered since capture.",
        styles["SmallGrey"],
    ))
    story.append(spacer(5))

    story.append(Paragraph("<b>Data Integrity</b>", styles["Normal"]))
    story.append(Paragraph(f"SHA-256: {pack['sha256_hash']}", styles["Mono"]))
    if methodology.get("blockchain_anchored"):
        story.append(Paragraph(
            "This hash was additionally submitted to the Bitcoin blockchain via the OpenTimestamps "
            "protocol, independently anchoring proof of its existence at this time - verifiable by any "
            "third party without needing to trust this application or its operator.",
            styles["Normal"],
        ))
    else:
        story.append(Paragraph(
            "Blockchain anchoring was not used for this record - the creation timestamp relies on this "
            "application's own database record rather than an independently verifiable Bitcoin timestamp.",
            styles["Normal"],
        ))
    story.append(spacer(6))

    # ================================================================
    # CONFIDENCE KEY
    # ================================================================
    story.append(heading("6. How to Read the Transaction Trail"))
    story.append(Paragraph(
        "<b>Direct link found</b>: an on-chain path was traced to a specifically targeted wallet. "
        "<b>Flagged trail end</b>: the trace reached a known or suspected custodial service (exchange, "
        "mixer, bridge) and stopped there by design - a lead for further legal process, not proof of "
        "anything beyond that point. <b>Amount-filtered</b>: a hop whose value did not clearly match the "
        "amount being tracked, recorded for manual review. Nothing in the automatically compiled "
        "findings below should be treated as conclusive proof without independent verification of each "
        "transaction at the linked block explorer, and without the instructed analyst's own review.",
        styles["Normal"],
    ))
    story.append(spacer(6))
    story.append(PageBreak())

    # ================================================================
    # TRANSACTION TRAIL ANALYSIS — auto-generated, factual, with an
    # analyst-commentary placeholder under each stage
    # ================================================================
    story.append(heading("7. Transaction Trail Analysis"))
    story.extend(_path_group_flowables_with_commentary("Direct Links Found", matched, styles))
    story.extend(_path_group_flowables_with_commentary("Flagged Trail Ends (Known/Suspected Services)", flagged, styles))
    story.extend(_path_group_flowables_with_commentary("Flagged for Manual Review (Amount Mismatch)", filtered, styles))
    if not (matched or flagged or filtered):
        story.append(Paragraph(
            "No on-chain activity was found within the configured hop limit. This does not rule out a "
            "link - see Section 5 for the exact parameters used.",
            styles["Normal"],
        ))
    story.append(spacer(4))

    # ================================================================
    # AUTOMATICALLY COMPILED FINDINGS — strictly factual, mechanical
    # ================================================================
    story.append(PageBreak())
    story.append(heading("8. Automatically Compiled Findings"))
    story.append(Paragraph(
        "The following is a mechanical summary of what the trace found - stated factually, with no "
        "evaluative interpretation. This is NOT a substitute for the instructed analyst's own expert "
        "conclusions in Section 9.",
        styles["SmallGrey"],
    ))
    story.append(spacer(3))
    findings = _compile_factual_findings(trace_data)
    if findings:
        for finding in findings:
            story.append(Paragraph(f"• {finding}", styles["Normal"]))
    else:
        story.append(Paragraph("No known entities, patterns, or structural indicators were identified in this trace.", styles["Normal"]))
    story.append(spacer(6))

    # ================================================================
    # EXPERT CONCLUSIONS — template only, never auto-completed
    # ================================================================
    story.append(heading("9. Expert Conclusions"))
    story.append(Paragraph(
        "⚠ TO BE COMPLETED BY THE INSTRUCTED ANALYST. This section must reflect the analyst's own "
        "independent professional judgment, in accordance with CPR Part 35. The automatically compiled "
        "findings in Section 8 may inform these conclusions but do not substitute for them.",
        styles["Placeholder"],
    ))
    story.append(spacer(3))
    for n in range(1, 4):
        story.append(Paragraph(f"{n}. [Insert conclusion]", styles["Normal"]))
        story.append(spacer(2))
    story.append(spacer(6))

    # ================================================================
    # RECOMMENDED NEXT STEPS — general, non-case-specific, not legal advice
    # ================================================================
    story.append(heading("10. Recommended Next Steps"))
    story.append(Paragraph(
        "The following are general observations only and do not constitute legal advice. The "
        "instructing solicitor should advise on the legal merits of any proposed action.",
        styles["SmallGrey"],
    ))
    story.append(spacer(3))
    next_steps = _generic_next_steps(trace_data)
    for step in next_steps:
        story.append(Paragraph(f"• {step}", styles["Normal"]))
    if not next_steps:
        story.append(Paragraph("[Insert recommended next steps based on the analyst's conclusions above.]", styles["Placeholder"]))
    story.append(spacer(6))

    # ================================================================
    # APPENDICES
    # ================================================================
    story.append(PageBreak())
    story.append(heading("11. Appendix A — Full Transaction Reference List"))
    all_hops = []
    for group in (matched, flagged, filtered):
        for path in group:
            all_hops.extend(path.get("hops", []))
    if all_hops:
        appendix_rows = [["Tx Hash", "From", "To", "Amount", "Time (UTC)"]] + [
            [
                Paragraph(hop.get("tx_hash", ""), styles["TableCell"]),
                Paragraph(hop.get("from_address", ""), styles["TableCell"]),
                Paragraph(hop.get("to_address", ""), styles["TableCell"]),
                Paragraph(hop.get("amount", ""), styles["TableCell"]),
                Paragraph(hop.get("tx_time_utc", ""), styles["TableCell"]),
            ]
            for hop in all_hops
        ]
        appendix_table = Table(appendix_rows, repeatRows=1, colWidths=[42*mm, 36*mm, 36*mm, 22*mm, 30*mm])
        appendix_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1c232c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, 0), 7),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#999999")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f5f7")]),
        ]))
        story.append(appendix_table)
    else:
        story.append(Paragraph("No transactions to list.", styles["Normal"]))
    story.append(spacer(6))
    story.append(Paragraph(
        "Appendix B — Raw investigation data export: available on request via the evidence pack's "
        "stored JSON record (evidence pack ID above). "
        "Appendix C — Analyst curriculum vitae and certification documentation: [attach separately]. "
        "Appendix D — Instruction letter: [attach separately].",
        styles["SmallGrey"],
    ))
    story.append(spacer(8))

    # ================================================================
    # DISCLAIMER
    # ================================================================
    story.append(heading("12. Disclaimer & Limitations"))
    story.append(Paragraph(
        "This report has been prepared for informational and legal support purposes only. No guarantee "
        "of asset recovery is expressed or implied. Exchange or service attribution indicates the likely "
        "presence of account-holder information at the named service; it does not guarantee that such "
        "information will be disclosed or that funds remain accessible. This report does not constitute "
        "legal advice - the instructing solicitor should advise their client on the legal merits of any "
        "proposed action based on the findings herein. All on-chain data is sourced from public "
        "blockchain records and is independently verifiable. This document was drafted with the "
        "assistance of the On-Chain Investigations Toolkit; the instructed analyst named in Section 1 "
        "takes full professional responsibility for its contents once reviewed, completed, and signed.",
        styles["Normal"],
    ))

    doc.build(story)
    return buffer.getvalue()


def _path_group_flowables_with_commentary(title, paths, styles):
    """Same as _path_group_flowables, but adds an analyst-commentary
    placeholder line under each stage - kept separate from the factual
    hop table itself."""
    from reportlab.platypus import Paragraph, Spacer
    from reportlab.lib.units import mm

    flowables = _path_group_flowables(title, paths, styles)
    if not paths:
        return flowables

    # Insert a commentary placeholder after each path's table+spacer pair.
    # _path_group_flowables appends [title, then per-path: label, table, spacer...]
    # so we rebuild with a placeholder inserted after each spacer.
    result = [flowables[0]]  # the group title
    idx = 1
    for _path in paths:
        # label, table, spacer = the next three flowables for this path
        result.extend(flowables[idx:idx + 3])
        idx += 3
        result.append(Paragraph("[Analyst commentary — insert professional interpretation of this stage]", styles["Placeholder"]))
        result.append(Spacer(1, 4 * mm))
    return result


def _generic_next_steps(trace_data):
    """General, non-case-specific notes based on entity TYPES found -
    never tailored legal advice, just prompts for the analyst/solicitor
    to consider."""
    steps = []
    entity_types_found = set()
    for group in (trace_data.get("matched_paths", []), trace_data.get("flagged_end_paths", [])):
        for path in group:
            hops = path.get("hops", [])
            if not hops:
                continue
            entity = hops[-1].get("to_known_entity") or hops[-1].get("matched_pattern")
            if entity:
                entity_types_found.add(entity.get("type"))

    if "exchange" in entity_types_found:
        steps.append(
            "Exchange attribution was identified - a legal preservation request or law enforcement "
            "subpoena to the named exchange may be worth discussing with the instructing solicitor."
        )
    if "mixer" in entity_types_found:
        steps.append(
            "A known or suspected mixing service was identified - funds passed through this point may "
            "not be traceable further on-chain; consider whether the mixer operator itself is a viable "
            "line of enquiry."
        )
    if "bridge" in entity_types_found or "instant_swap" in entity_types_found:
        steps.append(
            "A cross-chain bridge or swap service was identified - consider requesting records from "
            "that service, and whether a further trace on the destination chain is warranted."
        )
    if trace_data.get("amount_filtered_paths"):
        steps.append(
            "Some hops were set aside due to an amount mismatch - consider whether a wider search "
            "(different amount tolerance, or no amount filter) is warranted."
        )
    return steps
