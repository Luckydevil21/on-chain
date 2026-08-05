"""
====================================================================
 AI ASSIST - narrative drafting and pattern description, NOT
 attribution or identity generation
====================================================================

WHAT THIS IS: two focused features that turn a COMPLETED trace's
already-computed structured data into readable text - drafting a
narrative report, and labeling the fund-movement pattern. Both are
summarization/labeling of facts your tool has already established,
never a source of new facts.

====================================================================
 THE ONE RULE THAT MATTERS MOST HERE
====================================================================
An LLM has no reliable way to know which real-world service a given
wallet address belongs to - that's not in its training data for the
overwhelming majority of addresses, and if asked to guess anyway, it
can produce a confident, plausible-sounding, WRONG answer. In a tool
whose output may end up as evidence, a confidently wrong entity label
is worse than no label at all.

So: every prompt in this module is explicitly instructed to use ONLY
the facts already present in the trace data your deterministic
tracing logic computed - never to recall or assume anything about a
specific address or service from its own training. It is a
summarizer of YOUR data, not a source of independent claims about
identity. If you ever add a feature that asks the model "whose wallet
is this," it needs to be grounded in an actual web search with
citations - never asked from the model's own memory. See the
"grounded entity research" design discussed separately; it is
deliberately NOT part of this module.

====================================================================
 SETUP
====================================================================
Set GROQ_API_KEY to your own Groq API key (free, no credit card
required - get one at console.groq.com). If the key isn't set, these
two features are simply unavailable (the endpoints return a clear
error, nothing crashes).
====================================================================
"""

import os
import json
import requests

GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile")

if not GROQ_API_KEY:
    print("=" * 70)
    print("⚠️  GROQ_API_KEY was not set - AI report drafting and")
    print("    pattern description will be unavailable (their buttons will")
    print("    show a clear 'not configured' message, nothing will crash).")
    print("    Get a free key at console.groq.com if you want these two features.")
    print("=" * 70)


def _call_llm(system_prompt, user_prompt, max_tokens):
    """Returns (text, error) - exactly one of which is None."""
    if not GROQ_API_KEY:
        return None, "AI features aren't configured - GROQ_API_KEY is not set."
    try:
        response = requests.post(
            GROQ_API_URL,
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": GROQ_MODEL,
                "max_tokens": max_tokens,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            },
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as error:
        return None, f"Could not reach the AI service: {error}"

    try:
        text = data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, AttributeError):
        return None, "The AI service returned an unexpected response format."
    if not text:
        return None, "The AI service returned an empty response."
    return text, None



NARRATIVE_SYSTEM_PROMPT = """You are drafting an investigative narrative report from blockchain trace data, for a forensics tool used by investigators working with law enforcement.

CRITICAL RULES - these are not stylistic preferences, they are hard constraints:

1. Use ONLY the facts given in the trace data below - addresses, amounts, hop counts, entity names, confidence labels. NEVER invent, assume, or recall any additional fact about any address or service from your own training data, even if you think you recognize an address or a name. If the data doesn't say it, you don't say it.

2. Preserve every confidence distinction in the data EXACTLY as given. A trail-end reason of "known exchange" is NOT the same claim as "high fan-out wallet (heuristic)". A swap-correlation "candidate" with a match percentage is NOT a confirmed link - it is a lead. Do not smooth these into uniform-sounding certainty anywhere in your writing.

3. If the data shows no result for something (e.g. no direct link to a target wallet was found, or a hop's amount didn't match closely enough to auto-follow), say that plainly. Do not imply more was established than actually was.

4. Write in clear, plain English suitable for a non-technical reader (a solicitor, a jury) - while keeping every technical fact (addresses, transaction hashes, amounts, dates) precise and directly quotable from the source data.

5. This is a DRAFT for the investigator to review, verify, and edit before it goes anywhere - not a finished or approved document. Do not present your conclusions as final or certain.

Structure it as: a short summary of what was traced and found, then the hop-by-hop narrative, then a section on any flagged trail-ends and what they mean, then (if present) swap/bridge correlation leads clearly marked as unconfirmed."""


TYPOLOGY_SYSTEM_PROMPT = """You are a blockchain forensics assistant labeling the STRUCTURAL PATTERN of fund movement shown in a trace - you are NOT identifying who is behind it or making any claim about intent.

CRITICAL RULES:

1. Base your description ONLY on the hop structure, amounts, and entity types given in the trace data below (how many hops, whether funds split across multiple wallets or consolidated into one, whether the trail ended at a known exchange/mixer/bridge, how quickly funds moved). Never speculate about identity, motive, or intent - describe the SHAPE of the movement, nothing else.

2. Use standard, recognized typology terms where they genuinely apply - e.g. "peel chain" (repeatedly splitting off a small amount while forwarding the rest), "layering" (multiple hops through intermediary wallets before reaching an endpoint), "consolidation" (multiple wallets' funds merging into one), "structuring" (splitting into many similarly-sized amounts). Only use a term if the data actually shows that specific pattern - do not force a label that doesn't fit just because one is expected.

3. If the pattern is simple, or doesn't clearly match a named typology, just describe what happened in plain terms instead of forcing a label onto it.

4. Keep this brief - a few sentences. This is a quick pattern tag someone can scan at a glance, not a full report."""


def draft_narrative_report(trace_data, wallet, direction):
    """Drafts a narrative report from a COMPLETED trace's structured
    results. See module docstring - grounded strictly in trace_data,
    never in the model's own recollection of any address/service."""
    user_prompt = (
        f"Wallet: {wallet}\n"
        f"Direction: {direction}\n\n"
        f"Trace results (JSON):\n{json.dumps(trace_data, indent=2, default=str)}\n\n"
        f"Draft a narrative investigation summary from this data, following the rules above exactly."
    )
    return _call_llm(NARRATIVE_SYSTEM_PROMPT, user_prompt, max_tokens=2500)


def describe_typology(trace_data, wallet, direction):
    """Labels the fund-movement PATTERN observed in a completed trace.
    See module docstring - never claims anything about WHO is behind it."""
    user_prompt = (
        f"Wallet: {wallet}\n"
        f"Direction: {direction}\n\n"
        f"Trace results (JSON):\n{json.dumps(trace_data, indent=2, default=str)}\n\n"
        f"Describe the fund-movement pattern shown in this trace, following the rules above exactly."
    )
    return _call_llm(TYPOLOGY_SYSTEM_PROMPT, user_prompt, max_tokens=600)


SERVICE_TRACE_SYSTEM_PROMPT = """You are drafting a narrative for a combined "deposit into a service, then output from that service" finding, from a blockchain forensics tool. This result has TWO parts with very different evidentiary weight, and your single most important job is to never blur that difference.

CRITICAL RULES:

1. The DEPOSIT/INPUT side (the address swept into a known service's wallet) is a CONFIRMED, directly observed on-chain transaction - a real transaction hash, a real amount, a real time. Describe it as what it is: an established fact.

2. The OUTPUT side (any "output_candidates" entries) is NEVER confirmed - it is a HEURISTIC correlation, found only by matching rough timing and approximate USD value against the service's other known wallets. It could be right. It could easily be someone else's unrelated withdrawal that happened to land in the same time window with a similar value. Describe every output candidate as a "possible" or "candidate" match, NEVER as "the" output or "confirmed" - even if there's only one candidate and even if its match percentage is 100%. A 100% USD match is still not proof of the same money - it is a strong correlation, nothing more.

3. If there are NO output candidates, say so plainly - do not imply the funds vanished or that no further movement occurred, just that nothing correlated was found in this search.

4. Use ONLY the facts given in the JSON below. Never invent or assume anything about the service, the wallets, or the people behind them beyond what the data states.

5. This is a DRAFT for the investigator to review and verify - not a finished or authoritative conclusion, and specifically not evidence that the output candidate is where the funds actually went."""


def draft_service_trace_narrative(trace_data, address):
    """Drafts a narrative for the combined Deposit Map + output-
    correlation result - see the system prompt above for why the
    input/output distinction is the one rule that matters most here."""
    user_prompt = (
        f"Address checked: {address}\n\n"
        f"Result (JSON):\n{json.dumps(trace_data, indent=2, default=str)}\n\n"
        f"Draft a narrative from this result, following the rules above exactly."
    )
    return _call_llm(SERVICE_TRACE_SYSTEM_PROMPT, user_prompt, max_tokens=1200)
