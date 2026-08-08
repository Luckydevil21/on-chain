"""
====================================================================
 BASIC TESTS - link_tracer.py address detection, pattern matching,
 and other pure logic that doesn't need a live database or network.
====================================================================

WHY THESE EXIST: every bug fixed in this app's build history so far
was caught manually, by deploying and clicking around. These tests
catch a specific, common class of regression automatically -
particularly around address/chain detection, which is the foundation
almost everything else in the app depends on getting right.

HOW TO RUN:
    pip install pytest --break-system-packages
    pytest test_link_tracer.py -v

These tests do NOT require DATABASE_URL, network access, or any real
API keys - link_tracer.py's database-backed functions (known entities,
patterns) degrade gracefully to empty results when no DB is reachable,
which is exactly what lets these run anywhere, including in CI.

WHAT'S DELIBERATELY NOT COVERED HERE: anything that needs a live
network call (fetching real transactions from Etherscan/mempool.space/
etc.) or a live database. Those need integration tests with actual
test fixtures/mocking, which is a bigger undertaking - this file
covers the foundational, pure-function layer first, since that's
where a regression would be most silent and most damaging (wrong
chain detection breaks EVERYTHING downstream).
====================================================================
"""

import link_tracer as lt


# ====================================================================
# ADDRESS DETECTION - the foundation everything else depends on.
# Wrong detection here means wrong chain, wrong API called, wrong
# results, silently.
# ====================================================================

class TestEthereumAddressDetection:
    def test_valid_ethereum_address(self):
        assert lt.is_valid_ethereum_address("0x1f2f10d1c40777ae1da742455c65828ff36df389") is True

    def test_rejects_wrong_length(self):
        assert lt.is_valid_ethereum_address("0x1234") is False

    def test_rejects_missing_prefix(self):
        assert lt.is_valid_ethereum_address("1f2f10d1c40777ae1da742455c65828ff36df3800") is False

    def test_rejects_non_hex_characters(self):
        assert lt.is_valid_ethereum_address("0xZZZZ10d1c40777ae1da742455c65828ff36df38") is False


class TestBitcoinAddressDetection:
    def test_valid_bech32_address(self):
        assert lt.is_valid_bitcoin_address("bc1q832l0ednpnc79d7cuqf4ah23393ajy6kxhnzq9") is True

    def test_valid_legacy_p2pkh_address(self):
        assert lt.is_valid_bitcoin_address("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa") is True

    def test_valid_legacy_p2sh_address(self):
        assert lt.is_valid_bitcoin_address("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is True

    def test_rejects_random_string(self):
        assert lt.is_valid_bitcoin_address("not-a-bitcoin-address") is False


class TestXrpAddressDetection:
    def test_valid_xrp_address(self):
        assert lt.is_valid_xrp_address("rEwYpwoeRWfa7VPbkiSv9w4L8sKTh1EXo8") is True

    def test_rejects_missing_r_prefix(self):
        assert lt.is_valid_xrp_address("EwYpwoeRWfa7VPbkiSv9w4L8sKTh1EXo8x") is False

    def test_rejects_too_short(self):
        assert lt.is_valid_xrp_address("rShort") is False


class TestTronAddressDetection:
    def test_valid_tron_address(self):
        assert lt.is_valid_tron_address("TPwezUWpEGmFBENNWJHwXHRG1D2NCEEt5s") is True

    def test_rejects_missing_t_prefix(self):
        assert lt.is_valid_tron_address("PwezUWpEGmFBENNWJHwXHRG1D2NCEEt5sX") is False

    def test_rejects_wrong_length(self):
        assert lt.is_valid_tron_address("TPwezUWpEGm") is False


class TestSolanaAddressDetection:
    def test_valid_solana_address(self):
        assert lt.is_valid_solana_address("FDF8AxHB8UK7RS6xay6aBvwS3h7kez9gozqz14JyfKsg") is True

    def test_rejects_ethereum_style_address(self):
        # An Ethereum address should never be mistaken for a Solana one -
        # detect_chain() checks Ethereum FIRST specifically to prevent this.
        assert lt.is_valid_ethereum_address("0x1f2f10d1c40777ae1da742455c65828ff36df389") is True

    def test_rejects_string_with_invalid_base58_characters(self):
        # '0', 'O', 'I', 'l' are NOT valid base58 characters
        assert lt.is_valid_solana_address("0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl0OIl") is False

    def test_rejects_too_short(self):
        assert lt.is_valid_solana_address("short") is False


class TestDetectChainDispatchesCorrectly:
    """Confirms detect_chain() routes each address format to the right
    chain, and checks them in an order that can't misclassify one
    chain's address as another's (the whole reason Solana is checked
    LAST - see is_valid_solana_address's docstring)."""

    def test_ethereum(self):
        assert lt.detect_chain("0x1f2f10d1c40777ae1da742455c65828ff36df389") == "ethereum"

    def test_bitcoin_bech32(self):
        assert lt.detect_chain("bc1q832l0ednpnc79d7cuqf4ah23393ajy6kxhnzq9") == "bitcoin"

    def test_xrp(self):
        assert lt.detect_chain("rEwYpwoeRWfa7VPbkiSv9w4L8sKTh1EXo8") == "xrp"

    def test_tron(self):
        assert lt.detect_chain("TPwezUWpEGmFBENNWJHwXHRG1D2NCEEt5s") == "tron"

    def test_solana(self):
        assert lt.detect_chain("FDF8AxHB8UK7RS6xay6aBvwS3h7kez9gozqz14JyfKsg") == "solana"

    def test_unrecognized_string_returns_none(self):
        assert lt.detect_chain("definitely not a real address") is None

    def test_empty_string_returns_none(self):
        assert lt.detect_chain("") is None


# ====================================================================
# WASABI COINJOIN DETECTION - the structural heuristic added this
# session. Tests the actual threshold logic without needing a real
# Bitcoin transaction from the network.
# ====================================================================

class TestWasabiCoinjoinDetection:
    def _make_tx(self, output_values, input_count=15):
        return {
            "vin": [{}] * input_count,
            "vout": [{"value": v} for v in output_values],
        }

    def test_detects_transaction_with_11_equal_outputs(self):
        # Threshold is >10 per the WabiSabi paper - 11 should trigger it
        tx = self._make_tx([10_000_000] * 11 + [500_000])  # 11x 0.1 BTC + one odd-value output
        result = lt.detect_wasabi_coinjoin(tx)
        assert result is not None
        assert result["equal_output_count"] == 11
        assert result["equal_output_value_btc"] == 0.1
        assert result["type"] == "mixer"

    def test_does_not_flag_exactly_10_equal_outputs(self):
        # Threshold is "more than 10" per the WabiSabi paper - exactly 10 should NOT trigger it
        tx = self._make_tx([10_000_000] * 10)
        assert lt.detect_wasabi_coinjoin(tx) is None

    def test_flags_11_equal_outputs(self):
        # 11 is the smallest count that should actually trigger the heuristic
        tx = self._make_tx([10_000_000] * 11)
        result = lt.detect_wasabi_coinjoin(tx)
        assert result is not None
        assert result["equal_output_count"] == 11

    def test_does_not_flag_ordinary_transaction(self):
        tx = self._make_tx([5_000_000, 12_300_000, 900_000])
        assert lt.detect_wasabi_coinjoin(tx) is None

    def test_does_not_flag_samourai_style_5_output_transaction(self):
        # Samourai/Whirlpool uses a smaller, fixed 5-output structure -
        # this threshold should NOT catch that pattern, by design.
        tx = self._make_tx([10_000_000] * 5)
        assert lt.detect_wasabi_coinjoin(tx) is None

    def test_ignores_zero_value_outputs_when_counting(self):
        # An OP_RETURN output often has value 0 - shouldn't count towards the threshold
        tx = self._make_tx([10_000_000] * 11 + [0])
        result = lt.detect_wasabi_coinjoin(tx)
        assert result is not None
        assert result["equal_output_count"] == 11

    def test_handles_transaction_with_no_outputs(self):
        tx = {"vin": [], "vout": []}
        assert lt.detect_wasabi_coinjoin(tx) is None


# ====================================================================
# AMOUNT PARSING - used throughout amount-filtering during a trace.
# ====================================================================

class TestParseAmountFromLabel:
    def test_parses_xrp_amount(self):
        assert lt.parse_amount_from_label("23080.283377 XRP") == 23080.283377

    def test_parses_btc_amount(self):
        assert lt.parse_amount_from_label("0.00012345 BTC") == 0.00012345

    def test_returns_none_for_token_payment_label(self):
        assert lt.parse_amount_from_label("token payment") is None

    def test_returns_none_for_empty_string(self):
        assert lt.parse_amount_from_label("") is None

    def test_returns_none_for_none_input(self):
        assert lt.parse_amount_from_label(None) is None


# ====================================================================
# OP_RETURN / MEMO PATTERN MATCHING - the mechanism that recognizes
# rotating-address services (e.g. Bridgers.xyz). Uses monkeypatching
# to avoid needing a real database with real registered patterns.
# ====================================================================

class TestOpReturnPatternMatching:
    def test_matches_registered_pattern_substring(self, monkeypatch):
        monkeypatch.setattr(lt, "load_known_op_return_patterns", lambda: [
            {"pattern": "|bridgers|", "name": "Bridgers.xyz", "type": "bridge"}
        ])
        result = lt.check_op_return_patterns('{"toToken":"USDT(TRON)|o31kby|0.05|bridgers|0"}')
        assert result is not None
        assert result["name"] == "Bridgers.xyz"
        assert result["type"] == "bridge"

    def test_no_match_when_pattern_absent(self, monkeypatch):
        monkeypatch.setattr(lt, "load_known_op_return_patterns", lambda: [
            {"pattern": "|bridgers|", "name": "Bridgers.xyz", "type": "bridge"}
        ])
        result = lt.check_op_return_patterns("just an ordinary memo, nothing special")
        assert result is None

    def test_handles_empty_pattern_list(self, monkeypatch):
        monkeypatch.setattr(lt, "load_known_op_return_patterns", lambda: [])
        assert lt.check_op_return_patterns("anything at all") is None

    def test_handles_none_input(self):
        assert lt.check_op_return_patterns(None) is None

    def test_extracts_embedded_destination_when_present(self, monkeypatch):
        monkeypatch.setattr(lt, "load_known_op_return_patterns", lambda: [
            {"pattern": "|bridgers|", "name": "Bridgers.xyz", "type": "bridge"}
        ])
        memo = '{"toToken":"USDT(TRON)|o31kby|0.05|bridgers|0","destination":"TMbPCvv5cATRceLo7dKPrpxVvoKBBGLypC"}'
        result = lt.check_op_return_patterns(memo)
        assert result["embedded_destination_address"] == "TMbPCvv5cATRceLo7dKPrpxVvoKBBGLypC"
        assert result["embedded_destination_chain"] == "tron"

    def test_no_embedded_destination_when_memo_is_not_json(self, monkeypatch):
        monkeypatch.setattr(lt, "load_known_op_return_patterns", lambda: [
            {"pattern": "|bridgers|", "name": "Bridgers.xyz", "type": "bridge"}
        ])
        result = lt.check_op_return_patterns("plain text with |bridgers| in it, not JSON")
        assert result is not None
        assert "embedded_destination_address" not in result
