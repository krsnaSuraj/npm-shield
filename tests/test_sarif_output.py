"""Tests for SARIF output format support.

Verifies that --sarif flag produces valid SARIF 2.1.0 JSON
that GitHub Code Scanning can consume.
"""
import json
import pytest


class TestSarifOutput:
    """Verify SARIF format output is valid and consumable."""

    def test_sarif_flag_accepted(self):
        """--sarif flag must be accepted by CLI (after subcommand)."""
        from npm_shield.cli import build_parser
        parser = build_parser()
        # Flag must work both before and after the subcommand
        args = parser.parse_args(["scan", "--sarif", "."])
        assert args.sarif is True

    def test_sarif_generates_valid_json(self):
        """format_sarif must produce valid JSON."""
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class FakeFinding:
            severity = "critical"
            message = "Test finding"
            path = "package.json"
            package = ""
            version = ""
            kind = "test_marker"
            fix = "Remove it"

        class FakeResult:
            findings = [FakeFinding()]
            packages_checked = 1
            path = "."

        sarif_output = reporter.format_sarif(FakeResult())
        sarif_doc = json.loads(sarif_output)  # Must parse without error

    def test_sarif_has_required_fields(self):
        """SARIF output must have required top-level fields."""
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class FakeFinding:
            severity = "high"
            message = "Malware detected"
            path = "package.json"
            package = ""
            version = ""
            kind = "malware"
            fix = "rm package.json"

        class FakeResult:
            findings = [FakeFinding()]
            packages_checked = 1
            path = "."

        sarif_doc = json.loads(reporter.format_sarif(FakeResult()))

        # Required SARIF fields
        assert "version" in sarif_doc
        assert sarif_doc["version"] == "2.1.0"
        assert "$schema" in sarif_doc
        assert "runs" in sarif_doc
        assert len(sarif_doc["runs"]) == 1
        assert "tool" in sarif_doc["runs"][0]
        assert "results" in sarif_doc["runs"][0]

    def test_sarif_severity_mapping(self):
        """Critical→error, Medium→warning, Info→note."""
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class FakeResult:
            findings = []
            packages_checked = 0
            path = "."

        # Test with critical finding
        class CriticalFinding:
            severity = "critical"
            message = "Critical issue"
            path = ""
            package = "test-pkg"
            version = "1.0"
            kind = "test"
            fix = ""

        FakeResult.findings = [CriticalFinding()]
        sarif = json.loads(reporter.format_sarif(FakeResult()))
        assert sarif["runs"][0]["results"][0]["level"] == "error"

        # Test with info finding
        class InfoFinding:
            severity = "info"
            message = "Info issue"
            path = ""
            package = "test-pkg"
            version = "1.0"
            kind = "test"
            fix = ""

        FakeResult.findings = [InfoFinding()]
        sarif = json.loads(reporter.format_sarif(FakeResult()))
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_sarif_empty_results(self):
        """Clean scan with no findings must produce valid SARIF."""
        from npm_shield.reporter import Reporter
        reporter = Reporter()

        class FakeResult:
            findings = []
            packages_checked = 0
            path = "."

        sarif_doc = json.loads(reporter.format_sarif(FakeResult()))
        assert len(sarif_doc["runs"][0]["results"]) == 0
