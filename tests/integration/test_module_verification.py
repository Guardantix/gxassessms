"""Integration tests for the PowerShell module verification template.

Requires pwsh on PATH -- skipped when unavailable.
Tests run against isolated PSModulePath (no host contamination).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None,
    reason="pwsh not available on PATH",
)

TEMPLATE_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "gxassessms"
    / "adapters"
    / "_verification_scripts"
    / "verify_module.ps1"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_template(
    input_blob: dict,
    tmp_path: Path,
    *,
    ps_module_path: str | None = None,
    timeout: int = 60,
) -> tuple[dict, subprocess.CompletedProcess]:
    """Invoke verify_module.ps1 with a JSON input blob and return parsed report.

    Returns (report_dict, completed_process).
    """
    input_path = tmp_path / "input.json"
    report_path = tmp_path / "report.json"
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir(exist_ok=True)

    input_path.write_text(json.dumps(input_blob, indent=2), encoding="utf-8")

    cmd = [
        "pwsh",
        "-NoProfile",
        "-NonInteractive",
        "-File",
        str(TEMPLATE_PATH),
        "-InputPath",
        str(input_path),
        "-ReportPath",
        str(report_path),
        "-StagingDir",
        str(staging_dir),
    ]

    env = None
    if ps_module_path is not None:
        import os

        env = os.environ.copy()
        env["PSModulePath"] = ps_module_path

    proc = subprocess.run(  # noqa: S603
        cmd,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
    )

    report = json.loads(report_path.read_text(encoding="utf-8-sig")) if report_path.exists() else {}

    return report, proc


def _make_test_module(
    tmp_path: Path,
    module_name: str = "TestModule",
    version: str = "1.0.0",
    *,
    root_module: str | None = "TestModule.psm1",
    extra_psd1_fields: str = "",
    extra_files: dict[str, str] | None = None,
) -> Path:
    """Create a minimal PowerShell module in a temp PSModulePath.

    Returns the Modules root directory (for use as PSModulePath).
    """
    modules_dir = tmp_path / "Modules"
    mod_dir = modules_dir / module_name / version
    mod_dir.mkdir(parents=True)

    psd1_content = f"@{{\n    ModuleVersion = '{version}'\n"
    if root_module:
        psd1_content += f"    RootModule = '{root_module}'\n"
    psd1_content += (
        "    CompatiblePSEditions = @('Core', 'Desktop')\n    PowerShellVersion = '5.1'\n"
    )
    if extra_psd1_fields:
        psd1_content += extra_psd1_fields
    psd1_content += "}\n"

    (mod_dir / f"{module_name}.psd1").write_text(psd1_content, encoding="utf-8")

    if root_module:
        (mod_dir / root_module).write_text(
            f'function Get-{module_name}Result {{ return "OK" }}\n',
            encoding="utf-8",
        )

    if extra_files:
        for rel_path, content in extra_files.items():
            fpath = mod_dir / rel_path
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content, encoding="utf-8")

    return modules_dir


def _compute_module_hash(mod_dir: Path) -> str:
    """Compute tree hash for a module directory using Python implementation."""
    from gxassessms.adapters._tree_hash import compute_tree_hash

    return compute_tree_hash(mod_dir)


def _make_basic_input(
    module_name: str = "TestModule",
    version_range: str = ">=1.0.0,<2.0.0",
    approved_hashes: list[str] | None = None,
    *,
    mode: str = "preflight",
    allow_hash_fallback: bool = True,
    signers: list[dict] | None = None,
    post_import_invocation: dict | None = None,
) -> dict:
    """Build a standard input blob for verify_module.ps1."""
    return {
        "module_name": module_name,
        "effective_version_range": version_range,
        "effective_approved_hashes": approved_hashes or [],
        "allowed_signers": signers or [{"subject": "CN=Test", "issuer": "CN=TestCA"}],
        "allow_package_hash_fallback": allow_hash_fallback,
        "mode": mode,
        "post_import_invocation": post_import_invocation,
    }


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestGoldenVectorParity:
    """Validate that Python and PowerShell produce identical tree hashes."""

    def test_golden_vector_parity(self, fixtures_dir: Path) -> None:
        """Python and PowerShell produce identical hashes for the golden vector."""
        golden_dir = fixtures_dir / "module_hash_vectors" / "SimpleModule"
        if not golden_dir.exists():
            pytest.skip("Golden vector fixture not found")

        from gxassessms.adapters._tree_hash import compute_tree_hash

        python_hash = compute_tree_hash(golden_dir)

        # Invoke PowerShell hash computation directly
        ps_script = (
            f"$dir = '{golden_dir!s}'\n"
            "$files = Get-ChildItem -Path $dir -Recurse -File -Force "
            "| Sort-Object {\n"
            "    $_.FullName.Substring($dir.Length + 1).Replace('\\', '/')\n"
            "}\n"
            "$manifest = ''\n"
            "foreach ($f in $files) {\n"
            "    $rel = $f.FullName.Substring($dir.Length + 1)"
            ".Replace('\\', '/')\n"
            "    $hash = (Get-FileHash -Path $f.FullName "
            "-Algorithm SHA256).Hash.ToLower()\n"
            '    $manifest += "$rel`0$hash`n"\n'
            "}\n"
            "$bytes = [System.Text.Encoding]::UTF8.GetBytes($manifest)\n"
            "$sha = [System.Security.Cryptography.SHA256]::Create()\n"
            "$h = [BitConverter]::ToString("
            "$sha.ComputeHash($bytes)).Replace('-','').ToLower()\n"
            'Write-Output "sha256tree:v1:$h"\n'
        )

        result = subprocess.run(  # noqa: S603
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps_script],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
        )
        ps_hash = result.stdout.strip()

        assert python_hash == ps_hash, (
            f"Hash parity failure!\n"
            f"Python: {python_hash}\n"
            f"PowerShell: {ps_hash}\n"
            f"stderr: {result.stderr}"
        )


class TestModuleVerificationIntegration:
    """Integration tests for verify_module.ps1 end-to-end."""

    def test_preflight_approved_with_hash(self, tmp_path: Path) -> None:
        """Module found, hash matches, provenance approved."""
        modules_dir = _make_test_module(tmp_path)
        mod_dir = modules_dir / "TestModule" / "1.0.0"
        mod_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(approved_hashes=[mod_hash])
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        assert report.get("module_name") == "TestModule"
        assert report.get("provenance_approved") is True
        assert report.get("execution_supported") is True
        assert report.get("evidence_path") in ("hash_only", "signature_and_hash")
        assert len(report.get("candidates", [])) == 1
        assert report["approved_candidate"] is not None
        assert report["approved_candidate"]["package_hash"] == mod_hash
        assert report["approved_candidate"]["hash_approved"] is True

    def test_preflight_rejected_hash_mismatch(self, tmp_path: Path) -> None:
        """Module found, hash does not match, provenance rejected."""
        modules_dir = _make_test_module(tmp_path)

        fake_hash = "sha256tree:v1:0000000000000000000000000000000000000000000000000000000000000000"
        input_blob = _make_basic_input(approved_hashes=[fake_hash])
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        assert report.get("provenance_approved") is False
        assert len(report.get("rejection_reasons", [])) > 0

    def test_preflight_no_candidates(self, tmp_path: Path) -> None:
        """Module not installed, no candidates found."""
        # Empty PSModulePath
        empty_dir = tmp_path / "EmptyModules"
        empty_dir.mkdir()

        input_blob = _make_basic_input(module_name="NonexistentModule")
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(empty_dir))

        assert report.get("provenance_approved") is False
        assert "no_candidates" in report.get("rejection_reasons", [])
        assert len(report.get("candidates", [])) == 0

    def test_preflight_version_out_of_range(self, tmp_path: Path) -> None:
        """Module found but version is outside policy range."""
        modules_dir = _make_test_module(tmp_path, version="3.0.0")
        mod_dir = modules_dir / "TestModule" / "3.0.0"
        mod_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(
            version_range=">=1.0.0,<2.0.0",
            approved_hashes=[mod_hash],
        )
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        assert report.get("provenance_approved") is False
        # Candidate should exist but be rejected
        candidates = report.get("candidates", [])
        assert len(candidates) == 1
        assert candidates[0]["provenance_approved"] is False

    def test_confinement_violation_path_escape(self, tmp_path: Path) -> None:
        """Module with RootModule escaping module base is rejected."""
        modules_dir = _make_test_module(
            tmp_path,
            root_module=None,
            extra_psd1_fields="    RootModule = '../../escape.psm1'\n",
        )

        input_blob = _make_basic_input(approved_hashes=["sha256tree:v1:dummy"])
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        assert report.get("provenance_approved") is False
        candidates = report.get("candidates", [])
        assert len(candidates) == 1
        assert candidates[0].get("confinement_violation") is not None

    def test_signature_platform_unsupported_on_linux(self, tmp_path: Path) -> None:
        """On Linux, signature status should be 'platform_unsupported'."""
        import platform

        if platform.system() == "Windows":
            pytest.skip("Test only meaningful on non-Windows")

        modules_dir = _make_test_module(tmp_path)
        mod_dir = modules_dir / "TestModule" / "1.0.0"
        mod_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(approved_hashes=[mod_hash])
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        candidates = report.get("candidates", [])
        assert len(candidates) == 1
        # On Linux, both live and staged signature status should be platform_unsupported
        assert candidates[0].get("live_signature_status") == "platform_unsupported"
        assert candidates[0].get("staged_signature_status") == "platform_unsupported"
        # Evidence path should be hash_only (signature unavailable)
        assert candidates[0].get("evidence_path") == "hash_only"

    def test_hash_fallback_disallowed(self, tmp_path: Path) -> None:
        """When allow_package_hash_fallback is false and sig fails, rejected."""
        import platform

        if platform.system() == "Windows":
            pytest.skip("Test meaningful on non-Windows where sigs unavailable")

        modules_dir = _make_test_module(tmp_path)
        mod_dir = modules_dir / "TestModule" / "1.0.0"
        mod_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(
            approved_hashes=[mod_hash],
            allow_hash_fallback=False,
        )
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        assert report.get("provenance_approved") is False
        candidates = report.get("candidates", [])
        assert len(candidates) == 1
        assert candidates[0]["provenance_approved"] is False

    def test_report_always_written_on_rejection(self, tmp_path: Path) -> None:
        """Report file is written even when provenance is rejected."""
        empty_dir = tmp_path / "EmptyModules"
        empty_dir.mkdir()

        input_blob = _make_basic_input(module_name="NonexistentModule")
        report, _proc = _run_template(input_blob, tmp_path, ps_module_path=str(empty_dir))

        # Report should have been written
        assert report != {}
        assert "module_name" in report

    def test_tree_hash_matches_python(self, tmp_path: Path) -> None:
        """Tree hash computed by template matches Python implementation."""
        modules_dir = _make_test_module(
            tmp_path,
            extra_files={
                "Private/Helper.ps1": 'function Get-Helper { return "helper" }\n',
                "Public/Main.ps1": 'function Get-Main { return "main" }\n',
            },
        )
        mod_dir = modules_dir / "TestModule" / "1.0.0"
        expected_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(approved_hashes=[expected_hash])
        report, proc = _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        candidates = report.get("candidates", [])
        assert len(candidates) == 1
        assert candidates[0]["package_hash"] == expected_hash, (
            f"Hash mismatch!\n"
            f"Python:     {expected_hash}\n"
            f"PowerShell: {candidates[0].get('package_hash')}\n"
            f"stderr: {proc.stderr}"
        )

    def test_report_parseable_by_python(self, tmp_path: Path) -> None:
        """Report JSON is parseable by parse_verification_report."""
        modules_dir = _make_test_module(tmp_path)
        mod_dir = modules_dir / "TestModule" / "1.0.0"
        mod_hash = _compute_module_hash(mod_dir)

        input_blob = _make_basic_input(approved_hashes=[mod_hash])
        _run_template(input_blob, tmp_path, ps_module_path=str(modules_dir))

        # report.json already exists from _run_template, re-parse with Python parser
        report_path = tmp_path / "report.json"
        from gxassessms.core.contracts.verification import parse_verification_report

        result = parse_verification_report(report_path)
        assert result.module_name == "TestModule"
        assert result.provenance_approved is True
        assert result.approved_candidate is not None
