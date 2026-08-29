from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_approved_static_analyzer_is_hash_bound_and_fail_closed() -> None:
    script = (
        ROOT / "deploy/malware-static-lab/analyze-approved-static.sh"
    ).read_text(encoding="utf-8")

    assert '"classification": "quarantined_untrusted_sample"' in script
    assert '"execution_allowed": False' in script
    assert '"analysis_mode": "static_only"' in script
    assert '"operator_approved": True' in script
    assert "network interface detected" in script
    assert "analysis medium is not mounted read-only" in script
    assert "SHA-256 mismatch" in script
    assert "sample size mismatch" in script
    assert "sample exceeds static-analysis limit" in script
    assert "execution_performed=no" in script


def test_approved_static_analyzer_never_executes_or_contacts_network() -> None:
    script = (
        ROOT / "deploy/malware-static-lab/analyze-approved-static.sh"
    ).read_text(encoding="utf-8")

    for forbidden in (
        'bash "${sample}"',
        'sh "${sample}"',
        'python "${sample}"',
        'python3 "${sample}"',
        'exec "${sample}"',
        "chmod +x",
        "curl ",
        "wget ",
        "objdump -d",
        "qemu-",
    ):
        assert forbidden not in script

    assert "file -b --keep-going" in script
    assert "readelf --wide -h -l -S -d" in script
    assert 're.findall(rb"[\\x20-\\x7e]{6,}"' in script
