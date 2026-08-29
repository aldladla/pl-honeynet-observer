from honeynet.privacy import REDACTED, redact_text, sanitize_json


def test_sanitize_json_redacts_nested_sensitive_fields_without_mutating_input() -> None:
    source = {
        "password": "guess-me",
        "nested": [{"Authorization": "Bearer abc.def"}, {"safe": "kept"}],
    }

    sanitized = sanitize_json(source)

    assert sanitized == {
        "password": REDACTED,
        "nested": [{"Authorization": REDACTED}, {"safe": "kept"}],
    }
    assert source["password"] == "guess-me"


def test_redact_text_covers_common_inline_secret_forms() -> None:
    value = (
        "curl --password hunter2 "
        "https://alice:secret@example.invalid/file?access_token=token-value "
        "-H 'Authorization: Bearer bearer-value'"
    )

    sanitized = redact_text(value)

    for secret in ("hunter2", "alice:secret", "token-value", "bearer-value"):
        assert secret not in sanitized
    assert sanitized.count(REDACTED) >= 4
