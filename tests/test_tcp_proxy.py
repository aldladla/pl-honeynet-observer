from honeynet.tcp_proxy import proxy_protocol_header


def test_proxy_protocol_header_preserves_ipv4_socket_identity() -> None:
    header = proxy_protocol_header(
        ("192.0.2.44", 54321),
        ("198.51.100.10", 2222),
    )

    assert header == b"PROXY TCP4 192.0.2.44 198.51.100.10 54321 2222\r\n"


def test_proxy_protocol_header_handles_ipv6_and_rejects_invalid_identity() -> None:
    assert proxy_protocol_header(
        ("2001:db8::44", 54321, 0, 0),
        ("2001:db8::10", 2222, 0, 0),
    ) == b"PROXY TCP6 2001:db8::44 2001:db8::10 54321 2222\r\n"
    assert proxy_protocol_header(("not-an-ip", 1234), ("192.0.2.1", 2222)) == (
        b"PROXY UNKNOWN\r\n"
    )
    assert proxy_protocol_header(None, None) == b"PROXY UNKNOWN\r\n"
