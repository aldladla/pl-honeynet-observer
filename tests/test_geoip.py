from honeynet.geoip import GeoIpResolver, geo_context


def test_geo_context_allowlists_network_location_fields() -> None:
    city = {
        "country": {"iso_code": "PL", "names": {"en": "Poland", "pl": "Polska"}},
        "subdivisions": [{"names": {"en": "Mazovia", "pl": "Mazowieckie"}}],
        "city": {"names": {"en": "Warsaw", "pl": "Warszawa"}},
        "traits": {"raw_sensitive_vendor_field": "must-not-leak"},
    }
    asn = {
        "autonomous_system_number": 64500,
        "autonomous_system_organization": "Example Network",
        "raw_vendor_field": "must-not-leak",
    }

    result = geo_context(city, asn)

    assert result == {
        "country_code": "PL",
        "country_name": "Polska",
        "subdivision": "Mazowieckie",
        "city": "Warszawa",
        "asn": 64500,
        "organization": "Example Network",
        "provider": "local_mmdb",
        "scope": "network_infrastructure",
    }


def test_geo_context_accepts_flat_server_country_database() -> None:
    result = geo_context(
        {"country_code": "NL"},
        {
            "autonomous_system_number": 202412,
            "autonomous_system_organization": "Example Hosting",
        },
    )

    assert result == {
        "country_code": "NL",
        "asn": 202412,
        "organization": "Example Hosting",
        "provider": "local_mmdb",
        "scope": "network_infrastructure",
    }


def test_geoip_resolver_fails_open_without_local_databases(tmp_path) -> None:
    resolver = GeoIpResolver(
        str(tmp_path / "missing-city.mmdb"),
        str(tmp_path / "missing-asn.mmdb"),
    )

    assert resolver.lookup("192.0.2.1") is None
    assert resolver.lookup("203.0.113.8") is None
    assert resolver.lookup("not-an-ip") is None
