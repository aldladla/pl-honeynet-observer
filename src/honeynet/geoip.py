"""Offline GeoIP enrichment for the private analyst view.

The resolver never performs network requests. It only reads operator-provided
MaxMind-compatible MMDB files and returns network context, not attribution.
"""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Protocol

import maxminddb


class MmdbReader(Protocol):
    def get(self, ip_address: str) -> dict[str, Any] | None: ...


def _localized_name(record: dict[str, Any] | None) -> str | None:
    if not record:
        return None
    names = record.get("names") or {}
    return names.get("pl") or names.get("en")


def geo_context(
    city_record: dict[str, Any] | None,
    asn_record: dict[str, Any] | None,
) -> dict[str, Any] | None:
    """Build a stable, allowlisted projection from City and ASN records."""

    city_record = city_record or {}
    asn_record = asn_record or {}
    country = city_record.get("country") or city_record.get("registered_country") or {}
    subdivisions = city_record.get("subdivisions") or []
    subdivision = subdivisions[0] if subdivisions else None

    values = {
        "country_code": country.get("iso_code") or city_record.get("country_code"),
        "country_name": _localized_name(country),
        "subdivision": _localized_name(subdivision),
        "city": _localized_name(city_record.get("city")),
        "asn": asn_record.get("autonomous_system_number"),
        "organization": asn_record.get("autonomous_system_organization"),
    }
    projected = {field: value for field, value in values.items() if value is not None}
    if not projected:
        return None
    return {
        **projected,
        "provider": "local_mmdb",
        "scope": "network_infrastructure",
    }


class GeoIpResolver:
    """Cached, fail-open reader for optional local MMDB databases."""

    def __init__(self, country_db_path: str | None, asn_db_path: str | None) -> None:
        self._country = self._open(country_db_path)
        self._asn = self._open(asn_db_path)
        self._cache: dict[str, dict[str, Any] | None] = {}

    @staticmethod
    def _open(path_value: str | None) -> MmdbReader | None:
        if not path_value:
            return None
        path = Path(path_value)
        if not path.is_file():
            return None
        try:
            return maxminddb.open_database(path)
        except (OSError, maxminddb.InvalidDatabaseError):
            return None

    def lookup(self, ip_value: str) -> dict[str, Any] | None:
        try:
            address = ipaddress.ip_address(ip_value)
        except ValueError:
            return None
        if not address.is_global:
            return None

        normalized = str(address)
        if normalized in self._cache:
            return self._cache[normalized]
        city_record = self._country.get(normalized) if self._country else None
        asn_record = self._asn.get(normalized) if self._asn else None
        result = geo_context(city_record, asn_record)
        if len(self._cache) >= 16_384:
            self._cache.clear()
        self._cache[normalized] = result
        return result
