import asyncio
import ipaddress
import os
from collections.abc import Sequence
from typing import Any


def proxy_protocol_header(
    peer: Sequence[Any] | None, destination: Sequence[Any] | None
) -> bytes:
    """Build a trusted HAProxy PROXY v1 header for Cowrie.

    The values come from the accepted socket, never from client-provided bytes.
    Cowrie is only reachable from the private sensor network, so untrusted clients
    cannot bypass this gateway and forge the header.
    """

    if not peer or not destination or len(peer) < 2 or len(destination) < 2:
        return b"PROXY UNKNOWN\r\n"

    try:
        source_ip = ipaddress.ip_address(str(peer[0]).split("%", maxsplit=1)[0])
        destination_ip = ipaddress.ip_address(str(destination[0]).split("%", maxsplit=1)[0])
        source_port = int(peer[1])
        destination_port = int(destination[1])
        if source_ip.version != destination_ip.version:
            return b"PROXY UNKNOWN\r\n"
        if not (1 <= source_port <= 65_535 and 1 <= destination_port <= 65_535):
            return b"PROXY UNKNOWN\r\n"
    except (TypeError, ValueError):
        return b"PROXY UNKNOWN\r\n"

    family = "TCP4" if source_ip.version == 4 else "TCP6"
    header = (
        f"PROXY {family} {source_ip} {destination_ip} "
        f"{source_port} {destination_port}\r\n"
    )
    return header.encode("ascii")


async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(64 * 1024):
            writer.write(chunk)
            await writer.drain()
    finally:
        writer.close()
        await writer.wait_closed()


async def handle_client(
    client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
) -> None:
    upstream_host = os.getenv("UPSTREAM_HOST", "cowrie")
    upstream_port = int(os.getenv("UPSTREAM_PORT", "2222"))
    try:
        upstream_reader, upstream_writer = await asyncio.open_connection(
            upstream_host, upstream_port
        )
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return

    header = proxy_protocol_header(
        client_writer.get_extra_info("peername"),
        client_writer.get_extra_info("sockname"),
    )
    upstream_writer.write(header)
    await upstream_writer.drain()

    await asyncio.gather(
        relay(client_reader, upstream_writer),
        relay(upstream_reader, client_writer),
        return_exceptions=True,
    )


async def serve() -> None:
    server = await asyncio.start_server(handle_client, "0.0.0.0", 2222)
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(serve())
