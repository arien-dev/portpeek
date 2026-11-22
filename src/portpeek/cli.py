import argparse
import socket
import sys


def check_port(host: str, port: int, timeout: float = 0.5) -> bool:
    """Returns True if the port is open/in use, False if closed/free."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="Check whether a TCP port is open or free."
    )
    parser.add_argument("port", type=int, help="Port number to check (1-65535)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target host (default: 127.0.0.1)"
    )

    args = parser.parse_args()

    if not (1 <= args.port <= 65535):
        print("Error: Port must be between 1 and 65535.", file=sys.stderr)
        sys.exit(1)

    in_use = check_port(args.host, args.port)
    if in_use:
        print(f"[IN USE] {args.host}:{args.port} is reachable.")
    else:
        print(f"[FREE]   {args.host}:{args.port} is not accepting connections.")


if __name__ == "__main__":
    main()
