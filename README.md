# Nexus Share

Nexus Share is a local-first, encrypted peer-to-peer file transfer project that uses I2P for peer connectivity. The Node.js app provides the browser UI and transfer protocol, while the included PHP service handles local accounts, sessions, and peer discovery.

## About this project

I built this as a school project over two weeks. It was a chance to build a small desktop style web app.

It is not a finished security product, and there are probably rough edges. If you spot a bug, have an idea, or want to improve something, feel free to open an issue or send a pull request. I would be happy to learn from the feedback.

## Features

- I2P/SOCKS-based peer connectivity
- Per-transfer RSA-OAEP and ChaCha20-Poly1305 encryption
- Authenticated transfer metadata and SHA-256 file-integrity validation
- Explicit approval for incoming transfers
- Local-only Web UI bound to `127.0.0.1`
- Automatic i2pd bootstrap with SHA-256 archive verification

## Requirements

- Node.js 18 or newer
- PHP 8 with the `sockets` extension for the local directory service and tests (dont need php if your going to use the allready hosted server)
- Windows for automatic bundled i2pd startup; a running compatible I2P router can be configured on other platforms

## Quick start

1. Copy [.env.example](.env.example) to `.env` and adjust settings if needed. The built-in configuration loader reads `.env`; shell variables take precedence.
2. Run `npm run check` to validate JavaScript and PHP syntax.
3. Run `npm start`.
4. Open <http://127.0.0.1:3000>, register an account, then sign in.

By default, the app starts its local TCP directory service on port `8000`. To use a hosted JSON directory service, configure `AUTH_SERVER_URL` and set `AUTH_USE_HTTP=1`.

## Configuration

The environment template documents all supported options. Important settings include:

| Variable | Default | Purpose |
| --- | --- | --- |
| `UI_PORT` | `3000` | Local browser UI port |
| `AUTH_PORT_UI` | `8000` | Local directory service port |
| `LISTEN_PORT` | `9090` | I2P receiver port |
| `MAX_UPLOAD_BYTES` | `26214400` | Maximum file size accepted by the Web UI (25 MiB) |
| `SOCKET_TIMEOUT` | `30000` | Peer socket inactivity timeout in milliseconds |
| `AUTO_ACCEPT` | `false` | Automatically accept incoming transfers; keep disabled unless required |

## Development and testing

- `npm run check` — syntax-check JavaScript and PHP files
- `npm test` — run the local directory-server security checks
- `npm run test:e2e` — run the two-node I2P transfer test; this starts local services and may take several minutes
- `cd wrapper; cargo build --release` — build the optional Windows launcher. Place the resulting executable beside `p2p.js`; it requires Node.js, or a `NEXUS_NODE_PATH` environment variable that points to Node.js.

Generated files, received files, logs, user databases, and Rust build output are excluded through [.gitignore](.gitignore).

## Code structure

| Location | Responsibility |
| --- | --- |
| [p2p.js](p2p.js) | Composition root and public module exports |
| [src/application.js](src/application.js) | Runtime orchestration, HTTP API, I2P lifecycle, and legacy transfer protocol |
| [lib/config.js](lib/config.js) | Validated configuration and `.env` loading |
| [lib/i2p-sam.js](lib/i2p-sam.js) | SAM session negotiation and destination conversion |
| [lib/socks5.js](lib/socks5.js) | SOCKS5 proxy handshake implementation |
| [lib/logger.js](lib/logger.js) | Structured application logging |
| [lib/transfer-manager.js](lib/transfer-manager.js) | In-memory transfer lifecycle management |
| [lib/validators.js](lib/validators.js) | Input and filename validation |

## Security notes

The app validates filenames, limits request sizes, authenticates sessions, and verifies received file hashes. The automatic i2pd download is pinned to a specific release archive and checked against the upstream SHA-256 digest before extraction.

Please treat this as an educational project rather than a production-ready secure file-sharing service.

## Contributing

Small fixes, clearer documentation, tests, and security feedback are all useful. For bigger changes, opening an issue first makes it easier to discuss the direction before work starts.

## Repository publishing

This project is available under the [MIT License](LICENSE).
