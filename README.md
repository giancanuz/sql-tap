# sql-tap

Real-time SQL traffic viewer — proxy daemon + TUI client.

sql-tap sits between your application and your database (PostgreSQL or MySQL), capturing every query and displaying it
in an interactive terminal UI. Inspect queries, view transactions, and run EXPLAIN — all without changing your
application code.

![demo](./docs/demo.gif)

## Installation

### Homebrew

```bash
brew install --cask mickamy/tap/sql-tap
```

### Go

```bash
go install github.com/mickamy/sql-tap@latest
go install github.com/mickamy/sql-tap/cmd/sql-tapd@latest
```

### Build from source

```bash
git clone https://github.com/mickamy/sql-tap.git
cd sql-tap
make install
```

### Docker

**PostgreSQL**

```dockerfile
FROM postgres:18-alpine
ARG SQL_TAP_VERSION=0.0.1
ARG TARGETARCH
ADD https://github.com/mickamy/sql-tap/releases/download/v${SQL_TAP_VERSION}/sql-tap_${SQL_TAP_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/sql-tap.tar.gz
RUN tar -xzf /tmp/sql-tap.tar.gz -C /usr/local/bin sql-tapd && rm /tmp/sql-tap.tar.gz
ENTRYPOINT ["sql-tapd", "--driver=postgres", "--listen=:5433", "--upstream=localhost:5432", "--grpc=:9091"]
```

**MySQL**

```dockerfile
FROM mysql:8
ARG SQL_TAP_VERSION=0.0.1
ARG TARGETARCH
ADD https://github.com/mickamy/sql-tap/releases/download/v${SQL_TAP_VERSION}/sql-tap_${SQL_TAP_VERSION}_linux_${TARGETARCH}.tar.gz /tmp/sql-tap.tar.gz
RUN tar -xzf /tmp/sql-tap.tar.gz -C /usr/local/bin sql-tapd && rm /tmp/sql-tap.tar.gz
ENTRYPOINT ["sql-tapd", "--driver=mysql", "--listen=:3307", "--upstream=localhost:3306", "--grpc=:9091"]
```

## Quick start

**1. Start the proxy daemon**

```bash
# PostgreSQL: proxy listens on :5433, forwards to PostgreSQL on :5432
DATABASE_URL="postgres://user:pass@localhost:5432/db?sslmode=disable" \
  sql-tapd --driver=postgres --listen=:5433 --upstream=localhost:5432

# MySQL: proxy listens on :3307, forwards to MySQL on :3306
DATABASE_URL="user:pass@tcp(localhost:3306)/db" \
  sql-tapd --driver=mysql --listen=:3307 --upstream=localhost:3306
```

**2. Point your application at the proxy**

Connect your app to the proxy port instead of the database port. No code changes needed — sql-tapd speaks the native
wire protocol.

**3. Launch the TUI**

```bash
sql-tap localhost:9091
```

All queries flowing through the proxy appear in real-time.

## Usage

### sql-tapd

```
sql-tapd — SQL proxy daemon for sql-tap

Usage:
  sql-tapd [flags]

Flags:
  -driver    database driver: postgres, mysql (required)
  -listen    client listen address (required)
  -upstream  upstream database address (required)
  -grpc      gRPC server address for TUI (default: ":9091")
  -dsn-env   env var holding DSN for EXPLAIN (default: "DATABASE_URL")
  -version   show version and exit
```

Set `DATABASE_URL` (or the env var specified by `-dsn-env`) to enable EXPLAIN support. Without it, the proxy still
captures queries but EXPLAIN is disabled.

### sql-tap

```
sql-tap — Watch SQL traffic in real-time

Usage:
  sql-tap [flags] <addr>

Flags:
  -version  Show version and exit
```

`<addr>` is the gRPC address of sql-tapd (e.g. `localhost:9091`).

## Keybindings

### List view

| Key                | Action                               |
|--------------------|--------------------------------------|
| `j` / `↓`         | Move down                            |
| `k` / `↑`         | Move up                              |
| `Ctrl+d` / `PgDn` | Half-page down                       |
| `Ctrl+u` / `PgUp` | Half-page up                         |
| `/`                | Incremental search                   |
| `Enter`            | Inspect query / transaction          |
| `Space`            | Toggle transaction expand / collapse |
| `Esc`              | Clear search filter                  |
| `x`                | EXPLAIN                              |
| `X`                | EXPLAIN ANALYZE                      |
| `e`                | Edit query, then EXPLAIN             |
| `E`                | Edit query, then EXPLAIN ANALYZE     |
| `c`                | Copy query                           |
| `C`                | Copy query with bound args           |
| `q`                | Quit                                 |

### Inspector view

| Key       | Action                     |
|-----------|----------------------------|
| `j` / `↓` | Scroll down                |
| `k` / `↑` | Scroll up                  |
| `x`       | EXPLAIN                    |
| `X`       | EXPLAIN ANALYZE            |
| `e` / `E` | Edit and EXPLAIN / ANALYZE |
| `c`       | Copy query                 |
| `C`       | Copy query with bound args |
| `q`       | Back to list               |

### Explain view

| Key       | Action                           |
|-----------|----------------------------------|
| `j` / `↓` | Scroll down                      |
| `k` / `↑` | Scroll up                        |
| `h` / `←` | Scroll left                      |
| `l` / `→` | Scroll right                     |
| `c`       | Copy explain plan                |
| `e` / `E` | Edit and re-explain / re-analyze |
| `q`       | Back to list                     |

## How it works

```
┌─────────────┐      ┌───────────────────────┐      ┌────────────────────┐
│ Application │─────▶│  sql-tapd (proxy)     │─────▶│ PostgreSQL / MySQL │
└─────────────┘      │                       │      └────────────────────┘
                     │  captures queries     │
                     │  via wire protocol    │
                     └───────────┬───────────┘
                                 │ gRPC stream
                     ┌───────────▼───────────┐
                     │  sql-tap (TUI)        │
                     └───────────────────────┘
```

sql-tapd parses the database wire protocol (PostgreSQL or MySQL) to intercept queries transparently. It tracks prepared
statements, parameter bindings, transactions, execution time, rows affected, and errors. Events are streamed to
connected TUI clients via gRPC.

## License

[MIT](./LICENSE)
