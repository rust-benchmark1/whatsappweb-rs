# Build Guidelines

## Prerequisites

This project uses vendored OpenSSL (bundled and compiled from source), which requires some system build tools.

### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install build-essential perl
```

### Other Distributions

**Fedora/RHEL:**

```bash
sudo dnf install gcc make perl-core
```

**Arch Linux:**

```bash
sudo pacman -S base-devel perl
```

## Building

Build the library only (excludes examples and tests):

```bash
cargo build --lib
```

**Note:** The first build will take approximately 1-2 minutes because it compiles OpenSSL 3.5.4 from source. Subsequent builds will be much faster (seconds).

## Build Profiles

**Development build (default):**

```bash
cargo build --lib
```

**Release build (optimized):**

```bash
cargo build --lib --release
```

## Common Issues

### Missing build tools

**Error:** `failed to run custom build command for 'openssl-sys'`

**Solution:** Install the build prerequisites listed above (build-essential and perl).

### Disk space

The vendored OpenSSL build requires approximately 200MB of temporary disk space during compilation.

## Verification

To verify a successful build:

```bash
cargo build --lib 2>&1 | tail -5
```

You should see:

```
Finished `dev` profile [unoptimized + debuginfo] target(s) in X.XXs
```
