# Contributing to IronClaw

## Getting Started

1. Fork the repository
2. Clone your fork
3. Build: `make clean && make CISCO=1 FORTIGATE=1 PANOS=1`
4. Run tests: `make test`
5. Create a feature branch: `git checkout -b feature/your-feature`

## Code Standards

### C Code

- C11 standard
- No dynamic memory allocation in the cryptographic path
- All device output must be HMAC-signed before leaving the driver
- Trust tier classification must happen before command execution, never after
- Use fixed-size buffers with explicit bounds checking

### Python Code

- Python 3.10+
- The Python layer is a bridge — it does not sign, verify, or classify
- All cryptographic operations happen in C

### Tests

- Every new driver needs at least: connection test, command classification test, HMAC verification test
- Parser tests must include malformed input cases
- Run `make test` before submitting — zero warnings required

## Adding a New Vendor Driver

1. Create `src/drivers/driver_<vendor>.c` and `include/virp_driver_<vendor>.h`
2. Implement the `virp_driver_t` interface (connect, execute, classify, disconnect)
3. Add command classification for GREEN/YELLOW/RED/BLACK tiers
4. Add parser for structured output extraction
5. Write tests in `tests/test_driver_<vendor>.c`
6. Update the Makefile with a `<VENDOR>=1` flag
7. Create a feature branch and submit a PR

## Pull Request Process

1. Ensure `make test` passes with zero warnings
2. Update documentation if you changed behavior
3. Describe what your PR does and why
4. One PR per feature — keep them focused

## Security

If you find a vulnerability in the cryptographic verification path, **do not open a public issue.** See [SECURITY.md](SECURITY.md).

## Code of Conduct

Be professional. Be constructive. The goal is making networks safer, not winning arguments.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
