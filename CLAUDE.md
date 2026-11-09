# awto-jms539

- Entry point: `python3 scripts/dev.py --help`; `describe` returns JSON.
- Run `python3 scripts/dev.py test` or `gate`; logs are in `tmp/logs/dev.log`.
- `version` requires an explicitly selected device. `plan` is offline only;
  no firmware-writing command is implemented.
- Keep vendor binaries, captures and generated research in their ignored paths.
