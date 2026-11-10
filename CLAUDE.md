# awto-jms539

- Entry point: `python3 scripts/dev.py --help`; `describe` returns JSON.
- Run `python3 scripts/dev.py test` or `gate`; logs are in `tmp/logs/dev.log`.
- `version` requires an explicitly selected device. `plan` is offline only;
  `dev.py` has no firmware-writing command.
- `scripts/jms539_flash.py` (`check`/`write`/`restore`) is the only writer.
  Never run on hardware without Dan's explicit go; never mode 3. Tests use a
  fake dock (`tests/test_jms539_flash.py`).
- Keep vendor binaries, captures and generated research in their ignored paths.
