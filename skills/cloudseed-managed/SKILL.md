---
name: cloudseed-managed
description: Managed data platforms through the cloudseed CLI - Databricks and Snowflake connection profiles, testing connectivity, and passing commands to the official CLIs (`cloudseed databricks ...`, `cloudseed snowflake ...`). Use with the cloudseed skill when the user wants to work with Databricks or Snowflake.
---

# cloudseed managed data platforms

- `cloudseed databricks status` / `cloudseed snowflake status`: CLI installed? which profiles exist?
- `cloudseed databricks connect host=https://<workspace>.cloud.databricks.com` then the user enters a token
  interactively (or uses `databricks auth login`). `cloudseed snowflake connect account=<org-acct> user=<u> role=<r> warehouse=<w>`
  (the password is asked with hidden input). Values are `key=value` pairs (`--key value` works too); unknown keys are
  refused and anything missing is asked for - with `-y` the required ones (Databricks host; Snowflake account and user)
  must be given. `connect` writes the current environment's profile, or the one named with `--profile NAME`.
  Never ask the user to paste tokens into chat; tell them to run `connect` themselves.
- Profiles are stored 0600 in ~/.cloudseed/managed.json. Which one a command uses: `--profile NAME` (before or after
  the subcommand: `cloudseed snowflake test --profile prod`), else the current environment's own profile, else the
  saved `default` one (cloudseed says so when it falls back). `--env NAME` in front of the subcommand picks that
  environment's profile.
- `cloudseed databricks test` / `cloudseed snowflake test` verify the connection.
- Anything else is passed straight to the official CLI with the profile: Databricks gets it as environment variables,
  `snow` as a generated 0600 `--config-file` whose default connection is the profile (not used when you pass
  `-c/--connection`, `-x/--temporary-connection` or `--config-file` yourself):
  `cloudseed databricks clusters list`, `cloudseed databricks jobs list`, `cloudseed databricks workspace list /`,
  `cloudseed snowflake sql -q "select current_version()"`, `cloudseed snowflake object list warehouse`.
  To hand the vendor CLI its own `--profile`, start its arguments with `--`: `cloudseed databricks -- clusters list --profile X`.
- A missing CLI is installed only after asking; with `-y` the command stops (exit 2) with `cloudseed install databricks|snow`
  for the user to run.
- Profile secrets are stripped from agent environments and redacted from cloudseed's own output; in an agent session
  the vendor CLI's output is redacted line by line too, and it gets no terminal (piped input only): commands that need
  one (`databricks auth login`, prompts such as `databricks configure` without piped input, `snow sql` without
  `-q`/`-f`) are refused with exit code 2 and the command for the user to run in a terminal. Still never ask it to
  print secrets.
