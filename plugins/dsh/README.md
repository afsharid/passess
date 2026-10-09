# DeepSeek Harness plugin

DeepSeek Harness (DSH) reads a provider's key from the variable its `apiKeyEnv` names.
This plugin lets it read that key from passess instead, however DSH is opened: from the
Dock, from Spotlight, or by its own restart after an update ([ADR 11](../../docs/adr/0011-an-app-reads-the-keys-connected-to-it.md)).

1. Connect the secret to DeepSeek Harness by name in Passess.app (or
   `passess set NAME --clients dsh,…`). A secret connected to every agent does not count.
2. Add the plugin to the DSH profile's `cordis.patch.yml`
   (`~/.dsh/profiles/desktop/cordis.patch.yml` for the desktop app), with the absolute
   path of `index.js` (Node does not import a directory by its path):

   ```yaml
   - insert:
       - id: passess-credentials
         name: /Users/you/Projects/passess/plugins/dsh/index.js
   ```

3. Name the secret in the provider, as before: `apiKeyEnv: EVREN_LLM_API_KEY`.

A key DSH finds itself (its launch environment, `~/.dsh/.credentials.yaml`, a `.env`)
wins. For any other, the plugin asks `passess list --json` which secrets are connected
to `dsh` and runs `passess helper NAME` for those, without a shell, so passess sees DSH
as the caller. It keeps a value in memory for `ttlSeconds` (300) and a refusal for
`listSeconds` (30); a refusal reads as a missing key, and DSH reports
`MISSING_CREDENTIAL`. It never logs or writes a value. DSH's Models page shows a
connected key as set by the environment, so a key cannot be typed there over it.

Config, all optional: `passess` (the binary; found in `/opt/homebrew/bin`,
`/usr/local/bin`, `~/.local/bin`, `~/go/bin`), `ttlSeconds`, `listSeconds`.

`make dsh-check` runs its test against a stand-in passess.
