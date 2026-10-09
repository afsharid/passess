# DeepSeek Harness plugin

DeepSeek Harness (DSH) reads a provider's key from the variable its `apiKeyEnv` names.
This plugin lets it read that key from passess instead, however DSH is opened: from the
Dock, from Spotlight, or by its own restart after an update ([ADR 11](../../../docs/adr/0011-an-app-reads-the-keys-connected-to-it.md)).

In Passess.app, DeepSeek Harness is in the coding agents list: Set up installs the
plugin, and each key DSH asks for shows whether it reaches DSH, with a button that
connects it. From a terminal, the same is:

```text
passess install dsh --apply     # the plugin, and the row in ~/.dsh/profiles/desktop/cordis.patch.yml
passess status dsh              # plugin state, whether a running DSH loaded it, each key
passess set NAME --clients dsh  # connect a key by name; connected to every agent does not count
```

`index.mjs` is embedded in the passess binary; install writes it to
`~/.local/share/passess/dsh/index.mjs` and adds the row that loads it between
`# passess start` and `# passess end` in the profile patch, leaving the rest of the file
as it was. Restart DSH after an install that changed the plugin.

A key DSH finds itself (its launch environment, `~/.dsh/.credentials.yaml`, a `.env`)
wins. For any other, the plugin asks `passess list --json` which secrets are connected
to `dsh` and runs `passess helper NAME` for those, without a shell, so passess sees DSH
as the caller. It keeps a value in memory for `ttlSeconds` (300) and a refusal for
`listSeconds` (30); a refusal reads as a missing key, and DSH reports
`MISSING_CREDENTIAL`. It never logs or writes a value. DSH's Models page shows a
connected key as set by the environment, so a key cannot be typed there over it.

`make dsh-check` runs its test against a stand-in passess.
