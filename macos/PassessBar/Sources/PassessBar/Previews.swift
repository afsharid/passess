import AppKit
import PassessKit
import SwiftUI

/// Renders the panel and the approval window in sample states, in light and
/// dark, to PNG files: a change can be looked at without clicking through the
/// menu bar. The samples go through the same JSON decoding as the CLI's
/// output.
@MainActor
func renderPreviews(to dir: URL) -> Int32 {
    _ = NSApplication.shared
    NSApp.setActivationPolicy(.prohibited)
    do {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    } catch {
        print("error: \(error)")
        return 1
    }
    var failed = 0
    // English for every sample; the Secrets screens in Turkish too, as "-tr".
    for (name, view, translated) in samples() {
        for language in translated ? [L10n.Language.english, .turkish] : [.english] {
            L10n.override = language
            let base = language == .turkish ? "\(name)-tr" : name
            for (suffix, appearance) in [("light", NSAppearance.Name.aqua), ("dark", NSAppearance.Name.darkAqua)] {
                let url = dir.appendingPathComponent("\(base)-\(suffix).png")
                if render(view(), appearance: NSAppearance(named: appearance)!, to: url) {
                    print(url.path)
                } else {
                    print("error: could not render \(base)-\(suffix)")
                    failed += 1
                }
            }
        }
    }
    L10n.override = nil
    return failed == 0 ? 0 : 1
}

@MainActor
private func render(_ view: AnyView, appearance: NSAppearance, to url: URL) -> Bool {
    // Drawn as the key window would be: an offscreen window never is one, and
    // its prominent buttons and switches would come out grey.
    let host = NSHostingView(rootView: view.background(Color(nsColor: .windowBackgroundColor))
        .environment(\.controlActiveState, .key))
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 10, height: 10), styleMask: [.borderless],
                          backing: .buffered, defer: false)
    window.appearance = appearance
    window.contentView = host
    host.frame = NSRect(origin: .zero, size: host.fittingSize)
    window.setContentSize(host.fittingSize)
    host.layoutSubtreeIfNeeded()
    host.display()
    guard let rep = host.bitmapImageRepForCachingDisplay(in: host.bounds) else { return false }
    host.cacheDisplay(in: host.bounds, to: rep)
    guard let png = rep.representation(using: .png, properties: [:]) else { return false }
    return (try? png.write(to: url)) != nil
}

@MainActor
private func samples() -> [(String, () -> AnyView, Bool)] {
    let now = Date()
    let later = ISO8601DateFormatter().string(from: now.addingTimeInterval(25 * 60))
    let tonight = ISO8601DateFormatter().string(from: now.addingTimeInterval(7 * 3600))

    let healthy = decode(Doctor.self, """
    {"version": "0.5.0-alpha", "ok": true,
     "config": {"path": "/Users/you/.config/passess/config.toml", "ok": true},
     "secrets": 4, "profiles": 1, "harness": null, "problems": [],
     "backends": [{"scheme": "bws", "ok": true, "detail": "machine token from keychain://bws/machine"},
                  {"scheme": "keychain", "ok": true}]}
    """)
    let broken = decode(Doctor.self, """
    {"version": "0.5.0-alpha", "ok": false,
     "config": {"path": "/Users/you/.config/passess/config.toml", "ok": true},
     "secrets": 4, "profiles": 0, "harness": null,
     "backends": [{"scheme": "vault", "ok": false, "detail": "no vault address; set backends.vault.address or VAULT_ADDR"},
                  {"scheme": "keychain", "ok": true}],
     "problems": [{"severity": "error", "message": "vault:// is not usable",
                   "fix": "set backends.vault.address (or VAULT_ADDR) and a token: backends.vault.token, VAULT_TOKEN or `vault login`"},
                  {"severity": "warning", "message": "~/.config/opencode/opencode.jsonc can be read by other users",
                   "fix": "chmod 600 ~/.config/opencode/opencode.jsonc"}]}
    """)
    let noConfig = decode(Doctor.self, """
    {"version": "0.5.0-alpha", "ok": false,
     "config": {"path": "/Users/you/.config/passess/config.toml", "ok": false,
                "error": "no passess config at ~/.config/passess/config.toml"},
     "secrets": 0, "profiles": 0, "backends": [], "problems": [], "harness": null}
    """)
    let agentOn = decode(AgentStatus.self, """
    {"running": true, "pid": 81095, "build": "0.5.0-alpha", "cache_ttl": "10m0s",
     "cached": ["OPENROUTER_API_KEY", "HASS_TOKEN"], "expires": "\(later)", "jobs": 0, "served": 14,
     "approvers": 1, "pending": 0,
     "approvals": [{"secret": "HASS_TOKEN", "program": "curl", "anchor": {"pid": 46551, "name": "claude"}, "until": "\(tonight)"}]}
    """)
    let agentOff = decode(AgentStatus.self, #"{"running": false}"#)
    func harness(_ id: String, _ label: String, hooks: String, instructions: String, servers: Int = 0, actions: Int = 0) -> String {
        let s = (0..<servers).map { #"{"name": "server\#($0)", "state": "ok"}"# }.joined(separator: ",")
        let a = (0..<actions).map { _ in #"{"kind": "add"}"# }.joined(separator: ",")
        return #"{"id": "\#(id)", "label": "\#(label)", "servers": [\#(s)], "instructions_state": "\#(instructions)", "hooks": "\#(hooks)", "actions": [\#(a)], "errors": []}"#
    }
    let agents = decode(HarnessStatus.self, "{\"applied\": false, \"harnesses\": [" + [
        harness("claude", "Claude Code", hooks: "ok", instructions: "ok"),
        harness("codex", "Codex", hooks: "ok", instructions: "ok", servers: 1),
        harness("opencode", "OpenCode", hooks: "ok", instructions: "ok"),
        harness("kiro", "Kiro", hooks: "unavailable", instructions: "ok"),
        harness("antigravity", "Antigravity", hooks: "ok", instructions: "ok"),
        harness("claude-desktop", "Claude Desktop", hooks: "none", instructions: "none"),
    ].joined(separator: ",") + "]}")
    let agentsNeedSetup = decode(HarnessStatus.self, "{\"applied\": false, \"harnesses\": [" + [
        harness("claude", "Claude Code", hooks: "ok", instructions: "ok"),
        harness("codex", "Codex", hooks: "missing", instructions: "ok", actions: 1),
    ].joined(separator: ",") + "]}")
    let ask = decode(AgentAsk.self, """
    {"id": "7", "secrets": ["GITHUB_TOKEN"], "program": "gh", "path": "/opt/homebrew/bin/gh",
     "argv": ["gh", "pr", "create", "--fill"], "dir": "\(NSHomeDirectory())/Projects/passess",
     "harness": "claude-code", "anchor": {"pid": 46551, "name": "claude"}, "until": "\(tonight)"}
    """)

    let project = "92fe9fe6-c441-4b27-b261-b4b9007117b9"
    let list = decode(SecretList.self, """
    {"config": "/Users/you/.config/passess/config.toml",
     "agents": [{"id": "claude-code", "label": "Claude Code"}, {"id": "codex", "label": "Codex"},
                {"id": "opencode", "label": "OpenCode"}, {"id": "kiro", "label": "Kiro"},
                {"id": "antigravity", "label": "Antigravity"}, {"id": "cursor", "label": "Cursor"},
                {"id": "gemini-cli", "label": "Gemini CLI"}, {"id": "zed", "label": "Zed"}],
     "secrets": [
      {"name": "HASS_TOKEN", "backends": ["bws"], "refs": ["bws://\(project)/HASS_TOKEN"], "allow": [],
       "clients": ["claude-code"], "approve": true, "profiles": [], "mcp": []},
      {"name": "OPENROUTER_API_KEY", "backends": ["bws"], "refs": ["bws://\(project)/OPENROUTER_API_KEY"], "allow": [],
       "clients": ["claude-code", "codex", "opencode"], "approve": false, "profiles": [], "mcp": []},
      {"name": "SUDO_PASSWORD", "backends": ["bws"], "refs": ["bws://\(project)/SUDO_PASSWORD"], "allow": [],
       "clients": [], "approve": true, "profiles": [], "mcp": []},
      {"name": "TELEGRAM_BOT_TOKEN", "backends": ["bws"], "refs": ["bws://\(project)/TELEGRAM_BOT_TOKEN"], "allow": [],
       "clients": null, "approve": false, "profiles": ["hermes"], "mcp": []}]}
    """)
    let anHourAgo = ISO8601DateFormatter().string(from: now.addingTimeInterval(-3600))
    let discovery = decode(Discovery.self, """
    {"backends": [{"scheme": "bws", "ok": true}],
     "secrets": [{"key": "GITHUB_TOKEN", "project": "ai-stack", "name": "GITHUB_TOKEN",
                  "ref": "bws://\(project)/GITHUB_TOKEN", "name_taken": false, "created": "\(anHourAgo)"},
                 {"key": "slack-bot", "project": "ai-stack", "name": "SLACK_BOT",
                  "ref": "bws://0b2f6c1e-1d2e-4a5b-9c8d-7e6f5a4b3c2d", "name_taken": false, "created": "2026-05-01T09:00:00Z"}]}
    """)
    let listCheck = decode(Check.self, """
    {"config": "/Users/you/.config/passess/config.toml", "ok": true,
     "secrets": [{"name": "HASS_TOKEN", "state": "ok"}, {"name": "OPENROUTER_API_KEY", "state": "ok"},
                 {"name": "SUDO_PASSWORD", "state": "ok"}, {"name": "TELEGRAM_BOT_TOKEN", "state": "not found"}]}
    """)

    func panel(_ configure: @escaping (BarModel) -> Void) -> () -> AnyView {
        {
            let model = BarModel()
            configure(model)
            return AnyView(PanelView(model: model))
        }
    }
    func secretsModel() -> BarModel {
        let model = BarModel()
        model.seed(doctor: healthy, agent: agentOn, harnesses: agents, check: listCheck, secretList: list, discovery: discovery)
        return model
    }
    let allResolve = decode(Check.self, """
    {"config": "/Users/you/.config/passess/config.toml", "ok": true,
     "secrets": [{"name": "HASS_TOKEN", "state": "ok"}, {"name": "OPENROUTER_API_KEY", "state": "ok"},
                 {"name": "SUDO_PASSWORD", "state": "ok"}, {"name": "TELEGRAM_BOT_TOKEN", "state": "ok"}]}
    """)
    return [
        ("panel-healthy", panel { $0.seed(doctor: healthy, agent: agentOn, harnesses: agents, check: allResolve, checkedAt: now,
                                          approving: true, secretList: list, discovery: discovery) }, true),
        ("panel-problems", panel { $0.seed(doctor: broken, agent: agentOff, harnesses: agentsNeedSetup) }, false),
        ("panel-old-cli", panel { $0.seed(doctor: healthy, agent: nil, harnesses: agents) }, false),
        ("panel-loading", panel { $0.seed(doctor: nil, agent: nil) }, false),
        ("panel-no-config", panel { $0.seed(doctor: noConfig, agent: agentOff) }, false),
        ("panel-cli-missing", panel { $0.seed(doctor: nil, failure: Passess.Failure.notFound.description, agent: nil) }, false),
        ("ask", { AnyView(AskView(card: askCard(ask), allowTitle: t("Allow with Touch ID"), onAllow: {}, onDeny: {})) }, false),
        ("secrets", { AnyView(SecretsView(model: secretsModel()).frame(width: 480, height: 470)) }, true),
        ("connect-new", { AnyView(ConnectView(model: ConnectModel(mode: .add(discovery.secrets[0]), list: list, cli: nil), onCancel: {})) }, true),
        ("connect-change", { AnyView(ConnectView(model: ConnectModel(mode: .edit(list.secrets[3]), list: list, cli: nil), onCancel: {})) }, true),
    ]
}

private func decode<T: Decodable>(_ type: T.Type, _ json: String) -> T {
    do {
        return try AgentJSON.decoder.decode(type, from: Data(json.utf8))
    } catch {
        fatalError("preview sample \(T.self): \(error)")
    }
}
