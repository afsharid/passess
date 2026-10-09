import Foundation

/// Output of `passess status --json`: how each coding agent (harness) is set
/// up. Mirrors harnessOutput in internal/cli/install.go, for the fields the
/// panel reads.
public struct HarnessStatus: Decodable, Equatable {
    public struct Harness: Decodable, Equatable {
        public struct Server: Decodable, Equatable {
            public let name: String
            public let state: String
        }

        public let id: String
        public let label: String
        public let servers: [Server]?
        public let instructionsState: String
        public let hooks: String
        public let actions: [Action]?
        public let errors: [String]?

        enum CodingKeys: String, CodingKey {
            case id, label, servers, hooks, actions, errors
            case instructionsState = "instructions_state"
        }
    }

    /// A change `passess install` would make; only whether there are any matters here.
    public struct Action: Decodable, Equatable {
        public let kind: String
    }

    /// A desktop app that reads its own keys through passess (ADR 11).
    /// Mirrors appReport in internal/cli/apps.go.
    public struct App: Decodable, Equatable {
        public struct Key: Decodable, Equatable {
            public let name: String
            public let state: String // connected | every-agent | elsewhere | undefined
        }

        public let id: String
        public let label: String
        public let plugin: String // ok | missing | drift
        public let active: String? // when the running app loaded the plugin
        public let keys: [Key]?
        public let errors: [String]?

        public init(id: String, label: String, plugin: String, active: String?, keys: [Key]?, errors: [String]?) {
            (self.id, self.label, self.plugin, self.active, self.keys, self.errors) = (id, label, plugin, active, keys, errors)
        }
    }

    public let harnesses: [Harness]
    public let apps: [App]? // nil from a passess older than ADR 11

    public init(harnesses: [Harness], apps: [App]?) {
        self.harnesses = harnesses
        self.apps = apps
    }
}

/// A key an app asks for that does not reach it yet.
public struct KeyNeed: Identifiable, Equatable {
    public var id: String { name }
    public let name: String
    public let note: String
}

/// One coding agent in the panel.
public struct AgentRow: Identifiable, Equatable {
    public let id: String
    public let monogram: String
    public let title: String
    public let detail: String
    public let tone: Tone
    public let symbol: String
    /// The ID `passess install` sets up, when it needs it.
    public let install: String?
    /// For an app, the keys it asks for that do not reach it.
    public let keys: [KeyNeed]

    /// The command that sets it up, as a terminal would run it.
    public var fix: String? { install.map { "passess install \($0) --apply" } }
}

/// The coding agents, those that need something first. running says whether
/// an app is open, which tells a plugin waiting for a restart from one
/// waiting for the app to start.
public func codingAgents(_ status: HarnessStatus, running: (String) -> Bool = { _ in false }) -> [AgentRow] {
    let rows = status.harnesses.map { h -> AgentRow in
        var parts: [String] = []
        var attention = !(h.actions ?? []).isEmpty || !(h.errors ?? []).isEmpty
        switch h.hooks {
        case "ok": parts.append(t("hooks"))
        case "missing": parts.append(t("no hooks")); attention = true
        case "drift": parts.append(t("hooks outdated")); attention = true
        case "unavailable": parts.append(t("hooks by hand"))
        default: break
        }
        switch h.instructionsState {
        case "ok": parts.append(t("instructions"))
        case "missing": parts.append(t("no instructions")); attention = true
        case "drift": parts.append(t("instructions outdated")); attention = true
        default: break
        }
        let servers = h.servers ?? []
        if !servers.isEmpty {
            parts.append(t(servers.count == 1 ? "%ld MCP server" : "%ld MCP servers", servers.count))
            if servers.contains(where: { $0.state != "ok" }) { attention = true }
        }
        let guarded = h.hooks == "ok" || h.instructionsState == "ok" || !servers.isEmpty
        let tone: Tone = attention ? .warning : (guarded ? .ok : .neutral)
        var detail = parts.isEmpty ? t("Nothing set up") : parts.joined(separator: " · ")
        if let error = h.errors?.first { detail = error }
        return AgentRow(id: h.id, monogram: monogram(h.id, label: h.label), title: h.label, detail: detail, tone: tone,
                        symbol: tone == .ok ? "checkmark.shield.fill" : tone == .warning ? "exclamationmark.shield.fill" : "shield",
                        install: attention ? h.id : nil, keys: [])
    } + (status.apps ?? []).map { appRow($0, running: running($0.id)) }
    let order: [Tone: Int] = [.warning: 0, .error: 0, .ok: 1, .neutral: 2]
    return rows.enumerated().sorted { a, b in
        let (x, y) = (order[a.element.tone] ?? 3, order[b.element.tone] ?? 3)
        return x != y ? x < y : a.offset < b.offset
    }.map(\.element)
}

/// Two letters that stand for a harness in the panel; its name is beside them.
func monogram(_ id: String, label: String) -> String {
    let known = ["claude": "CC", "codex": "Cx", "opencode": "OC", "kiro": "K", "antigravity": "AG", "gemini": "G",
                 "cursor": "Cu", "vscode": "VS", "windsurf": "W", "zed": "Z", "claude-desktop": "CD", "dsh": "DS"]
    return known[id] ?? String(label.prefix(2))
}

/// An app's row: its plugin, and the keys it asks for that do not reach it.
func appRow(_ a: HarnessStatus.App, running: Bool) -> AgentRow {
    let keys = a.keys ?? []
    let needs = keys.filter { $0.state != "connected" }.map { k -> KeyNeed in
        switch k.state {
        case "every-agent": return KeyNeed(name: k.name, note: t("connected to every agent, not to this app by name"))
        case "elsewhere": return KeyNeed(name: k.name, note: t("not connected to this app"))
        default: return KeyNeed(name: k.name, note: t("not in passess yet"))
        }
    }
    var parts: [String] = []
    var attention = !needs.isEmpty || !(a.errors ?? []).isEmpty
    switch a.plugin {
    case "ok" where a.active != nil: parts.append(t("plugin loaded"))
    case "ok" where running: parts.append(t("restart it to load the plugin")); attention = true
    case "ok": parts.append(t("plugin ready"))
    case "drift": parts.append(t("plugin outdated")); attention = true
    default: parts.append(t("plugin not set up")); attention = true
    }
    if !keys.isEmpty {
        parts.append(t("%ld of %ld keys reach it", keys.count - needs.count, keys.count))
    }
    let tone: Tone = attention ? .warning : .ok
    return AgentRow(id: a.id, monogram: monogram(a.id, label: a.label), title: a.label,
                    detail: a.errors?.first ?? parts.joined(separator: " · "), tone: tone,
                    symbol: tone == .ok ? "checkmark.shield.fill" : "exclamationmark.shield.fill",
                    install: a.plugin == "ok" ? nil : a.id, keys: needs)
}
