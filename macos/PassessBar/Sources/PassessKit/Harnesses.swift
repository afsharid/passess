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

    public let harnesses: [Harness]
}

/// One coding agent in the panel.
public struct AgentRow: Identifiable, Equatable {
    public let id: String
    public let monogram: String
    public let title: String
    public let detail: String
    public let tone: Tone
    public let symbol: String
    public let fix: String? // the command that sets it up
}

/// The coding agents, those that need something first.
public func codingAgents(_ status: HarnessStatus) -> [AgentRow] {
    let rows = status.harnesses.map { h -> AgentRow in
        var parts: [String] = []
        var attention = !(h.actions ?? []).isEmpty || !(h.errors ?? []).isEmpty
        switch h.hooks {
        case "ok": parts.append("hooks")
        case "missing": parts.append("no hooks"); attention = true
        case "drift": parts.append("hooks outdated"); attention = true
        case "unavailable": parts.append("hooks by hand")
        default: break
        }
        switch h.instructionsState {
        case "ok": parts.append("instructions")
        case "missing": parts.append("no instructions"); attention = true
        case "drift": parts.append("instructions outdated"); attention = true
        default: break
        }
        let servers = h.servers ?? []
        if !servers.isEmpty {
            parts.append("\(servers.count) MCP server\(servers.count == 1 ? "" : "s")")
            if servers.contains(where: { $0.state != "ok" }) { attention = true }
        }
        let guarded = h.hooks == "ok" || h.instructionsState == "ok" || !servers.isEmpty
        let tone: Tone = attention ? .warning : (guarded ? .ok : .neutral)
        var detail = parts.isEmpty ? "Nothing set up" : parts.joined(separator: " · ")
        if let error = h.errors?.first { detail = error }
        return AgentRow(id: h.id, monogram: monogram(h.id, label: h.label), title: h.label, detail: detail, tone: tone,
                        symbol: tone == .ok ? "checkmark.shield.fill" : tone == .warning ? "exclamationmark.shield.fill" : "shield",
                        fix: attention ? "passess install \(h.id) --apply" : nil)
    }
    let order: [Tone: Int] = [.warning: 0, .error: 0, .ok: 1, .neutral: 2]
    return rows.enumerated().sorted { a, b in
        let (x, y) = (order[a.element.tone] ?? 3, order[b.element.tone] ?? 3)
        return x != y ? x < y : a.offset < b.offset
    }.map(\.element)
}

/// Two letters that stand for a harness in the panel; its name is beside them.
func monogram(_ id: String, label: String) -> String {
    let known = ["claude": "CC", "codex": "Cx", "opencode": "OC", "kiro": "K", "antigravity": "AG", "gemini": "G",
                 "cursor": "Cu", "vscode": "VS", "windsurf": "W", "zed": "Z", "claude-desktop": "CD"]
    return known[id] ?? String(label.prefix(2))
}
