import Foundation

/// Output of `passess list --json`. Mirrors listOutput in internal/cli/list.go.
/// Names, references and who may use each secret; never a value.
public struct SecretList: Decodable, Equatable {
    /// A coding agent a secret can be connected to.
    public struct Agent: Decodable, Equatable, Identifiable {
        public let id: String
        public let label: String

        public init(id: String, label: String) {
            self.id = id
            self.label = label
        }
    }

    public struct Secret: Decodable, Equatable, Identifiable {
        public var id: String { name }
        public let name: String
        public let backends: [String]
        public let refs: [String]?
        /// The coding agents it is connected to; nil means every one.
        public let clients: [String]?
        public let approve: Bool?
        public let profiles: [String]?
        public let mcp: [String]?
        public let note: String?
    }

    public let config: String
    public let secrets: [Secret]
    /// nil from a CLI older than the Secrets screen.
    public let agents: [Agent]?
}

/// Output of `passess discover --json`: the vault's secrets passess has no
/// reference to. Names only.
public struct Discovery: Decodable, Equatable {
    public struct Backend: Decodable, Equatable {
        public let scheme: String
        public let ok: Bool
        public let error: String?
    }

    public struct Found: Decodable, Equatable, Identifiable {
        public var id: String { ref }
        public let key: String // its name in the vault
        public let project: String
        public let name: String // the name passess suggests
        public let ref: String
        public let nameTaken: Bool

        enum CodingKeys: String, CodingKey {
            case key, project, name, ref
            case nameTaken = "name_taken"
        }
    }

    public let backends: [Backend]
    public let secrets: [Found]
}

/// One secret in the Secrets card.
public struct SecretRow: Identifiable, Equatable {
    public let id: String // its name
    public let agents: String // who may use it, in words
    public let asks: Bool // every new program and agent waits for an Allow
    public let usedBy: String? // profiles and MCP servers that hand it on
    public let tone: Tone // from the last check; neutral before one
    public let symbol: String
}

public func secretRows(_ list: SecretList, check: Check?) -> [SecretRow] {
    list.secrets.map { s in
        var tone = Tone.neutral, symbol = "key"
        if let state = check?.secrets.first(where: { $0.name == s.name })?.state {
            (tone, symbol) = state == "ok" ? (.ok, "checkmark.circle.fill") : (.error, "exclamationmark.circle.fill")
        }
        return SecretRow(id: s.name, agents: agentsText(s.clients, agents: list.agents ?? []), asks: s.approve ?? false,
                         usedBy: usedBy(s), tone: tone, symbol: symbol)
    }
}

/// Who a clients list lets in, in words and in the agents' order.
public func agentsText(_ clients: [String]?, agents: [SecretList.Agent]) -> String {
    guard let clients = clients else { return t("Every agent") }
    if clients.isEmpty { return t("No agent") }
    let known = agents.filter { clients.contains($0.id) }.map(\.label)
    let unknown = clients.filter { id in !agents.contains { $0.id == id } }
    return (known + unknown).joined(separator: ", ")
}

/// "Used by profile web, MCP server tool", or nil.
public func usedBy(_ s: SecretList.Secret) -> String? {
    let users = (s.profiles ?? []).map { t("profile %@", $0) } + (s.mcp ?? []).map { t("MCP server %@", $0) }
    return users.isEmpty ? nil : t("Used by %@", users.joined(separator: ", "))
}

/// A vault secret passess does not use yet, as the panel lists it.
public struct FoundRow: Identifiable, Equatable {
    public var id: String { found.ref }
    public let title: String // its name in the vault
    public let detail: String // where it is
    public let isNew: Bool
    public let found: Discovery.Found
}

/// isNew marks what turned up in the vault in the last day.
public func foundRows(_ d: Discovery, firstSeen: [String: Date], now: Date = Date()) -> [FoundRow] {
    d.secrets.map { f in
        let seen = firstSeen[f.ref] ?? now
        return FoundRow(title: f.key, detail: f.project.isEmpty ? "bws" : t("%@ · %@", "bws", f.project),
                        isNew: now.timeIntervalSince(seen) < 24 * 3600, found: f)
    }
}

/// firstSeen after a discovery: a reference seen for the first time gets now,
/// except on the very first discovery, when everything there is old news.
/// References no longer listed are forgotten.
public func noteFirstSeen(_ firstSeen: [String: Date], discovery: Discovery, now: Date = Date()) -> [String: Date] {
    let first = firstSeen.isEmpty
    var next: [String: Date] = [:]
    for f in discovery.secrets {
        next[f.ref] = firstSeen[f.ref] ?? (first ? .distantPast : now)
    }
    return next
}

/// The agents ticked when the Connect window opens: a secret every agent may
/// use has them all ticked.
public func pickedAgents(_ clients: [String]?, agents: [SecretList.Agent]) -> Set<String> {
    Set(clients ?? agents.map(\.id))
}

/// The --clients value for the ticked agents: all of them is "all", which
/// takes in agents passess learns later; none is "none".
public func clientsArgument(_ picked: Set<String>, agents: [SecretList.Agent]) -> String {
    if !agents.isEmpty && agents.allSatisfy({ picked.contains($0.id) }) { return "all" }
    let ids = agents.map(\.id).filter(picked.contains)
    return ids.isEmpty ? "none" : ids.joined(separator: ",")
}

/// Where a secret comes from, short: "bws · OPENROUTER_API_KEY" for a key in a
/// bws project, the vault alone otherwise.
public func sourceText(_ ref: String) -> String {
    guard let range = ref.range(of: "://") else { return ref }
    let scheme = String(ref[..<range.lowerBound])
    let path = ref[range.upperBound...].split(separator: "/")
    if scheme == "bws", path.count == 2 { return t("%@ · %@", scheme, String(path[1])) }
    return scheme
}

/// Why a name cannot be used, or nil.
public func nameProblem(_ name: String, taken: [String]) -> String? {
    if name.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil {
        return t("Use letters, digits and _; start with a letter.")
    }
    if taken.contains(name) { return t("A secret named %@ already exists.", name) }
    return nil
}
