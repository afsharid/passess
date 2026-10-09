import Foundation

/// Output of `passess list --json`. Mirrors listOutput in internal/cli/list.go.
/// Names, references and who may use each secret; never a value.
public struct SecretList: Decodable, Equatable {
    /// A coding agent a secret can be connected to.
    public struct Agent: Decodable, Equatable, Identifiable {
        public let id: String
        public let label: String
        /// A desktop app reading its own keys: only a list that names it lets
        /// a secret reach it, never "every agent" (ADR 11).
        public let app: Bool?

        public init(id: String, label: String, app: Bool? = nil) {
            self.id = id
            self.label = label
            self.app = app
        }

        public var isApp: Bool { app ?? false }
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
        /// Why it is not OK where the app acts on it: "not-set-up" when no
        /// token is stored anywhere passess looks.
        public let state: String?
        public let error: String?
    }

    /// bws has no machine token yet: the panel offers the vault window.
    public var bwsNotSetUp: Bool {
        backends.contains { $0.scheme == "bws" && $0.state == "not-set-up" }
    }

    public struct Found: Decodable, Equatable, Identifiable {
        public var id: String { ref }
        public let key: String // its name in the vault
        public let project: String
        public let name: String // the name passess suggests
        public let ref: String
        public let nameTaken: Bool
        public let created: String? // when it was added to the vault, RFC 3339

        enum CodingKeys: String, CodingKey {
            case key, project, name, ref, created
            case nameTaken = "name_taken"
        }
    }

    public let backends: [Backend]
    public let secrets: [Found]
}

/// One secret in the Secrets card.
public struct SecretRow: Identifiable, Equatable {
    public let id: String // its name
    public let clients: [String]? // the agents it is connected to; nil: every one
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
        return SecretRow(id: s.name, clients: s.clients, agents: agentsText(s.clients, agents: list.agents ?? []),
                         asks: s.approve ?? false, usedBy: usedBy(s), tone: tone, symbol: symbol)
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

/// The vault's unconnected secrets, those added in the last three days
/// first and marked new; within each group, in the order discover gave.
public func foundRows(_ d: Discovery, now: Date = Date()) -> [FoundRow] {
    let parse = ISO8601DateFormatter()
    let rows = d.secrets.map { f -> FoundRow in
        let created = f.created.flatMap(parse.date(from:))
        let fresh = created.map { now.timeIntervalSince($0) < 3 * 86_400 } ?? false
        return FoundRow(title: f.key, detail: f.project.isEmpty ? "bws" : t("%@ · %@", "bws", f.project), isNew: fresh, found: f)
    }
    return rows.filter(\.isNew) + rows.filter { !$0.isNew }
}

/// The agents ticked when the Connect window opens: a secret every agent may
/// use has them all ticked.
public func pickedAgents(_ clients: [String]?, agents: [SecretList.Agent]) -> Set<String> {
    Set(clients ?? agents.filter { !$0.isApp }.map(\.id)) // every agent does not reach an app
}

/// The --clients value for the ticked agents: every coding agent and no app
/// is "all", which takes in agents passess learns later; an app ticked is
/// named, since only a list naming it reaches it; none is "none".
public func clientsArgument(_ picked: Set<String>, agents: [SecretList.Agent]) -> String {
    let coding = agents.filter { !$0.isApp }
    if !coding.isEmpty && coding.allSatisfy({ picked.contains($0.id) }) && !agents.contains(where: { $0.isApp && picked.contains($0.id) }) {
        return "all"
    }
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

/// Whether a name matches what the user typed to filter by: any part of it,
/// ignoring case; an empty filter matches everything.
public func matches(_ name: String, filter: String) -> Bool {
    let f = filter.trimmingCharacters(in: .whitespaces)
    return f.isEmpty || name.range(of: f, options: [.caseInsensitive, .diacriticInsensitive]) != nil
}

/// Why a name cannot be used, or nil.
public func nameProblem(_ name: String, taken: [String]) -> String? {
    if name.range(of: "^[A-Za-z_][A-Za-z0-9_]*$", options: .regularExpression) == nil {
        return t("Use letters, digits and _; start with a letter.")
    }
    if taken.contains(name) { return t("A secret named %@ already exists.", name) }
    return nil
}
