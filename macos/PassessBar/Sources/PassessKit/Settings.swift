import Foundation

/// Output of `passess backend --json`. Mirrors backendView in
/// internal/cli/backend.go: settings, and where each credential lives.
public struct BackendSettings: Decodable, Equatable {
    public struct OP: Decodable, Equatable {
        public var account: String
    }

    public struct Vault: Decodable, Equatable {
        public var address: String
        public var namespace: String
        public var caCert: String
        public let token: String // a reference

        enum CodingKeys: String, CodingKey {
            case address, namespace, token
            case caCert = "ca_cert"
        }
    }

    public struct BW: Decodable, Equatable {
        public let session: String // a reference
    }

    public struct BWS: Decodable, Equatable {
        public var serverURL: String
        public let accessToken: String // a reference

        enum CodingKeys: String, CodingKey {
            case serverURL = "server_url"
            case accessToken = "access_token"
        }
    }

    public var op: OP
    public var vault: Vault
    public let bw: BW
    public var bws: BWS
}

/// One server in `passess mcp list --json`. Mirrors mcpView in
/// internal/cli/settings.go: names and plain values only.
public struct MCPServer: Decodable, Equatable, Identifiable {
    public let name: String
    public let command: [String]?
    public let url: String?
    public let env: [String: String]? // variable → secret name
    public let vars: [String: String]?
    public let inherit: [String]?
    public let headers: [String: String]? // header → {{SECRET}} template
    public let harnesses: [String] // empty: every installed one
    public let redact: Bool
    public let secrets: [String]

    public var id: String { name }
    public var isRemote: Bool { url != nil }

    /// What the list shows under the name: the command line or the URL.
    public var summary: String { url ?? (command ?? []).joined(separator: " ") }
}

/// One profile in `passess profile list --json`.
public struct Profile: Decodable, Equatable, Identifiable {
    public let name: String
    public let secrets: [String]
    public let required: [String]?
    public let allow: [String]?
    public let inherit: [String]?
    public let env: [String: String]?
    public let tty: Bool
    public let run: String // the command line that uses it

    public var id: String { name }
}

/// Output of `passess agent config --json`.
public struct AgentConfig: Decodable, Equatable {
    public var cacheTTL: String
    public var approvalTTL: String
    public var approvalTimeout: String

    public init(cacheTTL: String, approvalTTL: String, approvalTimeout: String) {
        self.cacheTTL = cacheTTL
        self.approvalTTL = approvalTTL
        self.approvalTimeout = approvalTimeout
    }

    enum CodingKeys: String, CodingKey {
        case cacheTTL = "cache_ttl"
        case approvalTTL = "approval_ttl"
        case approvalTimeout = "approval_timeout"
    }
}

/// What the Settings window asks of an MCP server: the form's fields, each
/// one a flag of `passess mcp add` or `set`.
public struct MCPForm: Equatable {
    public var name = ""
    public var remote = false
    public var command = "" // one argument per line
    public var url = ""
    public var env = "" // VAR=SECRET, one per line
    public var vars = "" // VAR=VALUE, one per line
    public var headers = "" // Name=Template, one per line
    public var inherit = "" // caller variables, one per line
    public var harnesses = "" // comma-separated; empty for all
    public var redact = true

    public init() {}

    public init(_ s: MCPServer) {
        name = s.name
        remote = s.isRemote
        command = (s.command ?? []).joined(separator: "\n")
        url = s.url ?? ""
        env = MCPForm.lines(s.env)
        vars = MCPForm.lines(s.vars)
        headers = MCPForm.lines(s.headers)
        inherit = (s.inherit ?? []).joined(separator: "\n")
        harnesses = s.harnesses.joined(separator: ",")
        redact = s.redact
    }

    static func lines(_ m: [String: String]?) -> String {
        (m ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
    }

    static func items(_ text: String) -> [String] {
        text.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
    }

    /// The flags after `mcp add NAME` or `mcp set NAME`. Every list is given,
    /// so what the form shows is what the server gets.
    public var arguments: [String] {
        var args: [String] = []
        if remote {
            args += ["--url", url.trimmingCharacters(in: .whitespaces)]
            args += MCPForm.items(headers).flatMap { ["--header", $0] }
            if MCPForm.items(headers).isEmpty { args += ["--header", ""] }
        } else {
            args += MCPForm.items(command).flatMap { ["--command", $0] }
            // An emptied list is sent as "", which empties it in the config.
            for (flag, list) in [("--env", env), ("--var", vars), ("--inherit", inherit)] {
                let items = MCPForm.items(list)
                args += items.isEmpty ? [flag, ""] : items.flatMap { [flag, $0] }
            }
        }
        let ids = harnesses.trimmingCharacters(in: .whitespaces)
        args += ["--harnesses", ids.isEmpty ? "all" : ids]
        args += ["--redact=\(redact)"]
        return args
    }
}

public extension Passess {
    /// `passess backend --json`.
    func backendSettings() throws -> BackendSettings {
        try decode(BackendSettings.self, from: run(["backend", "--json"]))
    }

    /// `passess backend NAME --flag value …`: plain settings, never a
    /// credential. An empty value goes back to the default.
    func setBackend(_ backend: String, _ settings: [(flag: String, value: String)]) throws {
        try change(["backend", backend] + settings.flatMap { ["--" + $0.flag, $0.value] })
    }

    /// `passess backend vault --token` or `backend bw --session`: the
    /// credential goes to the keychain on stdin. Only the copy inside the app
    /// should run this, as with the bws token (see bundled).
    func storeBackendCredential(_ backend: String, flag: String, value: String) throws {
        var data = Data(value.utf8)
        defer { data.resetBytes(in: 0..<data.count) }
        try change(["backend", backend, "--" + flag], stdin: data)
    }

    /// `passess mcp list --json`.
    func mcpServers() throws -> [MCPServer] {
        try decode([MCPServer].self, from: run(["mcp", "list", "--json"]))
    }

    /// `passess mcp add` when adding is true, else `mcp set`.
    func saveMCP(_ form: MCPForm, adding: Bool) throws {
        try change(["mcp", adding ? "add" : "set", form.name] + form.arguments)
    }

    func removeMCP(_ name: String) throws {
        try change(["mcp", "remove", name])
    }

    /// `passess profile list --json`.
    func profiles() throws -> [Profile] {
        try decode([Profile].self, from: run(["profile", "list", "--json"]))
    }

    /// `passess profile add` or `set`, with every list given.
    func saveProfile(name: String, secrets: [String], required: [String], allow: [String], inherit: [String],
                     env: [String], tty: Bool, adding: Bool) throws {
        var args = ["profile", adding ? "add" : "set", name, "--secrets", secrets.joined(separator: ","),
                    "--required", required.joined(separator: ","), "--allow", allow.joined(separator: ",")]
        args += inherit.isEmpty ? ["--inherit", ""] : inherit.flatMap { ["--inherit", $0] }
        args += env.isEmpty ? ["--env", ""] : env.flatMap { ["--env", $0] }
        args += ["--tty=\(tty)"]
        try change(args)
    }

    func removeProfile(_ name: String) throws {
        try change(["profile", "remove", name])
    }

    /// `passess agent config --json`.
    func agentConfig() throws -> AgentConfig {
        try decode(AgentConfig.self, from: run(["agent", "config", "--json"]))
    }

    func setAgentConfig(_ c: AgentConfig) throws {
        try change(["agent", "config", "--cache-ttl", c.cacheTTL, "--approval-ttl", c.approvalTTL,
                    "--approval-timeout", c.approvalTimeout])
    }

    /// `passess install ID --apply`, with --force to replace an MCP entry
    /// the user wrote, or --no-hooks to leave hooks out.
    func install(_ id: String, force: Bool, hooks: Bool) throws {
        try change(["install", id, "--apply"] + (force ? ["--force"] : []) + (hooks ? [] : ["--no-hooks"]))
    }

    /// `passess uninstall ID --apply`: takes passess out of a coding agent's
    /// config, after a backup.
    func uninstall(_ id: String) throws {
        try change(["uninstall", id, "--apply"])
    }
}
