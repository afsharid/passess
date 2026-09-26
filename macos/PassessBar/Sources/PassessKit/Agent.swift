import Foundation

/// A process as the agent names it.
public struct AgentProc: Codable, Equatable {
    public let pid: Int
    public let name: String
}

/// Output of `passess agent status --json`. Mirrors agent.Info in
/// internal/agent/agent.go, under a "running" field. It names secrets, never
/// values; when no agent runs, only running is present.
public struct AgentStatus: Decodable, Equatable {
    public struct Approval: Decodable, Equatable {
        public let secret: String
        public let program: String
        public let anchor: AgentProc
        public let until: Date
    }

    public let running: Bool
    public let pid: Int?
    public let build: String?
    public let cacheTTL: String?
    public let cached: [String]?
    public let expires: Date?
    public let jobs: Int?
    public let served: Int?
    public let approvers: Int?
    public let pending: Int?
    public let approvals: [Approval]?

    enum CodingKeys: String, CodingKey {
        case running, pid, build, cached, expires, jobs, served, approvers, pending, approvals
        case cacheTTL = "cache_ttl"
    }
}

/// A question from the agent: may these secrets go to this command? Mirrors
/// agent.AskFor. It carries names and the command, never a value.
public struct AgentAsk: Decodable, Equatable {
    public let id: String
    public let secrets: [String]
    public let program: String
    public let path: String
    public let argv: [String]
    public let dir: String
    public let harness: String?
    public let anchor: AgentProc?
    public let until: Date?
}

/// One message from the agent. Mirrors agent.Frame, for the fields an
/// approver reads.
public struct AgentFrame: Decodable {
    public let status: Int?
    public let error: String?
    public let ask: AgentAsk?
    public let cancel: String?
}

/// The first line a client sends. Mirrors agent.Request, for the fields a
/// control or approver request needs.
public struct AgentRequest: Encodable {
    public let v: Int
    public let build: String
    public let kind: String

    public init(kind: String, build: String = "PassessBar") {
        self.v = 1
        self.build = build
        self.kind = kind
    }
}

/// An approver's reply. Mirrors agent.Frame{Answer: &agent.Answer{…}}.
public struct AgentAnswer: Encodable {
    public struct Body: Encodable {
        public let id: String
        public let allow: Bool
    }

    public let answer: Body

    public init(id: String, allow: Bool) {
        answer = Body(id: id, allow: allow)
    }
}

public enum AgentJSON {
    /// Go writes RFC 3339 times with up to nine fractional digits, which
    /// ISO8601DateFormatter does not read; they are shown to the minute, so
    /// the fraction is dropped.
    public static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        decoder.dateDecodingStrategy = .custom { d in
            let text = try d.singleValueContainer().decode(String.self)
            let whole = text.replacingOccurrences(of: #"\.[0-9]+"#, with: "", options: .regularExpression)
            guard let date = formatter.date(from: whole) else {
                throw DecodingError.dataCorrupted(.init(codingPath: d.codingPath, debugDescription: "not an RFC 3339 time: \(text)"))
            }
            return date
        }
        return decoder
    }()

    /// Where the agent listens. Mirrors agent.SocketPath: PASSESS_AGENT_SOCK,
    /// else $XDG_RUNTIME_DIR/passess/agent.sock, else under ~/.local/state.
    public static func socketPath(environment: [String: String] = ProcessInfo.processInfo.environment,
                                  home: String = NSHomeDirectory()) -> String {
        if let path = environment["PASSESS_AGENT_SOCK"], !path.isEmpty { return path }
        if let runtime = environment["XDG_RUNTIME_DIR"], !runtime.isEmpty { return runtime + "/passess/agent.sock" }
        return home + "/.local/state/passess/agent.sock"
    }
}
