import Foundation

/// Output of `passess scan --json`. Mirrors scanOutput in
/// internal/cli/scan.go: where a credential sits in clear, never the value.
public struct ScanReport: Decodable, Equatable {
    public struct Finding: Decodable, Equatable, Identifiable {
        public let path: String
        public let line: Int
        public let category: String // config | dotfile | env | transcript | path
        public let kind: String // known (a value passess manages) | rule (a secret-shaped string)
        public let secret: String?
        public let rule: String?
        public let fingerprint: String

        public var id: String { "\(path):\(line):\(fingerprint)" }

        /// What was found: the secret's name, or the kind of string.
        public var what: String { secret ?? rule ?? kind }
    }

    public let files: Int
    public let findings: [Finding]
    public let errors: [String]
    public let notes: [String]?
    public let unresolved: [String]

    /// The findings grouped by file, in the order the scan reported them.
    public var byFile: [(path: String, category: String, findings: [Finding])] {
        var order: [String] = []
        var groups: [String: [Finding]] = [:]
        for f in findings {
            if groups[f.path] == nil { order.append(f.path) }
            groups[f.path, default: []].append(f)
        }
        return order.map { ($0, groups[$0]![0].category, groups[$0]!) }
    }

    /// Whether a transcript holds a value passess manages: what scrubbing fixes.
    public var transcriptsHoldValues: Bool {
        findings.contains { $0.category == "transcript" && $0.kind == "known" }
    }
}

/// One line of `passess activity --json`. Mirrors auditEntry in
/// internal/cli/agentlog.go: names and programs, never values.
public struct ActivityEntry: Decodable, Equatable, Identifiable {
    public let time: Date
    public let kind: String // exec, ask, approval
    public let anchor: String?
    public let harness: String?
    public let secrets: [String]
    public let program: String?
    public let dir: String?
    public let outcome: String
    public let status: Int?

    public var id: String { "\(time.timeIntervalSince1970)-\(kind)-\(secrets.joined(separator: ","))-\(outcome)" }

    /// Whether this was a refusal, a denial or a question nobody answered.
    public var refused: Bool { ["refused", "denied", "timeout", "no-approver", "failed"].contains(outcome) }
}

public extension Passess {
    /// `passess scan --json --dir DIR`: harness configs and dotfiles in the
    /// home, .env files under dir, and, with transcripts, the harnesses'
    /// session logs. It exits 1 when it finds something; that is a report too.
    func scan(dir: String, transcripts: Bool) throws -> ScanReport {
        let args = ["scan", "--json", "--dir", dir] + (transcripts ? ["--transcripts"] : [])
        return try decode(ScanReport.self, from: run(args, timeout: 300))
    }

    /// `passess scan --scrub --apply`: the configured values in the
    /// transcripts the scan finds are replaced, after a backup.
    func scrubTranscripts() throws {
        let r = try execute(["scan", "--scrub", "--apply", "--json"], timeout: 300)
        guard r.status == 0 || r.status == 1 else { throw Failure.refused(said(r.stderr, status: r.status)) }
    }

    /// `passess migrate env FILE`: what moving the file's values to the
    /// keychain would do, as passess says it; with apply, it does it.
    func migrateEnv(_ file: String, apply: Bool) throws -> String {
        let r = try execute(["migrate", "env", file] + (apply ? ["--apply", "--yes"] : []), timeout: 120)
        guard r.status == 0 else { throw Failure.refused(said(r.stderr, status: r.status)) }
        return String(decoding: r.stdout, as: UTF8.self)
    }

    /// `passess activity --json`, newest first.
    func activity(limit: Int = 300) throws -> [ActivityEntry] {
        try AgentJSON.decoder.decode([ActivityEntry].self, from: run(["activity", "--json", "--limit", String(limit)]))
    }

    /// `passess agent revoke`: takes back one Allow, without locking the agent.
    func revoke(secret: String, program: String, pid: Int) throws {
        try change(["agent", "revoke", secret, "--program", program, "--pid", String(pid)])
    }
}
