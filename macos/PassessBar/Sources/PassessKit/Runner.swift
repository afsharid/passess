import Foundation

/// Runs the passess CLI and decodes its JSON. The app only ever asks for
/// reports; no secret value crosses into this process.
public struct Passess {
    public let executable: URL

    public init(executable: URL) {
        self.executable = executable
    }

    /// How to install the CLI, for the panel to offer.
    public static let installCommand = "brew install afsharid/tap/passess"

    public enum Failure: Error, CustomStringConvertible {
        case notFound
        case timedOut
        case unreadable(String)
        /// passess refused a change and said why.
        case refused(String)

        public var description: String {
            switch self {
            case .notFound: return "The passess command line tool is not installed."
            case .timedOut: return "passess did not answer in time"
            case let .unreadable(why): return "could not read passess output: \(why)"
            case let .refused(why): return why
            }
        }
    }

    /// Directories searched for the CLI and handed to it as PATH. Apps started
    /// from Finder get a minimal PATH, which would hide bws or op from passess.
    public static func searchPath(home: String = NSHomeDirectory()) -> [String] {
        ["\(home)/.local/bin", "\(home)/go/bin", "/opt/homebrew/bin", "/usr/local/bin",
         "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
    }

    /// Prefers the copy bundled inside the app, then the search path.
    public static func locate(bundle: Bundle = .main, fileManager: FileManager = .default) -> Passess? {
        if let bundled = bundle.url(forResource: "passess", withExtension: nil),
           fileManager.isExecutableFile(atPath: bundled.path) {
            return Passess(executable: bundled)
        }
        for dir in searchPath() {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("passess")
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return Passess(executable: candidate)
            }
        }
        return nil
    }

    /// Runs passess and returns its stdout. doctor and check exit 1 when
    /// something needs attention and still print a full report, so the exit
    /// status is not an error here.
    public func run(_ arguments: [String], timeout: TimeInterval = 30) throws -> Data {
        try execute(arguments, timeout: timeout).stdout
    }

    /// Runs passess and keeps everything it said, for the commands that change
    /// the config: their refusals are on stderr.
    func execute(_ arguments: [String], timeout: TimeInterval) throws -> (status: Int32, stdout: Data, stderr: Data) {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = [
            "HOME": NSHomeDirectory(),
            "USER": NSUserName(),
            "PATH": Passess.searchPath().joined(separator: ":"),
            "LANG": "en_US.UTF-8",
        ]
        let stdout = Pipe(), stderr = Pipe()
        process.standardOutput = stdout
        process.standardError = stderr
        process.standardInput = FileHandle.nullDevice

        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        try process.run()
        var out = Data(), err = Data()
        let reads = DispatchGroup()
        for (pipe, assign) in [(stdout, { (d: Data) in out = d }), (stderr, { (d: Data) in err = d })] {
            reads.enter()
            DispatchQueue.global().async {
                assign(pipe.fileHandleForReading.readDataToEndOfFile())
                reads.leave()
            }
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            throw Failure.timedOut
        }
        reads.wait()
        return (process.terminationStatus, out, err)
    }

    /// Runs a command that changes the config; a refusal throws what passess said.
    private func change(_ arguments: [String]) throws {
        let r = try execute(arguments, timeout: 30)
        guard r.status == 0 else {
            let said = String(decoding: r.stderr, as: UTF8.self)
                .split(separator: "\n").first.map { String($0) } ?? "passess exited \(r.status)"
            throw Failure.refused(said.hasPrefix("passess: ") ? String(said.dropFirst(9)) : said)
        }
    }

    /// `passess list --json`: every secret, and who may use it.
    public func list() throws -> SecretList {
        try decode(SecretList.self, from: run(["list", "--json"]))
    }

    /// `passess discover --json`: what the vault holds that passess does not use.
    public func discover() throws -> Discovery {
        try decode(Discovery.self, from: run(["discover", "--json"], timeout: 90))
    }

    /// `passess add`: a vault secret becomes one agents can use.
    public func add(name: String, ref: String, clients: String, approve: Bool) throws {
        try change(["add", name, "--ref", ref, "--clients", clients] + (approve ? ["--approve"] : []))
    }

    /// `passess set`: who may use a secret, and whether each use asks.
    public func set(name: String, clients: String, approve: Bool) throws {
        try change(["set", name, "--clients", clients, "--approve", approve ? "true" : "false"])
    }

    /// `passess install ID --apply`: sets up a coding agent or an app (hooks,
    /// instructions, MCP servers, an app's plugin), after a backup.
    public func install(_ id: String) throws {
        try change(["install", id, "--apply"])
    }

    /// `passess remove`: passess forgets the secret; the vault keeps it.
    public func remove(name: String) throws {
        try change(["remove", name])
    }

    /// The CLI that starts the agent: the one on the search path, which
    /// harnesses run too, so the agent is the same build as its clients. The
    /// bundled copy only when there is none.
    public static func locateForAgent(bundle: Bundle = .main, fileManager: FileManager = .default) -> Passess? {
        for dir in searchPath() {
            let candidate = URL(fileURLWithPath: dir).appendingPathComponent("passess")
            if fileManager.isExecutableFile(atPath: candidate.path) {
                return Passess(executable: candidate)
            }
        }
        return locate(bundle: bundle, fileManager: fileManager)
    }

    /// `passess status --json`: how each coding agent is set up. It reads
    /// config files only (0.01 s).
    public func harnesses() throws -> HarnessStatus {
        let data = try run(["status", "--json"])
        do {
            return try JSONDecoder().decode(HarnessStatus.self, from: data)
        } catch {
            throw Failure.unreadable(String(describing: error))
        }
    }

    public func agentStatus() throws -> AgentStatus {
        let data = try run(["agent", "status", "--json"])
        do {
            return try AgentJSON.decoder.decode(AgentStatus.self, from: data)
        } catch {
            throw Failure.unreadable(String(describing: error))
        }
    }

    /// Runs `passess agent start`, `lock` or `stop`.
    public func agent(_ subcommand: String) throws {
        _ = try run(["agent", subcommand], timeout: 15)
    }

    public func doctor() throws -> Doctor {
        try decode(Doctor.self, from: run(["doctor", "--json"]))
    }

    public func check() throws -> Check {
        try decode(Check.self, from: run(["check", "--json"], timeout: 120))
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        do {
            return try JSONDecoder().decode(type, from: data)
        } catch {
            throw Failure.unreadable(String(describing: error))
        }
    }
}
