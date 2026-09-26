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

        public var description: String {
            switch self {
            case .notFound: return "The passess command line tool is not installed."
            case .timedOut: return "passess did not answer in time"
            case let .unreadable(why): return "could not read passess output: \(why)"
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
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = [
            "HOME": NSHomeDirectory(),
            "USER": NSUserName(),
            "PATH": Passess.searchPath().joined(separator: ":"),
            "LANG": "en_US.UTF-8",
        ]
        let stdout = Pipe()
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice

        let done = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in done.signal() }
        try process.run()
        var data = Data()
        let reader = DispatchQueue(label: "passess.stdout")
        let readDone = DispatchSemaphore(value: 0)
        reader.async {
            data = stdout.fileHandleForReading.readDataToEndOfFile()
            readDone.signal()
        }
        if done.wait(timeout: .now() + timeout) == .timedOut {
            process.terminate()
            throw Failure.timedOut
        }
        readDone.wait()
        return data
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
