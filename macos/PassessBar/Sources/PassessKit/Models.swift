import Foundation

/// Output of `passess doctor --json`. Mirrors doctorOutput in internal/cli/doctor.go.
public struct Doctor: Decodable, Equatable {
    public struct FileStatus: Decodable, Equatable {
        public let path: String
        public let ok: Bool
        public let error: String?
    }

    public struct Backend: Decodable, Equatable {
        public let scheme: String
        public let ok: Bool
        public let detail: String?
    }

    public struct Problem: Decodable, Equatable {
        public let severity: String
        public let message: String
        public let fix: String?
    }

    public let version: String
    public let ok: Bool
    public let config: FileStatus
    public let project: FileStatus?
    public let secrets: Int
    public let profiles: Int
    public let backends: [Backend]
    public let harness: String?
    public let problems: [Problem]
}

/// Output of `passess check --json`. Mirrors checkOutput in internal/cli/check.go.
/// It names secrets and where they resolved from; it never carries a value.
public struct Check: Decodable, Equatable {
    public struct Item: Decodable, Equatable {
        public let name: String
        public let state: String
        public let from: String?
        public let detail: String?
    }

    public let config: String
    public let ok: Bool
    public let secrets: [Item]
}
