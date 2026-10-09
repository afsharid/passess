import Foundation

// What the panel shows, independent of SwiftUI so it can be checked headless.
// Every state carries a symbol as well as a tone: none is told by color alone.

/// How good or bad something is.
public enum Tone: Equatable {
    case ok, warning, error, neutral
}

/// Overall state, shown by the menu bar icon and the panel's header.
public enum Health: Equatable {
    case ok, warning, error, unknown

    /// SF Symbol for the status item.
    public var symbol: String {
        switch self {
        case .ok: return "lock.shield"
        case .warning: return "exclamationmark.shield"
        case .error: return "xmark.shield"
        case .unknown: return "shield.slash"
        }
    }

    public var tone: Tone {
        switch self {
        case .ok: return .ok
        case .warning: return .warning
        case .error: return .error
        case .unknown: return .neutral
        }
    }
}

public func health(_ doctor: Doctor?) -> Health {
    guard let doctor = doctor else { return .unknown }
    if doctor.problems.contains(where: { $0.severity == "error" }) { return .error }
    if !doctor.problems.isEmpty { return .warning }
    return .ok
}

/// What clicking an item does.
public enum ItemAction: Equatable {
    case none
    case copy(String)
    case open(URL)
}

/// One line of the panel.
public struct Item: Equatable, Identifiable {
    public let id: String
    public let symbol: String
    public let tone: Tone
    public let title: String
    public let detail: String?
    public let action: ItemAction

    public init(id: String, symbol: String, tone: Tone, title: String, detail: String? = nil, action: ItemAction = .none) {
        self.id = id
        self.symbol = symbol
        self.tone = tone
        self.title = title
        self.detail = detail
        self.action = action
    }
}

/// The panel's first line and what it says under it.
public struct Headline: Equatable {
    public let title: String
    public let detail: String
    public let health: Health
}

public func headline(doctor: Doctor?, failure: String?) -> Headline {
    guard let d = doctor else {
        if let failure = failure {
            return Headline(title: t("passess cannot run"), detail: failure, health: .error)
        }
        return Headline(title: t("Checking…"), detail: "", health: .unknown)
    }
    let summary = secretsSummary(d)
    guard d.config.ok else {
        return Headline(title: t("No config yet"), detail: d.config.error ?? t("passess has no config to read"), health: .error)
    }
    let n = d.problems.count
    switch health(d) {
    case .error: return Headline(title: t(n == 1 ? "%ld problem" : "%ld problems", n), detail: summary, health: .error)
    case .warning: return Headline(title: t(n == 1 ? "%ld warning" : "%ld warnings", n), detail: summary, health: .warning)
    default: return Headline(title: t("All clear"), detail: summary, health: .ok)
    }
}

/// "10 secrets · 2 profiles".
public func secretsSummary(_ d: Doctor) -> String {
    t(d.secrets == 1 ? "%ld secret" : "%ld secrets", d.secrets) + " · " + t(d.profiles == 1 ? "%ld profile" : "%ld profiles", d.profiles)
}

public func problems(_ d: Doctor) -> [Item] {
    d.problems.enumerated().map { i, p in
        let error = p.severity == "error"
        return Item(id: "problem-\(i)", symbol: error ? "xmark.octagon.fill" : "exclamationmark.triangle.fill",
                    tone: error ? .error : .warning, title: p.message, detail: p.fix,
                    action: p.fix.map { .copy($0) } ?? .none)
    }
}

public func backends(_ d: Doctor) -> [Item] {
    d.backends.map { b in
        Item(id: "backend-\(b.scheme)", symbol: b.ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
             tone: b.ok ? .ok : .warning, title: b.scheme, detail: b.ok ? (b.detail ?? t("Ready")) : (b.detail ?? t("Not usable")))
    }
}

/// The result of "Check secrets": which resolve. Names and sources only.
public func checkItems(_ c: Check) -> [Item] {
    c.secrets.map { s in
        let symbol: String, tone: Tone
        switch s.state {
        case "ok": (symbol, tone) = ("checkmark.circle.fill", .ok)
        case "unavailable": (symbol, tone) = ("bolt.horizontal.circle.fill", .warning)
        default: (symbol, tone) = ("questionmark.circle.fill", .error)
        }
        return Item(id: "secret-\(s.name)", symbol: symbol, tone: tone, title: s.name,
                    detail: s.from ?? s.state, action: s.detail.map { .copy($0) } ?? .none)
    }
}

public func checkSummary(_ c: Check) -> (text: String, tone: Tone) {
    let ok = c.secrets.filter { $0.state == "ok" }.count
    if c.secrets.isEmpty { return (t("No secrets defined yet"), .neutral) }
    return (t("%ld of %ld resolve", ok, c.secrets.count), ok == c.secrets.count ? .ok : .warning)
}

/// The agent's part of the panel.
public struct AgentCard: Equatable {
    public let running: Bool
    public let status: String // one line under "Agent"
    public let holds: [String] // secret names
    public let approving: Bool
    public let approvals: [Item]
    /// Another build than the passess on the PATH: start replaces it.
    public var outdated = false
}

/// nil when the CLI could not say.
public func agentCard(_ a: AgentStatus?, approving: Bool, now: Date = Date()) -> AgentCard? {
    guard let a = a else { return nil }
    guard a.running else {
        return AgentCard(running: false, status: t("Off: every command asks the vault"), holds: [], approving: false, approvals: [])
    }
    let holds = a.cached ?? []
    let status: String
    if a.outdated == true {
        status = t("Another passess build than yours, which it refuses: start it again")
    } else if a.cacheTTL == "0s" {
        status = t("Cache off")
    } else if holds.isEmpty {
        status = t("Holds no values")
    } else if let expires = a.expires {
        status = t(holds.count == 1 ? "Holds %ld value until %@" : "Holds %ld values until %@", holds.count, clock(expires))
    } else {
        status = t(holds.count == 1 ? "Holds %ld value" : "Holds %ld values", holds.count)
    }
    let approvals = (a.approvals ?? []).map { ap in
        Item(id: "approval-\(ap.secret)-\(ap.program)-\(ap.anchor.pid)", symbol: "checkmark.shield.fill", tone: .ok,
             title: "\(ap.secret) → \(ap.program)", detail: t("%@ · until %@", ap.anchor.name, clock(ap.until)))
    }
    return AgentCard(running: true, status: status, holds: holds, approving: approving, approvals: approvals,
                     outdated: a.outdated ?? false)
}

/// What the approval panel says about one question.
public struct AskCard: Equatable {
    public let title: String // "claude wants GITHUB_TOKEN"
    public let program: String // "for gh"
    public let command: String // "gh api user"
    public let directory: String // "~/Projects/app"
    public let caller: String // "pid 46551 · says it is claude-code"
    public let footnote: String // how long an Allow lasts
}

public func askCard(_ ask: AgentAsk, home: String = NSHomeDirectory()) -> AskCard {
    let who = ask.anchor?.name ?? t("An unidentified caller")
    var caller = ask.anchor.map { t("%@, pid %ld", $0.name, $0.pid) } ?? t("no process passess can remember the answer for")
    if let harness = ask.harness { caller += t(" · reports %@", harness) }
    let footnote: String
    if let until = ask.until {
        footnote = t("Allowing lets %@ have it whenever this %@ asks, until %@. The value never reaches this app.",
                     ask.program, who, clock(until))
    } else {
        footnote = t("Allowing counts for this one command. The value never reaches this app.")
    }
    return AskCard(title: t("%@ wants %@", who, ask.secrets.joined(separator: ", ")), program: t("for %@", ask.program),
                   command: ask.argv.joined(separator: " "), directory: abbreviate(ask.dir, home: home),
                   caller: caller, footnote: footnote)
}

/// Lines for `PassessBar --print-report`.
public func reportLines(doctor: Doctor?, failure: String?) -> [String] {
    let h = headline(doctor: doctor, failure: failure)
    var lines = ["health: \(h.health)", "\(h.title)\(h.detail.isEmpty ? "" : " — \(h.detail)")"]
    if let d = doctor {
        lines += backends(d).map { "  \($0.title): \($0.detail ?? "")" }
        lines += problems(d).map { "  ! \($0.title)" }
    }
    return lines
}

func abbreviate(_ path: String, home: String) -> String {
    if path == home { return "~" }
    if path.hasPrefix(home + "/") { return "~" + path.dropFirst(home.count) }
    return path
}

private func clock(_ date: Date) -> String {
    DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .short)
}
