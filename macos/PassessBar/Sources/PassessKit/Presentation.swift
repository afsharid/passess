import Foundation

/// Overall state shown by the menu bar icon.
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
}

public func health(_ doctor: Doctor?) -> Health {
    guard let doctor = doctor else { return .unknown }
    if doctor.problems.contains(where: { $0.severity == "error" }) { return .error }
    if !doctor.problems.isEmpty { return .warning }
    return .ok
}

/// What clicking a row does.
public enum RowAction: Equatable {
    case none
    case copy(String)
    case open(URL)
}

/// One menu line, independent of AppKit.
public struct Row: Equatable {
    public var title: String
    public var symbol: String?
    public var action: RowAction
    public var isHeader: Bool

    public init(_ title: String, symbol: String? = nil, action: RowAction = .none, isHeader: Bool = false) {
        self.title = title
        self.symbol = symbol
        self.action = action
        self.isHeader = isHeader
    }
}

/// Rows for the status section of the menu.
public func rows(doctor: Doctor?, failure: String?) -> [Row] {
    guard let d = doctor else {
        return [Row(failure ?? "Checking…", symbol: "hourglass")]
    }
    var out: [Row] = [Row("passess \(d.version)", isHeader: true)]

    if d.config.ok {
        let summary = "\(d.secrets) secret\(d.secrets == 1 ? "" : "s"), \(d.profiles) profile\(d.profiles == 1 ? "" : "s")"
        out.append(Row("Config: \(summary)", symbol: "doc.text",
                       action: .open(URL(fileURLWithPath: d.config.path))))
    } else {
        out.append(Row("Config: \(d.config.error ?? "not loaded")", symbol: "doc.text"))
    }
    if let p = d.project {
        out.append(Row("Project: \((p.path as NSString).deletingLastPathComponent)",
                       symbol: p.ok ? "folder" : "folder.badge.questionmark"))
    }
    for b in d.backends {
        let detail = b.detail.map { " — \($0)" } ?? ""
        out.append(Row("\(b.scheme):// \(b.ok ? "ready" : "not usable")\(detail)",
                       symbol: b.ok ? "checkmark.circle" : "xmark.circle"))
    }
    if let h = d.harness {
        out.append(Row("Running under \(h): output is redacted", symbol: "eye.slash"))
    }
    for p in d.problems {
        let symbol = p.severity == "error" ? "exclamationmark.octagon" : "exclamationmark.triangle"
        if let fix = p.fix {
            out.append(Row("\(p.message) — click to copy the fix", symbol: symbol, action: .copy(fix)))
        } else {
            out.append(Row(p.message, symbol: symbol))
        }
    }
    if d.problems.isEmpty {
        out.append(Row("Everything looks fine", symbol: "checkmark.seal"))
    }
    return out
}

/// Rows for the "Secrets" submenu after a check. Names and states only.
public func rows(check: Check) -> [Row] {
    if check.secrets.isEmpty {
        return [Row("No secrets defined yet")]
    }
    return check.secrets.map { item in
        let symbol: String
        switch item.state {
        case "ok": symbol = "checkmark.circle"
        case "unavailable": symbol = "bolt.horizontal.circle"
        default: symbol = "questionmark.circle"
        }
        let source = item.from ?? item.state
        return Row("\(item.name) — \(source)", symbol: symbol,
                   action: item.detail.map { .copy($0) } ?? .none)
    }
}

/// Rows for the agent's part of the menu. Names only.
public func rows(agent: AgentStatus?, approving: Bool) -> [Row] {
    guard let a = agent else {
        return [Row("Agent: status unknown", symbol: "questionmark.circle")]
    }
    guard a.running else {
        return [Row("Agent: not running — every command asks the vault", symbol: "moon.zzz")]
    }
    var out = [Row("Agent: running, pid \(a.pid ?? 0)", symbol: "bolt.shield")]
    let cached = a.cached ?? []
    if cached.isEmpty {
        out.append(Row("Holds no values" + (a.cacheTTL == "0s" ? " (cache off)" : ""), symbol: "tray"))
    } else {
        let until = a.expires.map { " until " + clock($0) } ?? ""
        out.append(Row("Holds \(cached.joined(separator: ", "))\(until)", symbol: "tray.full"))
    }
    out.append(Row(approving ? "Answering approval questions here" : "Not answering approval questions yet",
                   symbol: approving ? "hand.raised" : "hand.raised.slash"))
    for ap in a.approvals ?? [] {
        out.append(Row("\(ap.secret) for \(ap.program) — \(ap.anchor.name) (pid \(ap.anchor.pid)), until \(clock(ap.until))",
                       symbol: "checkmark.shield"))
    }
    return out
}

/// The title and body of the alert that puts a question to the user.
public func askText(_ ask: AgentAsk) -> (title: String, detail: String) {
    var who = "A caller passess cannot identify"
    if let anchor = ask.anchor {
        who = "\(anchor.name) (pid \(anchor.pid))"
    }
    let title = "\(who) wants \(ask.secrets.joined(separator: ", ")) for \(ask.program)"
    var detail = "In \(ask.dir)\n$ \(ask.argv.joined(separator: " "))"
    if let harness = ask.harness {
        detail += "\n\nIt says it runs under \(harness)."
    }
    if let until = ask.until {
        detail += "\n\nAn Allow lasts until \(clock(until)), for this program and this caller only."
    } else {
        detail += "\n\nAn Allow counts for this command only."
    }
    return (title, detail)
}

private func clock(_ date: Date) -> String {
    DateFormatter.localizedString(from: date, dateStyle: .none, timeStyle: .short)
}
