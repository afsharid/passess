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
