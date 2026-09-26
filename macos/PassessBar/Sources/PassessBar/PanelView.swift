import PassessKit
import SwiftUI

/// The panel the menu bar icon opens: health first, then what needs the
/// user, then the parts that are fine.
struct PanelView: View {
    @ObservedObject var model: BarModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Header(model: model)
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 12)
            if let d = model.doctor, d.config.ok {
                content(d)
            } else if let d = model.doctor {
                NoConfig(doctor: d, model: model)
            } else if model.failure == Passess.Failure.notFound.description {
                Section("Get started") {
                    ProblemRow(item: Item(id: "install", symbol: "shippingbox.fill", tone: .neutral,
                                          title: "Install it in a terminal", detail: Passess.installCommand,
                                          action: .copy(Passess.installCommand)),
                               model: model)
                }
            }
            Divider()
            Footer(model: model)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
        }
        .frame(width: 340)
    }

    @ViewBuilder
    private func content(_ d: Doctor) -> some View {
        let issues = problems(d)
        if !issues.isEmpty {
            Section("Needs attention") {
                ForEach(issues) { item in
                    ProblemRow(item: item, model: model)
                    if item.id != issues.last?.id { Divider() }
                }
            }
        }
        Section("Secrets", trailing: { CheckButton(model: model) }) {
            SecretsSection(model: model)
        }
        Section("Backends") {
            ForEach(backends(d)) { ItemRow(item: $0) }
        }
        Section("Agent", trailing: { AgentSwitch(model: model) }) {
            AgentSection(model: model)
        }
    }
}

// MARK: building blocks

extension Tone {
    var color: Color {
        switch self {
        case .ok: return Color(nsColor: .systemGreen)
        case .warning: return Color(nsColor: .systemOrange)
        case .error: return Color(nsColor: .systemRed)
        case .neutral: return .secondary
        }
    }

    var spoken: String {
        switch self {
        case .ok: return "fine"
        case .warning: return "warning"
        case .error: return "problem"
        case .neutral: return ""
        }
    }
}

/// A titled group of rows, with an optional control on the title line.
struct Section<Content: View, Trailing: View>: View {
    let title: String
    let trailing: Trailing
    let content: Content

    init(_ title: String, @ViewBuilder trailing: () -> Trailing, @ViewBuilder content: () -> Content) {
        self.title = title
        self.trailing = trailing()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack(alignment: .center) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 8)
                trailing
            }
            .padding(.horizontal, 4)
            VStack(alignment: .leading, spacing: 7) {
                content
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.primary.opacity(0.045)))
        }
        .padding(.horizontal, 10)
        .padding(.bottom, 10)
    }
}

extension Section where Trailing == EmptyView {
    init(_ title: String, @ViewBuilder content: () -> Content) {
        self.init(title, trailing: { EmptyView() }, content: content)
    }
}

struct ToneIcon: View {
    let symbol: String
    let tone: Tone

    var body: some View {
        Image(systemName: symbol)
            .font(.system(size: 13))
            .foregroundStyle(tone.color)
            .frame(width: 16)
            .accessibilityHidden(true)
    }
}

struct ItemRow: View {
    let item: Item

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            ToneIcon(symbol: item.symbol, tone: item.tone)
            if item.tone == .ok || item.tone == .neutral {
                Text(item.title)
                    .font(.system(size: 13))
                if let detail = item.detail {
                    Text(detail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            } else {
                VStack(alignment: .leading, spacing: 1) {
                    Text(item.title)
                        .font(.system(size: 13))
                    if let detail = item.detail {
                        Text(detail)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(item.tone.spoken)
    }
}

// MARK: header

struct Header: View {
    @ObservedObject var model: BarModel

    var body: some View {
        let h = headline(doctor: model.doctor, failure: model.failure)
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                Circle()
                    .fill(h.health.tone.color.opacity(0.14))
                if model.doctor == nil && model.failure == nil {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: h.health.symbol + ".fill")
                        .font(.system(size: 15, weight: .medium))
                        .foregroundStyle(h.health.tone.color)
                }
            }
            .frame(width: 32, height: 32)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(h.title)
                    .font(.system(size: 15, weight: .semibold))
                if !h.detail.isEmpty {
                    Text(h.detail)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 8)
            Button(action: model.refresh) {
                Image(systemName: "arrow.clockwise")
            }
            .buttonStyle(.borderless)
            .help("Refresh")
            .accessibilityLabel("Refresh")
        }
    }
}

// MARK: sections

struct ProblemRow: View {
    let item: Item
    @ObservedObject var model: BarModel

    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            ToneIcon(symbol: item.symbol, tone: item.tone)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 4) {
                HStack(alignment: .firstTextBaseline) {
                    Text(item.title)
                        .font(.system(size: 13))
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 4)
                    if case let .copy(text) = item.action {
                        CopyButton(copied: model.copied == item.id) { model.copy(text, from: item.id) }
                    }
                }
                if let fix = item.detail {
                    Text(fix)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .lineLimit(4)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                }
            }
        }
    }
}

struct CopyButton: View {
    let copied: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .font(.system(size: 11))
                .foregroundStyle(copied ? Tone.ok.color : .secondary)
        }
        .buttonStyle(.borderless)
        .help(copied ? "Copied" : "Copy the fix")
        .accessibilityLabel(copied ? "Copied" : "Copy the fix")
    }
}

struct CheckButton: View {
    @ObservedObject var model: BarModel

    var body: some View {
        if model.checking {
            ProgressView().controlSize(.mini)
        } else {
            Button(model.check == nil ? "Check now" : "Check again", action: model.runCheck)
                .buttonStyle(.borderless)
                .font(.system(size: 11))
                .help("Resolve every secret once and show which work. No value is shown.")
        }
    }
}

// No @State in these views: the SDK's @State is a macro, and the Command Line
// Tools this app builds with carry no SwiftUI macro plugin.
struct SecretsSection: View {
    @ObservedObject var model: BarModel

    var body: some View {
        if let check = model.check {
            let summary = checkSummary(check)
            let items = checkItems(check)
            DisclosureGroup {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(items) { ItemRow(item: $0) }
                }
                .padding(.top, 4)
            } label: {
                HStack(spacing: 8) {
                    ToneIcon(symbol: summary.tone == .ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
                             tone: summary.tone)
                    Text(summary.text).font(.system(size: 13))
                    if let at = model.checkedAt {
                        Text(at, style: .time)
                            .font(.system(size: 11))
                            .foregroundStyle(.tertiary)
                    }
                }
            }
        } else {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                ToneIcon(symbol: "key.fill", tone: .neutral)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Not checked yet").font(.system(size: 13))
                    Text("A check resolves each secret once. Names only; no value is shown.")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }
}

struct AgentSwitch: View {
    @ObservedObject var model: BarModel

    var body: some View {
        if model.agent != nil {
            Toggle("", isOn: Binding(
                get: { model.agent?.running == true },
                set: { model.agentCommand($0 ? "start" : "stop") }
            ))
            .toggleStyle(.switch)
            .controlSize(.mini)
            .labelsHidden()
            .disabled(model.agentBusy)
            .help(model.agent?.running == true ? "Stop the agent: it forgets every value and approval" : "Start the agent")
            .accessibilityLabel("Agent")
        }
    }
}

struct AgentSection: View {
    @ObservedObject var model: BarModel

    var body: some View {
        if let card = agentCard(model.agent, approving: model.approving) {
            VStack(alignment: .leading, spacing: 5) {
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    ToneIcon(symbol: card.running ? (card.holds.isEmpty ? "tray" : "tray.full.fill") : "moon.zzz.fill",
                             tone: card.running ? .ok : .neutral)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(card.status).font(.system(size: 13))
                        if !card.holds.isEmpty {
                            Text(card.holds.joined(separator: ", "))
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                        }
                    }
                    Spacer(minLength: 4)
                    if card.running {
                        Button {
                            model.agentCommand("lock")
                        } label: {
                            Label("Lock", systemImage: "lock.fill").font(.system(size: 11))
                        }
                        .buttonStyle(.borderless)
                        .disabled(model.agentBusy)
                        .help("Forget every cached value and approval now")
                    }
                }
                if card.running {
                    HStack(spacing: 8) {
                        ToneIcon(symbol: card.approving ? "hand.raised.fill" : "hand.raised.slash", tone: card.approving ? .ok : .neutral)
                        Text(card.approving ? "Approval questions appear here" : "Not connected for approval questions")
                            .font(.system(size: 12))
                            .foregroundStyle(card.approving ? .primary : .secondary)
                    }
                    ForEach(card.approvals) { ItemRow(item: $0) }
                }
            }
        } else {
            HStack(spacing: 8) {
                ToneIcon(symbol: "questionmark.circle", tone: .neutral)
                Text("This passess has no agent yet")
                    .font(.system(size: 12))
                    .foregroundStyle(.secondary)
            }
        }
    }
}

struct NoConfig: View {
    let doctor: Doctor
    @ObservedObject var model: BarModel

    var body: some View {
        let start = "passess add NAME --ref <reference>"
        Section("Get started") {
            ProblemRow(item: Item(id: "start", symbol: "sparkles", tone: .neutral,
                                  title: "Add a first secret in a terminal", detail: start, action: .copy(start)),
                       model: model)
        }
    }
}

// MARK: footer

struct Footer: View {
    @ObservedObject var model: BarModel

    var body: some View {
        HStack(spacing: 12) {
            Toggle("Open at Login", isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                .toggleStyle(.checkbox)
                .font(.system(size: 12))
            if let version = model.doctor?.version {
                Text(version)
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .help("passess \(version)")
            }
            Spacer()
            if let config = model.doctor?.config, config.ok {
                let path = config.path
                Button("Config") { model.open(URL(fileURLWithPath: path)) }
                    .buttonStyle(.borderless)
                    .font(.system(size: 12))
                    .help(path)
            }
            Button {
                model.open(URL(string: "https://github.com/afsharid/passess#readme")!)
            } label: {
                Image(systemName: "questionmark.circle")
            }
            .buttonStyle(.borderless)
            .help("passess on GitHub")
            .accessibilityLabel("Help")
            Button("Quit") { NSApp.terminate(nil) }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .keyboardShortcut("q")
        }
    }
}
