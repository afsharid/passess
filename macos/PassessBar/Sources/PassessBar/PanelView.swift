import PassessKit
import SwiftUI

// No @State in these views: the SDK's @State is a macro, and the Command Line
// Tools this app builds with carry no SwiftUI macro plugin.

/// The panel the menu bar icon opens, laid out like Control Center: how
/// things are, two tiles for what the user switches and checks, then what
/// needs them, the coding agents, the agent's approvals, the backends.
struct PanelView: View {
    @ObservedObject var model: BarModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Header(model: model)
                .padding(.horizontal, 14)
                .padding(.top, 14)
                .padding(.bottom, 12)
            if let d = model.doctor, d.config.ok {
                HStack(spacing: 8) {
                    AgentTile(model: model)
                    SecretsTile(model: model)
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
                content(d)
            } else if model.doctor != nil {
                GetStarted(item: Item(id: "start", symbol: "sparkles", tone: .neutral, title: t("Add a first secret in a terminal"),
                                      detail: "passess add NAME --ref <reference>", action: .copy("passess add NAME --ref <reference>")),
                           model: model)
            } else if model.failure == Passess.Failure.notFound.description {
                GetStarted(item: Item(id: "install", symbol: "shippingbox.fill", tone: .neutral, title: t("Install it in a terminal"),
                                      detail: Passess.installCommand, action: .copy(Passess.installCommand)),
                           model: model)
            }
            Divider()
            Footer(model: model)
                .padding(.horizontal, 14)
                .padding(.vertical, 10)
        }
        .frame(width: 340)
        .onAppear(perform: model.panelOpened)
    }

    @ViewBuilder
    private func content(_ d: Doctor) -> some View {
        let issues = problems(d)
        if !issues.isEmpty {
            Card(t("Needs attention")) {
                ForEach(issues) { item in
                    ProblemRow(item: item, model: model)
                    if item.id != issues.last?.id { Divider() }
                }
            }
        }
        if model.secretList?.agents != nil {
            SecretsEntry(model: model)
        }
        if let status = model.harnesses, !status.harnesses.isEmpty {
            let rows = codingAgents(status)
            let guarded = rows.filter { $0.tone == .ok }.count
            Card(t("Coding agents"), trailing: {
                Text(t("%ld of %ld guarded", guarded, rows.count))
                    .font(.system(size: 11))
                    .foregroundStyle(.tertiary)
            }) {
                ForEach(rows) { AgentRowView(row: $0, model: model) }
            }
        }
        if let card = agentCard(model.agent, approving: model.approving), card.running {
            Card(t("Approvals"), trailing: { ApproverState(approving: card.approving) }) {
                if card.approvals.isEmpty {
                    Text(card.approving ? t("None yet. Questions open a window of their own.") : t("Questions go unanswered until this app connects."))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    ForEach(card.approvals) { ItemRow(item: $0) }
                }
            }
        }
        if let check = model.check {
            let failing = checkItems(check).filter { $0.tone != .ok }
            if !failing.isEmpty {
                Card(t("Secrets that do not resolve")) {
                    ForEach(failing) { ItemRow(item: $0) }
                }
            }
        }
        Card(t("Backends")) {
            BackendsView(items: backends(d))
        }
    }
}

/// The way into the Secrets window, with what turned up in the vault lately
/// right here to connect.
struct SecretsEntry: View {
    @ObservedObject var model: BarModel

    var body: some View {
        let fresh = model.found.filter(\.isNew)
        Card(t("Secrets and connections")) {
            ForEach(fresh.prefix(2)) { row in
                FoundRowView(row: row, model: model)
                Divider()
            }
            Button(action: model.openSecrets) {
                HStack(spacing: 8) {
                    ToneIcon(symbol: "key.fill", tone: .neutral)
                    Text(summary)
                        .font(.system(size: 13))
                        .foregroundStyle(.primary)
                    Spacer(minLength: 4)
                    Text(t("Show"))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.tertiary)
                        .accessibilityHidden(true)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(t("See every secret and change who may use it"))
        }
    }

    private var summary: String {
        let n = model.secretList?.secrets.count ?? 0
        let waiting = model.found.count
        let secrets = t(n == 1 ? "%ld secret" : "%ld secrets", n)
        return waiting == 0 ? secrets : secrets + " · " + t("%ld not connected", waiting)
    }
}

// MARK: tokens and building blocks

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
        case .ok: return t("fine")
        case .warning: return t("needs attention")
        case .error: return t("problem")
        case .neutral: return ""
        }
    }
}

private let cardFill = Color.primary.opacity(0.05)

/// A titled group of rows on a quiet rounded background.
struct Card<Content: View, Trailing: View>: View {
    let title: String
    let trailing: Trailing
    let content: Content

    init(_ title: String, @ViewBuilder trailing: () -> Trailing, @ViewBuilder content: () -> Content) {
        self.title = title
        self.trailing = trailing()
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .firstTextBaseline) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .accessibilityAddTraits(.isHeader)
                Spacer(minLength: 8)
                trailing
            }
            .padding(.horizontal, 4)
            VStack(alignment: .leading, spacing: 8) {
                content
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardFill))
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 12)
    }
}

extension Card where Trailing == EmptyView {
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
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(h.health.tone.color.opacity(0.16))
                if model.doctor == nil && model.failure == nil {
                    ProgressView().controlSize(.small)
                } else {
                    Image(systemName: h.health.symbol + ".fill")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(h.health.tone.color)
                }
            }
            .frame(width: 38, height: 38)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(h.title)
                    .font(.system(size: 16, weight: .semibold))
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
                    .font(.system(size: 12, weight: .medium))
                    .foregroundStyle(.secondary)
            }
            .buttonStyle(.borderless)
            .help(t("Refresh"))
            .accessibilityLabel(t("Refresh"))
        }
    }
}

// MARK: tiles

/// A Control Center tile: a round symbol, lit when on, a title and a line.
struct Tile: View {
    let symbol: String
    let title: String
    let detail: String
    var lit = false
    var tint: Color = .primary
    var enabled = true
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 10) {
                ZStack {
                    Circle()
                        .fill(lit ? Color.accentColor : Color.primary.opacity(0.09))
                    Image(systemName: symbol)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(lit ? Color.white : tint)
                }
                .frame(width: 30, height: 30)
                VStack(alignment: .leading, spacing: 1) {
                    Text(title)
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(.primary)
                    Text(detail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 9)
            .frame(maxWidth: .infinity)
            .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.primary.opacity(0.06)))
            .contentShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.55)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
    }
}

struct AgentTile: View {
    @ObservedObject var model: BarModel

    var body: some View {
        if let card = agentCard(model.agent, approving: model.approving) {
            Tile(symbol: card.running ? "bolt.fill" : "bolt", title: t("Agent"),
                 detail: model.agentBusy ? "…" : card.running ? (card.holds.isEmpty ? t("On") : t("On · holds %ld", card.holds.count)) : t("Off"),
                 lit: card.running, enabled: !model.agentBusy) {
                model.agentCommand(card.running ? "stop" : "start")
            }
            .help(card.running ? t("%@. Click to stop: the agent forgets every value and approval.", card.status)
                : t("Start the agent: cached values, approvals"))
        } else {
            Tile(symbol: "bolt.slash", title: t("Agent"), detail: t("Update passess"), enabled: false) {}
                .help(t("The passess on your PATH has no agent yet: brew upgrade passess"))
        }
    }
}

struct SecretsTile: View {
    @ObservedObject var model: BarModel

    var body: some View {
        let summary = model.check.map(checkSummary)
        Tile(symbol: "key.fill", title: t("Secrets"),
             detail: model.checking ? t("Checking…") : summary?.text ?? t("Click to check"),
             tint: summary?.tone.color ?? .primary, enabled: !model.checking, action: model.runCheck)
            .help(t("Resolve every secret once and show which work. Names only; no value is shown."))
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
        .help(copied ? t("Copied") : t("Copy the command that fixes it"))
        .accessibilityLabel(copied ? t("Copied") : t("Copy the fix"))
    }
}

struct AgentRowView: View {
    let row: AgentRow
    @ObservedObject var model: BarModel

    var body: some View {
        HStack(spacing: 10) {
            Text(row.monogram)
                .font(.system(size: 10, weight: .bold, design: .rounded))
                .foregroundStyle(.secondary)
                .frame(width: 26, height: 26)
                .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(Color.primary.opacity(0.08)))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 1) {
                Text(row.title)
                    .font(.system(size: 13, weight: .medium))
                Text(row.detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }
            Spacer(minLength: 4)
            if let fix = row.fix {
                CopyButton(copied: model.copied == row.id) { model.copy(fix, from: row.id) }
            }
            Image(systemName: row.symbol)
                .font(.system(size: 13))
                .foregroundStyle(row.tone.color)
                .accessibilityHidden(true)
        }
        .accessibilityElement(children: .combine)
        .accessibilityValue(row.tone.spoken)
    }
}

struct ApproverState: View {
    let approving: Bool

    var body: some View {
        Label(approving ? t("answered here") : t("not connected"), systemImage: approving ? "hand.raised.fill" : "hand.raised.slash")
            .font(.system(size: 11))
            .foregroundStyle(approving ? Tone.ok.color : Tone.warning.color)
            .labelStyle(.titleAndIcon)
    }
}

/// Usable backends in one line; one that is not gets a line of its own with why.
struct BackendsView: View {
    let items: [Item]

    var body: some View {
        let ready = items.filter { $0.tone == .ok }
        let broken = items.filter { $0.tone != .ok }
        if !ready.isEmpty {
            HStack(spacing: 14) {
                ForEach(ready) { item in
                    HStack(spacing: 5) {
                        ToneIcon(symbol: item.symbol, tone: item.tone)
                        Text(item.title).font(.system(size: 13))
                    }
                    .help(item.detail ?? "")
                    .accessibilityElement(children: .combine)
                    .accessibilityValue(t("ready"))
                }
                Spacer(minLength: 0)
            }
        }
        ForEach(broken) { ItemRow(item: $0) }
        if items.isEmpty {
            Text(t("No secret uses a vault yet"))
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
        }
    }
}

struct GetStarted: View {
    let item: Item
    @ObservedObject var model: BarModel

    var body: some View {
        Card(t("Get started")) {
            ProblemRow(item: item, model: model)
        }
    }
}

// MARK: footer

struct Footer: View {
    @ObservedObject var model: BarModel

    var body: some View {
        HStack(spacing: 12) {
            Toggle(t("Open at Login"), isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                .toggleStyle(.checkbox)
                .font(.system(size: 12))
                .fixedSize()
            if let version = model.doctor?.version {
                Text(version)
                    .font(.system(size: 11).monospacedDigit())
                    .foregroundStyle(.tertiary)
                    .lineLimit(1)
                    .layoutPriority(-1) // the first to give way when the words are longer
                    .help("passess \(version)")
            }
            Spacer()
            if let config = model.doctor?.config, config.ok {
                Button(t("Config")) { model.open(URL(fileURLWithPath: config.path)) }
                    .buttonStyle(.borderless)
                    .font(.system(size: 12))
                    .help(config.path)
            }
            Button {
                model.open(URL(string: "https://github.com/afsharid/passess#readme")!)
            } label: {
                Image(systemName: "questionmark.circle")
            }
            .buttonStyle(.borderless)
            .help(t("passess on GitHub"))
            .accessibilityLabel(t("Help"))
            Button(t("Quit")) { NSApp.terminate(nil) }
                .buttonStyle(.borderless)
                .font(.system(size: 12))
                .keyboardShortcut("q")
        }
    }
}
