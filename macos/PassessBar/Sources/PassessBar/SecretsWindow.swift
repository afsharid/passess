import AppKit
import PassessKit
import SwiftUI

/// Every secret passess knows and who may use it, and the vault's secrets
/// that are not connected yet. A row opens the Connect window; nothing here
/// changes anything by itself, and no value is ever shown.
struct SecretsView: View {
    @ObservedObject var model: BarModel

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
                .padding(.horizontal, 20)
                .padding(.top, 22)
                .padding(.bottom, 14)
            filter
                .padding(.horizontal, 20)
                .padding(.bottom, 12)
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let problem = vaultProblem {
                        Card(t("In your vault, not connected")) {
                            Label(problem, systemImage: "exclamationmark.triangle.fill")
                                .font(.system(size: 12))
                                .foregroundStyle(Tone.warning.color)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } else if !found.isEmpty {
                        Card(t("In your vault, not connected"), highlighted: found.contains(where: \.isNew)) {
                            ForEach(found) { row in
                                FoundRowView(row: row, model: model)
                                if row.id != found.last?.id { Divider() }
                            }
                        }
                    }
                    if let list = model.secretList {
                        let rows = secretRows(list, check: model.check).filter { matches($0.id, filter: model.secretsFilter) }
                        Card(t("Connected")) {
                            if rows.isEmpty {
                                Text(t("No secret matches"))
                                    .font(.system(size: 12))
                                    .foregroundStyle(.secondary)
                                    .frame(maxWidth: .infinity, alignment: .center)
                                    .padding(.vertical, 8)
                            }
                            ForEach(rows) { row in
                                if let secret = list.secrets.first(where: { $0.name == row.id }) {
                                    SecretRowView(row: row, secret: secret, agents: list.agents ?? [], model: model)
                                    if row.id != rows.last?.id { Divider() }
                                }
                            }
                        }
                    }
                    Label {
                        Text(t("Values are never shown. Every change asks for Touch ID or your password."))
                    } icon: {
                        Image(systemName: "lock.shield.fill").foregroundStyle(Brand.text)
                    }
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 18)
                    .padding(.bottom, 18)
                }
            }
        }
        .frame(minWidth: 460, idealWidth: 500, minHeight: 360, idealHeight: 620)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Brand.tint)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 14) {
            Badge(symbol: "key.fill", size: 46)
            VStack(alignment: .leading, spacing: 5) {
                Text(t("Secrets"))
                    .font(.system(size: 22, weight: .bold))
                HStack(spacing: 6) {
                    let n = model.secretList?.secrets.count ?? 0
                    Pill(text: t(n == 1 ? "%ld secret" : "%ld secrets", n), symbol: "key.fill", tint: .secondary)
                    if !model.found.isEmpty {
                        Pill(text: t("%ld not connected", model.found.count), symbol: "plus", tint: Brand.text)
                    }
                    if let agents = model.secretList?.agents, !agents.isEmpty {
                        Pill(text: t(agents.count == 1 ? "%ld agent" : "%ld agents", agents.count), symbol: "person.2.fill", tint: .secondary)
                    }
                }
            }
            Spacer()
            Button(action: { model.refresh(); model.discover(maxAge: 0) }) {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 13, weight: .medium))
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.secondary)
            .help(t("Refresh"))
            .accessibilityLabel(t("Refresh"))
        }
    }

    private var filter: some View {
        HStack(spacing: 7) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(.secondary)
            TextField(t("Filter by name"), text: Binding(get: { model.secretsFilter }, set: { model.secretsFilter = $0 }))
                .textFieldStyle(.plain)
                .font(.system(size: 13))
            if !model.secretsFilter.isEmpty {
                Button { model.secretsFilter = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.tertiary)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(t("Clear"))
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .surface()
    }

    private var found: [FoundRow] {
        model.found.filter { matches($0.title, filter: model.secretsFilter) || matches($0.found.name, filter: model.secretsFilter) }
    }

    /// Why the vault could not be listed, when it could not.
    private var vaultProblem: String? {
        guard let d = model.discovery, !d.backends.contains(where: \.ok),
              let why = d.backends.first?.error else { return nil }
        return t("Your vault could not be read: %@", why)
    }
}

struct FoundRowView: View {
    let row: FoundRow
    @ObservedObject var model: BarModel

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "key.horizontal.fill")
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Brand.text)
                .frame(width: 28, height: 28)
                .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Brand.tint.opacity(0.13)))
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(row.title)
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .lineLimit(1)
                    .truncationMode(.middle)
                HStack(spacing: 6) {
                    if row.isNew { Pill(text: t("New"), symbol: "sparkle") }
                    Text(row.detail)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
            }
            Spacer(minLength: 6)
            Button { model.openConnect(row.found) } label: {
                Label(t("Connect"), systemImage: "link")
            }
            .buttonStyle(PrimaryButtonStyle(compact: true))
        }
        .accessibilityElement(children: .combine)
    }
}

struct SecretRowView: View {
    let row: SecretRow
    let secret: SecretList.Secret
    let agents: [SecretList.Agent]
    @ObservedObject var model: BarModel

    var body: some View {
        Button { model.openEdit(secret) } label: {
            HStack(spacing: 10) {
                Image(systemName: "key.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(secret.backends.contains("keychain") ? Color.secondary : Brand.text)
                    .frame(width: 28, height: 28)
                    .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.06)))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 4) {
                    Text(row.id)
                        .font(.system(size: 13, weight: .semibold, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    HStack(spacing: 6) {
                        if let ids = row.clients, !ids.isEmpty {
                            AvatarStack(ids: ids, agents: agents, size: 16)
                        } else {
                            Image(systemName: row.clients == nil ? "person.2.fill" : "nosign")
                                .font(.system(size: 10))
                                .foregroundStyle(.secondary)
                                .accessibilityHidden(true)
                        }
                        Text(row.agents)
                            .font(.system(size: 11))
                            .foregroundStyle(.secondary)
                            .lineLimit(1)
                    }
                }
                Spacer(minLength: 6)
                if row.asks {
                    Pill(text: t("Asks first"), symbol: "touchid", tint: .secondary)
                }
                switch row.tone {
                case .ok: Pill(text: t("Works"), symbol: "checkmark", tint: Tone.ok.color)
                case .error, .warning: Pill(text: t("Does not resolve"), symbol: "exclamationmark", tint: Tone.error.color)
                case .neutral: EmptyView()
                }
                Image(systemName: "chevron.right")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.tertiary)
                    .accessibilityHidden(true)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(t("Change who may use %@", row.id))
        .accessibilityElement(children: .combine)
        .accessibilityValue(row.tone.spoken)
    }
}

/// The Secrets window: a normal window, opened from the panel.
final class SecretsWindow: NSWindow, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init(model: BarModel, onClose: @escaping () -> Void) {
        super.init(contentRect: NSRect(x: 0, y: 0, width: 500, height: 620),
                   styleMask: [.titled, .closable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        self.onClose = onClose
        title = t("Secrets")
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        isReleasedWhenClosed = false
        delegate = self
        contentViewController = NSHostingController(rootView: SecretsView(model: model))
        setContentSize(NSSize(width: 500, height: 620))
        center()
    }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }
}
