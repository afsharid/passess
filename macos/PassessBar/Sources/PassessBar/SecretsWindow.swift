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
            HStack(alignment: .firstTextBaseline) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(t("Secrets"))
                        .font(.system(size: 18, weight: .semibold))
                    Text(summary)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
                Spacer()
                Button(action: { model.refresh(); model.discover(maxAge: 0) }) {
                    Image(systemName: "arrow.clockwise")
                }
                .buttonStyle(.borderless)
                .help(t("Refresh"))
                .accessibilityLabel(t("Refresh"))
            }
            .padding(.horizontal, 20)
            .padding(.top, 18)
            .padding(.bottom, 10)

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    if let problem = vaultProblem {
                        Card(t("In your vault, not connected")) {
                            Label(problem, systemImage: "exclamationmark.triangle.fill")
                                .font(.system(size: 12))
                                .foregroundStyle(Tone.warning.color)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    } else if !model.found.isEmpty {
                        Card(t("In your vault, not connected")) {
                            ForEach(model.found) { row in
                                FoundRowView(row: row, model: model)
                                if row.id != model.found.last?.id { Divider() }
                            }
                        }
                    }
                    if let list = model.secretList {
                        let rows = secretRows(list, check: model.check)
                        Card(t("Connected")) {
                            ForEach(rows) { row in
                                if let secret = list.secrets.first(where: { $0.name == row.id }) {
                                    SecretRowView(row: row, secret: secret, model: model)
                                    if row.id != rows.last?.id { Divider() }
                                }
                            }
                        }
                    }
                    Label(t("Values are never shown. Every change asks for Touch ID or your password."), systemImage: "eye.slash")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 16)
                        .padding(.bottom, 16)
                }
            }
        }
        .frame(minWidth: 460, idealWidth: 480, minHeight: 360, idealHeight: 600)
    }

    private var summary: String {
        let n = model.secretList?.secrets.count ?? 0
        let secrets = t(n == 1 ? "%ld secret" : "%ld secrets", n)
        let waiting = model.found.count
        return waiting == 0 ? secrets : secrets + " · " + t(waiting == 1 ? "%ld not connected" : "%ld not connected", waiting)
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
            ToneIcon(symbol: "key.horizontal", tone: .neutral)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 6) {
                    Text(row.title)
                        .font(.system(size: 13, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    if row.isNew { NewBadge() }
                }
                Text(row.detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)
            Button(t("Connect")) { model.openConnect(row.found) }
                .controlSize(.small)
        }
        .accessibilityElement(children: .combine)
    }
}

struct NewBadge: View {
    var body: some View {
        Text(t("New"))
            .font(.system(size: 10, weight: .semibold))
            .padding(.horizontal, 6)
            .padding(.vertical, 1)
            .foregroundStyle(Color.accentColor)
            .background(Capsule().fill(Color.accentColor.opacity(0.16)))
    }
}

struct SecretRowView: View {
    let row: SecretRow
    let secret: SecretList.Secret
    @ObservedObject var model: BarModel

    var body: some View {
        Button { model.openEdit(secret) } label: {
            HStack(spacing: 10) {
                ToneIcon(symbol: row.symbol, tone: row.tone)
                VStack(alignment: .leading, spacing: 1) {
                    Text(row.id)
                        .font(.system(size: 13, design: .monospaced))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(row.asks ? row.agents + " · " + t("Asks first") : row.agents)
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }
                Spacer(minLength: 6)
                if row.asks {
                    Image(systemName: "touchid")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .accessibilityHidden(true)
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
        super.init(contentRect: NSRect(x: 0, y: 0, width: 480, height: 600),
                   styleMask: [.titled, .closable, .resizable, .fullSizeContentView], backing: .buffered, defer: false)
        self.onClose = onClose
        title = t("Secrets")
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        isReleasedWhenClosed = false
        delegate = self
        contentViewController = NSHostingController(rootView: SecretsView(model: model))
        setContentSize(NSSize(width: 480, height: 600))
        center()
    }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }
}
