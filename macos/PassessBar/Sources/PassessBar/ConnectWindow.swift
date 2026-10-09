import AppKit
import PassessKit
import SwiftUI

/// What the Connect window edits: which coding agents may use a secret and
/// whether each new use asks the user. Nothing here holds a value. State
/// lives in @Published, not @State: see PanelView.
final class ConnectModel: ObservableObject {
    enum Mode {
        case add(Discovery.Found) // a vault secret passess does not use yet
        case edit(SecretList.Secret)
    }

    let mode: Mode
    let agents: [SecretList.Agent]
    private let taken: [String]
    private let cli: Passess?
    /// Called on the main thread once passess has made the change.
    var onDone: (() -> Void)?

    @Published var name: String
    @Published var picked: Set<String>
    @Published var approve: Bool
    @Published private(set) var busy = false
    @Published private(set) var error: String?

    /// tick is an agent ticked from the start: the app whose row asked to
    /// connect this key. Saving still takes the user's Touch ID.
    init(mode: Mode, list: SecretList?, cli: Passess?, tick: String? = nil) {
        self.mode = mode
        agents = list?.agents ?? []
        taken = list?.secrets.map(\.name) ?? []
        self.cli = cli
        switch mode {
        case let .add(found):
            // Nothing ticked: the user says who gets it. Asking every time is
            // the careful start; it can be turned off here later.
            name = found.name
            picked = []
            approve = true
        case let .edit(secret):
            name = secret.name
            picked = pickedAgents(secret.clients, agents: agents)
            approve = secret.approve ?? false
        }
        if let tick = tick { picked.insert(tick) }
    }

    var adding: Bool {
        if case .add = mode { return true }
        return false
    }

    var title: String {
        switch mode {
        case let .add(found): return t("Connect %@", found.key)
        case let .edit(secret): return secret.name
        }
    }

    var source: String {
        switch mode {
        case let .add(found): return t("Source: %@", found.project.isEmpty ? "bws" : t("%@ · %@", "bws", found.project))
        case let .edit(secret): return t("Source: %@", secret.refs?.first.map(sourceText) ?? secret.backends.joined(separator: ", "))
        }
    }

    var nameError: String? { adding ? nameProblem(name, taken: taken) : nil }

    var users: [String] {
        guard case let .edit(secret) = mode else { return [] }
        return (secret.profiles ?? []).map { t("profile %@", $0) } + (secret.mcp ?? []).map { t("MCP server %@", $0) }
    }

    var saveTitle: String {
        switch (adding, Authenticator.hasTouchID) {
        case (true, true): return t("Connect with Touch ID")
        case (true, false): return t("Connect…")
        case (false, true): return t("Save with Touch ID")
        case (false, false): return t("Save…")
        }
    }

    func setPicked(_ id: String, _ on: Bool) {
        if on { picked.insert(id) } else { picked.remove(id) }
    }

    func pickAll() { picked = Set(agents.map(\.id)) }

    func pickNone() { picked = [] }

    /// Touch ID first, then passess add or set.
    func save() {
        guard !busy, nameError == nil, let cli = cli else { return }
        let name = name, approve = approve, clients = clientsArgument(picked, agents: agents), mode = mode
        let reason = adding ? t("connect %@ to coding agents", name) : t("change who may use %@", name)
        Authenticator.confirm(reason) { ok in
            guard ok else { return }
            self.perform {
                switch mode {
                case let .add(found): try cli.add(name: name, ref: found.ref, clients: clients, approve: approve)
                case .edit: try cli.set(name: name, clients: clients, approve: approve)
                }
            }
        }
    }

    /// After a confirmation and Touch ID, passess forgets the secret; the
    /// vault keeps it.
    func remove() {
        guard case let .edit(secret) = mode, !busy, let cli = cli else { return }
        if !users.isEmpty {
            error = t("Removing it would break %@; take it out there first.", users.joined(separator: ", "))
            return
        }
        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = t("Remove %@ from passess?", secret.name)
        alert.informativeText = t("Agents can no longer use it. Your vault keeps the secret.")
        alert.addButton(withTitle: t("Remove"))
        alert.addButton(withTitle: t("Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Authenticator.confirm(t("remove %@ from passess", secret.name)) { ok in
            guard ok else { return }
            self.perform { try cli.remove(name: secret.name) }
        }
    }

    private func perform(_ change: @escaping () throws -> Void) {
        busy = true
        error = nil
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                try change()
                DispatchQueue.main.async {
                    self.busy = false
                    self.onDone?()
                }
            } catch {
                DispatchQueue.main.async {
                    self.busy = false
                    self.error = String(describing: error)
                }
            }
        }
    }
}

struct ConnectView: View {
    @ObservedObject var model: ConnectModel
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center, spacing: 14) {
                Badge(symbol: model.adding ? "link" : "key.fill", size: 46)
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.title)
                        .font(.system(size: 17, weight: .bold))
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(model.source)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
            }

            if model.adding {
                VStack(alignment: .leading, spacing: 6) {
                    Text(t("Name agents see"))
                        .font(.system(size: 13, weight: .semibold))
                    TextField("", text: Binding(get: { model.name }, set: { model.name = $0 }))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                        .accessibilityLabel(t("Name agents see"))
                    if let problem = model.nameError {
                        Label(problem, systemImage: "exclamationmark.circle.fill")
                            .font(.system(size: 11))
                            .foregroundStyle(Tone.error.color)
                    }
                }
            }

            VStack(alignment: .leading, spacing: 10) {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(t("Who may use it?"))
                        .font(.system(size: 13, weight: .semibold))
                    Spacer()
                    Button(t("All"), action: model.pickAll)
                        .buttonStyle(.borderless)
                    Text("·").foregroundStyle(.tertiary)
                    Button(t("None"), action: model.pickNone)
                        .buttonStyle(.borderless)
                }
                .font(.system(size: 12))
                LazyVGrid(columns: [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)], spacing: 8) {
                    ForEach(model.agents) { agent in
                        let on = model.picked.contains(agent.id)
                        AgentChoice(agent: agent, picked: on) { model.setPicked(agent.id, !on) }
                    }
                }
                if model.picked.isEmpty {
                    Label(t("Without an agent ticked, no agent can use it; your own terminal still can."), systemImage: "info.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            HStack(spacing: 12) {
                Image(systemName: "touchid")
                    .font(.system(size: 17, weight: .medium))
                    .foregroundStyle(Brand.text)
                    .frame(width: 32, height: 32)
                    .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Brand.tint.opacity(0.12)))
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(t("Ask me first"))
                        .font(.system(size: 13, weight: .semibold))
                    Text(t("Each new program and agent waits for your OK: Touch ID or your password."))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Toggle(t("Ask me first"), isOn: Binding(get: { model.approve }, set: { model.approve = $0 }))
                    .toggleStyle(BrandSwitchStyle())
                    .accessibilityLabel(t("Ask me first"))
            }
            .padding(12)
            .surface()

            VStack(alignment: .leading, spacing: 7) {
                if !model.users.isEmpty {
                    DetailLine(symbol: "link", text: t("Used by %@", model.users.joined(separator: ", ")))
                }
                HStack(alignment: .firstTextBaseline, spacing: 8) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(Brand.text)
                        .frame(width: 14)
                        .accessibilityHidden(true)
                    Text(t("The value is never shown, here or to any agent."))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }

            if let error = model.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Tone.error.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }

            HStack(spacing: 10) {
                if !model.adding {
                    Button(role: .destructive, action: model.remove) {
                        Label(t("Remove from passess"), systemImage: "trash")
                    }
                    .buttonStyle(.borderless)
                    .foregroundStyle(Tone.error.color)
                    .disabled(model.busy)
                }
                Spacer()
                if model.busy {
                    ProgressView().controlSize(.small)
                    Text(t("Saving…")).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                Button(t("Cancel"), action: onCancel)
                    .keyboardShortcut(.cancelAction)
                    .controlSize(.large)
                Button(action: model.save) {
                    Label(model.saveTitle, systemImage: model.saveTitle.contains("Touch ID") ? "touchid" : "lock.fill")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(model.busy || model.nameError != nil)
            }
        }
        .padding(22)
        .frame(width: 440)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Brand.tint)
    }
}

/// One coding agent to tick: its avatar and name on a tile that lights up
/// when picked.
struct AgentChoice: View {
    let agent: SecretList.Agent
    let picked: Bool
    let toggle: () -> Void

    var body: some View {
        Button(action: toggle) {
            HStack(spacing: 9) {
                AgentAvatar(id: agent.id, label: agent.label, size: 24)
                Text(agent.label)
                    .font(.system(size: 13, weight: picked ? .semibold : .regular))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 4)
                Image(systemName: picked ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 15))
                    .foregroundStyle(picked ? Brand.text : Color.secondary.opacity(0.55))
            }
            .padding(.horizontal, 10)
            .padding(.vertical, 8)
            .background(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(picked ? Brand.tint.opacity(0.11) : Color(nsColor: .controlBackgroundColor)))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(picked ? Brand.text.opacity(0.65) : Color.primary.opacity(0.1), lineWidth: picked ? 1.2 : 0.5))
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(agent.label)
        .accessibilityValue(picked ? t("selected") : t("not selected"))
        .accessibilityAddTraits(picked ? [.isButton, .isSelected] : .isButton)
    }
}

/// The Connect window: one at a time, above other windows until it closes. It
/// grows and shrinks with what it shows (a hint, an error).
final class ConnectPanel: NSPanel, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init(model: ConnectModel, onClose: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable, .fullSizeContentView],
                   backing: .buffered, defer: false)
        self.onClose = onClose
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        title = model.title
        isMovableByWindowBackground = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        level = .floating
        standardWindowButton(.miniaturizeButton)?.isHidden = true
        standardWindowButton(.zoomButton)?.isHidden = true
        delegate = self
        let controller = NSHostingController(rootView: ConnectView(model: model, onCancel: { [weak self] in self?.close() }))
        controller.sizingOptions = .preferredContentSize
        contentViewController = controller
        setContentSize(controller.view.fittingSize)
        center()
    }

    override var canBecomeKey: Bool { true }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }
}
