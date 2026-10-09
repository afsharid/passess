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

    init(mode: Mode, list: SecretList?, cli: Passess?) {
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
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .top, spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(Color.accentColor.opacity(0.15))
                    Image(systemName: "key.fill")
                        .font(.system(size: 18, weight: .medium))
                        .foregroundStyle(Color.accentColor)
                }
                .frame(width: 40, height: 40)
                .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(model.title)
                        .font(.system(size: 15, weight: .semibold))
                        .fixedSize(horizontal: false, vertical: true)
                    Text(model.source)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
            }

            if model.adding {
                VStack(alignment: .leading, spacing: 5) {
                    Text(t("Name agents see"))
                        .font(.system(size: 12, weight: .medium))
                    TextField("", text: Binding(get: { model.name }, set: { model.name = $0 }))
                        .textFieldStyle(.roundedBorder)
                        .font(.system(size: 13, design: .monospaced))
                        .accessibilityLabel(t("Name agents see"))
                    if let problem = model.nameError {
                        Text(problem)
                            .font(.system(size: 11))
                            .foregroundStyle(Tone.error.color)
                    }
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text(t("Who may use it?"))
                    .font(.system(size: 12, weight: .medium))
                LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)],
                          alignment: .leading, spacing: 7) {
                    ForEach(model.agents) { agent in
                        Toggle(agent.label, isOn: Binding(get: { model.picked.contains(agent.id) },
                                                          set: { model.setPicked(agent.id, $0) }))
                            .toggleStyle(.checkbox)
                            .font(.system(size: 13))
                    }
                }
                if model.picked.isEmpty {
                    Text(t("Without an agent ticked, no agent can use it; your own terminal still can."))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            VStack(alignment: .leading, spacing: 3) {
                Toggle(t("Ask me first"), isOn: Binding(get: { model.approve }, set: { model.approve = $0 }))
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .font(.system(size: 13))
                Text(t("Each new program and agent waits for your OK: Touch ID or your password."))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: 6) {
                if !model.users.isEmpty {
                    DetailLine(symbol: "link", text: t("Used by %@", model.users.joined(separator: ", ")))
                }
                DetailLine(symbol: "eye.slash", text: t("The value is never shown, here or to any agent."))
            }
            .padding(10)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.05)))

            if let error = model.error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Tone.error.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }

            HStack(spacing: 8) {
                if !model.adding {
                    Button(t("Remove from passess"), role: .destructive, action: model.remove)
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
                    Label(model.saveTitle, systemImage: model.saveTitle.contains("Touch ID") ? "touchid" : "lock")
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.large)
                .disabled(model.busy || model.nameError != nil)
            }
        }
        .padding(20)
        .frame(width: 420)
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
