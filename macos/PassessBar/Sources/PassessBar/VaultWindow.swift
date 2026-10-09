import AppKit
import PassessKit
import SwiftUI

/// Sets up the vault on a new machine: the user pastes the Bitwarden Secrets
/// Manager machine token, Touch ID confirms, and `passess backend bws` puts it
/// in the keychain on stdin. The app holds the token only until that returns.
final class VaultModel: ObservableObject {
    @Published var token = ""
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    var onDone: (() -> Void)?
    private let cli: Passess?

    init(cli: Passess?) {
        self.cli = cli
        if cli == nil {
            error = t("This copy of the app has no passess inside it, so it cannot take the token. Run `passess backend bws` in a terminal.")
        }
    }

    var canSave: Bool { !busy && !token.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && cli != nil }

    func save() {
        guard canSave, let cli = cli else { return }
        Authenticator.confirm(t("store the token that opens your vault")) { ok in
            guard ok else { return }
            self.busy = true
            self.error = nil
            let token = self.token.trimmingCharacters(in: .whitespacesAndNewlines)
            DispatchQueue.global().async {
                var failure: String?
                do { try cli.storeBWSToken(token) } catch { failure = String(describing: error) }
                DispatchQueue.main.async {
                    self.busy = false
                    if let failure = failure {
                        self.error = failure
                    } else {
                        self.token = ""
                        self.onDone?()
                    }
                }
            }
        }
    }
}

struct VaultView: View {
    @ObservedObject var model: VaultModel
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            HStack(spacing: 12) {
                Badge(symbol: "lock.shield.fill", size: 40)
                VStack(alignment: .leading, spacing: 2) {
                    Text(t("Connect your vault"))
                        .font(.system(size: 17, weight: .bold))
                    Text("Bitwarden Secrets Manager")
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }
            Text(t("Paste a machine account's access token. passess keeps it in your keychain and uses it only to read the secrets you connect; agents never see it."))
                .font(.system(size: 12))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField(t("Access token"), text: $model.token)
                .textFieldStyle(.roundedBorder)
                .font(.system(size: 12, design: .monospaced))
                .onSubmit(model.save)
            if let error = model.error {
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(Tone.error.color)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button(t("Cancel"), action: onCancel)
                    .keyboardShortcut(.cancelAction)
                Button(action: model.save) {
                    Label(model.busy ? t("Saving…") : t("Save…"), systemImage: "lock.fill")
                }
                .buttonStyle(PrimaryButtonStyle())
                .disabled(!model.canSave)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(22)
        .frame(width: 400)
    }
}

/// The vault window: one at a time, above other windows until it closes.
final class VaultPanel: NSPanel, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init(model: VaultModel, onClose: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable, .fullSizeContentView],
                   backing: .buffered, defer: false)
        self.onClose = onClose
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        title = t("Connect your vault")
        isMovableByWindowBackground = true
        isReleasedWhenClosed = false
        hidesOnDeactivate = false
        level = .floating
        standardWindowButton(.miniaturizeButton)?.isHidden = true
        standardWindowButton(.zoomButton)?.isHidden = true
        delegate = self
        let controller = NSHostingController(rootView: VaultView(model: model, onCancel: { [weak self] in self?.close() }))
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
