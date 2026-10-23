import AppKit
import PassessKit
import SwiftUI

/// The first run, after 1Password's "Set up your developer tools": five
/// steps, each one a button, none a command to copy. Each step reads its
/// state from what the panel already knows (doctor, list, status), so the
/// window can be opened again later and shows what is left.
struct OnboardingView: View {
    @ObservedObject var model: BarModel
    let onClose: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 14) {
                Badge(symbol: "sparkles", size: 46)
                VStack(alignment: .leading, spacing: 3) {
                    Text(t("Set up passess"))
                        .font(.system(size: 20, weight: .bold))
                    Text(t("Five steps, no terminal. Each can be done again later."))
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                }
            }

            Step(number: 1, title: t("Put passess on your PATH"), detail: cliDetail, done: model.cliOnPath) {
                if !model.cliOnPath {
                    Button(t("Link it")) { model.linkCLI() }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                        .disabled(!model.canLinkCLI)
                }
            }

            Step(number: 2, title: t("Find your password managers"), detail: backendsDetail, done: !usable.isEmpty) {
                Button(t("Check again")) { model.refresh() }
                    .buttonStyle(.borderless)
            }

            Step(number: 3, title: t("Add your first secret"), detail: secretsDetail, done: secretCount > 0) {
                Button(secretCount > 0 ? t("Add another") : t("Add")) { model.openAdd() }
                    .buttonStyle(PrimaryButtonStyle(compact: true))
            }

            Step(number: 4, title: t("Set up your coding agents"), detail: agentsDetail, done: !rows.isEmpty && waiting.isEmpty) {
                EmptyView()
            }
            if !waiting.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(waiting) { AgentRowView(row: $0, model: model) }
                }
                .padding(.leading, 36)
            }

            Step(number: 5, title: t("Start the agent at login"), detail: t("Secrets that ask first keep working after a restart."),
                 done: model.agentStartsAtLogin) {
                if !model.agentStartsAtLogin {
                    Button(t("Turn on")) { model.setAgentAtLogin(true) }
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                }
            }

            HStack {
                Toggle(t("Open at Login"), isOn: Binding(get: { model.openAtLogin }, set: { model.setOpenAtLogin($0) }))
                    .toggleStyle(.checkbox)
                    .font(.system(size: 12))
                Spacer()
                Button(t("Done"), action: onClose)
                    .keyboardShortcut(.defaultAction)
                    .controlSize(.large)
            }
        }
        .padding(22)
        .frame(width: 460)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Brand.tint)
    }

    private var cliDetail: String {
        if let path = model.cliPath { return path }
        return model.canLinkCLI ? t("Links ~/.local/bin/passess to the copy inside this app.")
            : t("This copy of the app has no passess inside it: %@", Passess.installCommand)
    }

    private var usable: [String] {
        (model.doctor?.backends ?? []).filter(\.ok).map(\.scheme)
    }

    private var backendsDetail: String {
        guard model.doctor != nil else { return t("Checking…") }
        return usable.isEmpty ? t("None found yet: install 1Password's op, or add a secret to the keychain.")
            : t("Ready: %@", usable.joined(separator: ", "))
    }

    private var secretCount: Int { model.secretList?.secrets.count ?? 0 }

    private var secretsDetail: String {
        secretCount > 0 ? t(secretCount == 1 ? "%ld secret" : "%ld secrets", secretCount)
            : t("From 1Password, the keychain or a reference")
    }

    private var rows: [AgentRow] {
        model.harnesses.map { codingAgents($0, running: model.isRunning) } ?? []
    }

    /// The coding agents passess can set up and has not yet.
    private var waiting: [AgentRow] { rows.filter { $0.install != nil } }

    private var agentsDetail: String {
        if model.harnesses == nil { return t("Checking…") }
        if rows.isEmpty { return t("No coding agent found on this Mac.") }
        return waiting.isEmpty ? t("Every coding agent found is set up.") : t("Set up runs passess install, after a backup.")
    }
}

/// One numbered step: a check once it is done.
private struct Step<Action: View>: View {
    let number: Int
    let title: String
    let detail: String
    let done: Bool
    @ViewBuilder let action: () -> Action

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            ZStack {
                Circle().fill(done ? AnyShapeStyle(Brand.gradient) : AnyShapeStyle(Color.primary.opacity(0.08)))
                if done {
                    Image(systemName: "checkmark").font(.system(size: 11, weight: .bold)).foregroundStyle(.white)
                } else {
                    Text("\(number)").font(.system(size: 12, weight: .semibold)).foregroundStyle(.secondary)
                }
            }
            .frame(width: 24, height: 24)
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                    .truncationMode(.middle)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
            }
            .accessibilityElement(children: .combine)
            .accessibilityValue(done ? t("done") : t("not done"))
            Spacer(minLength: 8)
            action()
        }
    }
}

/// The setup window: a normal window, opened on first run and from the panel.
final class OnboardingWindow: NSWindow, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init(model: BarModel, onClose: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
        self.onClose = onClose
        title = t("Set up passess")
        titlebarAppearsTransparent = true
        titleVisibility = .hidden
        isMovableByWindowBackground = true
        isReleasedWhenClosed = false
        delegate = self
        let controller = NSHostingController(rootView: OnboardingView(model: model, onClose: { [weak self] in self?.close() }))
        controller.sizingOptions = .preferredContentSize
        contentViewController = controller
        setContentSize(controller.view.fittingSize)
        center()
    }

    func windowWillClose(_ notification: Notification) {
        let close = onClose
        onClose = nil
        close?()
    }
}
