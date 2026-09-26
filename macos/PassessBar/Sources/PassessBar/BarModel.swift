import AppKit
import PassessKit
import ServiceManagement

/// Everything the panel shows, and what its buttons do. Reports come from the
/// CLI (`doctor --json`, `agent status --json`) on a background queue; secrets
/// are resolved only when the user asks for a check.
final class BarModel: ObservableObject {
    @Published private(set) var doctor: Doctor?
    @Published private(set) var failure: String?
    @Published private(set) var agent: AgentStatus?
    @Published private(set) var check: Check?
    @Published private(set) var checkedAt: Date?
    @Published private(set) var checking = false
    @Published private(set) var agentBusy = false
    @Published private(set) var approving = false
    @Published private(set) var copied: String? // id of the item whose text was just copied
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled

    private let work = DispatchQueue(label: "passess.bar.work")
    private var refreshing = false
    private var timer: Timer?
    let approver = ApproverController()

    var health: Health { doctor == nil && failure == nil ? .unknown : PassessKit.health(doctor) }

    func start() {
        approver.onChange = { [weak self] in
            guard let self = self else { return }
            self.approving = self.approver.connected
            self.refresh()
        }
        approver.start()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func refresh() {
        guard !refreshing else { return }
        guard let cli = Passess.locate() else {
            doctor = nil
            failure = Passess.Failure.notFound.description
            return
        }
        refreshing = true
        work.async {
            var doctor: Doctor?
            var failure: String?
            do { doctor = try cli.doctor() } catch { failure = String(describing: error) }
            let agent = try? (Passess.locateForAgent() ?? cli).agentStatus()
            DispatchQueue.main.async {
                self.refreshing = false
                self.doctor = doctor
                self.failure = failure
                self.agent = agent
            }
        }
    }

    func runCheck() {
        guard let cli = Passess.locate(), !checking else { return }
        checking = true
        work.async {
            let result = try? cli.check()
            DispatchQueue.main.async {
                self.checking = false
                self.check = result
                self.checkedAt = Date()
            }
        }
    }

    /// `passess agent start`, `lock` or `stop`, with the CLI harnesses run.
    func agentCommand(_ subcommand: String) {
        guard let cli = Passess.locateForAgent(), !agentBusy else { return }
        agentBusy = true
        work.async {
            try? cli.agent(subcommand)
            DispatchQueue.main.async {
                self.agentBusy = false
                self.refresh()
            }
        }
    }

    func copy(_ text: String, from id: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copied = id
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            if self?.copied == id { self?.copied = nil }
        }
    }

    func open(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    /// Fixed state for previews: nothing runs.
    func seed(doctor: Doctor?, failure: String? = nil, agent: AgentStatus?, check: Check? = nil,
              checkedAt: Date? = nil, approving: Bool = false) {
        self.doctor = doctor
        self.failure = failure
        self.agent = agent
        self.check = check
        self.checkedAt = checkedAt
        self.approving = approving
        openAtLogin = true
    }

    func setOpenAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Could not change Open at Login"
            alert.informativeText = "\(error.localizedDescription)\n\nMove Passess.app to /Applications and try again, or add it under System Settings → General → Login Items."
            alert.runModal()
        }
        openAtLogin = SMAppService.mainApp.status == .enabled
    }
}
