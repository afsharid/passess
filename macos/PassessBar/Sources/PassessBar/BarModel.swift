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
    @Published private(set) var harnesses: HarnessStatus?
    @Published private(set) var check: Check?
    @Published private(set) var checkedAt: Date?
    @Published private(set) var checking = false
    @Published private(set) var agentBusy = false
    @Published private(set) var approving = false
    @Published private(set) var copied: String? // id of the item whose text was just copied
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled
    /// `passess list --json`: the secrets and who may use each.
    @Published private(set) var secretList: SecretList?
    /// `passess discover --json`: what the vault holds that passess does not use.
    @Published private(set) var discovery: Discovery?
    /// What the Secrets window's filter field holds.
    @Published var secretsFilter = ""

    private let work = DispatchQueue(label: "passess.bar.work")
    private let vault = DispatchQueue(label: "passess.bar.vault") // discover asks the vault: not behind refresh
    private var refreshing = false
    private var discovering = false
    private var discoveredAt: Date?
    private var timer: Timer?
    private var frozen = false // a preview: seeded state, nothing runs
    private var connectPanel: ConnectPanel?
    private var secretsWindow: SecretsWindow?
    let approver = ApproverController()

    var health: Health { doctor == nil && failure == nil ? .unknown : PassessKit.health(doctor) }

    /// The vault secrets not connected yet, the new ones first.
    var found: [FoundRow] {
        guard secretList?.agents != nil, let d = discovery else { return [] }
        return foundRows(d)
    }

    func start() {
        approver.onChange = { [weak self] in
            guard let self = self else { return }
            self.approving = self.approver.connected
            self.refresh()
        }
        approver.start()
        refresh()
        discover(maxAge: 0)
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.refresh()
            self?.discover(maxAge: 30 * 60)
        }
    }

    /// The panel opened: what it shows should be current.
    func panelOpened() {
        refresh()
        discover(maxAge: 120)
    }

    /// `passess discover`, at most once per maxAge seconds: it asks the vault,
    /// which sends its values along with the names (passess drops them).
    func discover(maxAge: TimeInterval) {
        guard !frozen, !discovering, let cli = Passess.locate() else { return }
        if let at = discoveredAt, Date().timeIntervalSince(at) < maxAge { return }
        discovering = true
        vault.async {
            let found = try? cli.discover()
            DispatchQueue.main.async {
                self.discovering = false
                self.discoveredAt = Date()
                self.discovery = found
            }
        }
    }

    func openSecrets() {
        if secretsWindow == nil {
            secretsWindow = SecretsWindow(model: self) { [weak self] in self?.secretsWindow = nil }
        }
        NSApp.activate(ignoringOtherApps: true)
        secretsWindow?.makeKeyAndOrderFront(nil)
        refresh()
        discover(maxAge: 30)
    }

    func openConnect(_ found: Discovery.Found) {
        show(ConnectModel(mode: .add(found), list: secretList, cli: Passess.locate()))
    }

    func openEdit(_ secret: SecretList.Secret) {
        show(ConnectModel(mode: .edit(secret), list: secretList, cli: Passess.locate()))
    }

    private func show(_ connect: ConnectModel) {
        connectPanel?.close()
        let panel = ConnectPanel(model: connect) { [weak self] in self?.connectPanel = nil }
        connect.onDone = { [weak self, weak panel] in
            panel?.close()
            guard let self = self else { return }
            self.check = nil // it describes the secrets as they were
            self.refresh()
            self.discover(maxAge: 0)
        }
        connectPanel = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }


    func refresh() {
        guard !frozen, !refreshing else { return }
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
            let harnesses = try? cli.harnesses()
            let list = try? cli.list()
            DispatchQueue.main.async {
                self.refreshing = false
                self.doctor = doctor
                self.failure = failure
                self.agent = agent
                self.harnesses = harnesses
                self.secretList = list
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
    func seed(doctor: Doctor?, failure: String? = nil, agent: AgentStatus?, harnesses: HarnessStatus? = nil,
              check: Check? = nil, checkedAt: Date? = nil, approving: Bool = false,
              secretList: SecretList? = nil, discovery: Discovery? = nil) {
        frozen = true
        self.doctor = doctor
        self.failure = failure
        self.agent = agent
        self.harnesses = harnesses
        self.check = check
        self.checkedAt = checkedAt
        self.approving = approving
        self.secretList = secretList
        self.discovery = discovery
        openAtLogin = true
    }

    func setOpenAtLogin(_ on: Bool) {
        do {
            if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
        } catch {
            let alert = NSAlert()
            alert.messageText = t("Could not change Open at Login")
            alert.informativeText = "\(error.localizedDescription)\n\n"
                + t("Move Passess.app to /Applications and try again, or add it under System Settings → General → Login Items.")
            alert.runModal()
        }
        openAtLogin = SMAppService.mainApp.status == .enabled
    }
}
