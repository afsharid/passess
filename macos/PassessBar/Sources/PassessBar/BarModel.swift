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
    @Published private(set) var installing: String? // the agent `passess install` is setting up
    @Published private(set) var installFailure: [String: String] = [:] // by agent: what passess said
    @Published var picking: String? // the provider whose secret list is open (KeyNeed.id)
    @Published var openAtLogin = SMAppService.mainApp.status == .enabled
    /// The agent started at login by launchd, from the plist inside the app
    /// (Contents/Library/LaunchAgents): "ask first" secrets work after a
    /// restart without opening the panel.
    @Published private(set) var agentAtLogin = BarModel.loginAgent.status
    /// `passess list --json`: the secrets and who may use each.
    @Published private(set) var secretList: SecretList?
    /// `passess discover --json`: what the vault holds that passess does not use.
    @Published private(set) var discovery: Discovery?
    /// What the Secrets window's filter field holds.
    @Published var secretsFilter = ""
    /// The passess on the search path, which harnesses and shells find.
    @Published private(set) var cliPath = Passess.onSearchPath()?.executable.path

    private let work = DispatchQueue(label: "passess.bar.work")
    private let vault = DispatchQueue(label: "passess.bar.vault") // discover asks the vault: not behind refresh
    private var refreshing = false
    private var discovering = false
    private var discoveredAt: Date?
    private var timer: Timer?
    private var frozen = false // a preview: seeded state, nothing runs
    private var connectPanel: ConnectPanel?
    private var secretsWindow: SecretsWindow?
    private var vaultPanel: VaultPanel?
    private var onboardingWindow: OnboardingWindow?
    private var settingsWindow: SettingsWindow?
    private var settingsModel: SettingsModel?
    private var exposedWindow: ToolWindow?
    private var activityWindow: ToolWindow?
    @Published private(set) var revoking: String? // the approval Item being taken back
    private static let onboardedKey = "onboarded"
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
        // First run, or a setup left half done: the setup window, once.
        if !UserDefaults.standard.bool(forKey: BarModel.onboardedKey) && (cliPath == nil || !agentStartsAtLogin) {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { self.openOnboarding() }
        }
        timer = Timer.scheduledTimer(withTimeInterval: 60, repeats: true) { [weak self] _ in
            self?.refresh()
            self?.discover(maxAge: 30 * 60)
        }
    }

    /// The panel opened: what it shows should be current.
    func panelOpened() {
        if !frozen { agentAtLogin = BarModel.loginAgent.status } // approved in System Settings meanwhile
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

    func openOnboarding() {
        if onboardingWindow == nil {
            onboardingWindow = OnboardingWindow(model: self) { [weak self] in
                self?.onboardingWindow = nil
                UserDefaults.standard.set(true, forKey: BarModel.onboardedKey)
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        onboardingWindow?.makeKeyAndOrderFront(nil)
        refresh()
    }

    /// Backends, MCP servers, profiles and the agent's timings: the rest of
    /// the config, without editing it.
    func openSettings(_ tab: SettingsModel.Tab = .backends) {
        if let window = settingsWindow, let model = settingsModel {
            model.tab = tab
            model.load()
            NSApp.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            return
        }
        let model = SettingsModel(tab: tab)
        model.onChange = { [weak self] in self?.refresh() }
        model.onAddSecret = { [weak self] in self?.openAdd() }
        settingsModel = model
        settingsWindow = SettingsWindow(model: model) { [weak self] in
            self?.settingsWindow = nil
            self?.settingsModel = nil
        }
        NSApp.activate(ignoringOtherApps: true)
        settingsWindow?.makeKeyAndOrderFront(nil)
    }

    /// Where credentials sit in clear on this Mac, and the moves that fix it.
    func openExposed() {
        if exposedWindow == nil {
            let model = ExposedModel()
            model.onChange = { [weak self] in self?.refresh() }
            exposedWindow = ToolWindow(title: t("Secrets in clear"), view: ExposedView(model: model)) { [weak self] in
                self?.exposedWindow = nil
            }
            model.scan()
        }
        NSApp.activate(ignoringOtherApps: true)
        exposedWindow?.makeKeyAndOrderFront(nil)
    }

    /// What the agent ran and what was approved.
    func openActivity() {
        if activityWindow == nil {
            activityWindow = ToolWindow(title: t("Activity"), view: ActivityView(model: ActivityModel())) { [weak self] in
                self?.activityWindow = nil
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        activityWindow?.makeKeyAndOrderFront(nil)
    }

    /// Takes back one Allow. Narrowing access needs no Touch ID.
    func revoke(_ id: String, secret: String, program: String, pid: Int) {
        guard !frozen, revoking == nil, let cli = Passess.locateForAgent() else { return }
        revoking = id
        work.async {
            try? cli.revoke(secret: secret, program: program, pid: pid)
            DispatchQueue.main.async {
                self.revoking = nil
                self.refresh()
            }
        }
    }

    /// What a problem's button does: the action doctor named for it.
    func performFix(_ action: String, target: String?) {
        guard !frozen else { return }
        switch action {
        case "start-config":
            openOnboarding()
        case "open-config":
            if let path = target { open(URL(fileURLWithPath: path)) }
        case "fix-permissions":
            if let path = target {
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
            }
            refresh()
        case "add-secret":
            openAdd()
        case "install-tool":
            if let tool = target { installTool(tool) }
        case "open-1password":
            if let app = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.1password.1password") {
                NSWorkspace.shared.openApplication(at: app, configuration: NSWorkspace.OpenConfiguration())
            } else {
                open(URL(string: "https://1password.com/downloads/mac")!)
            }
        case "backend-settings":
            openSettings(.backends)
        default:
            break
        }
    }

    /// Installs the CLI a backend needs with Homebrew, when there is one;
    /// else opens where to get it.
    private func installTool(_ tool: String) {
        let formula = ["op": ["--cask", "1password-cli"], "bw": ["bitwarden-cli"]][tool]
        let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first { FileManager.default.isExecutableFile(atPath: $0) }
        guard let args = formula, let brew = brew, installing == nil else {
            let pages = ["op": "https://developer.1password.com/docs/cli/get-started/",
                         "bw": "https://bitwarden.com/help/cli/",
                         "bws": "https://bitwarden.com/help/secrets-manager-cli/"]
            open(URL(string: pages[tool] ?? "https://github.com/afsharid/passess#readme")!)
            return
        }
        installing = "tool:" + tool
        work.async {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: brew)
            p.arguments = ["install"] + args
            p.environment = ["HOME": NSHomeDirectory(), "PATH": Passess.searchPath().joined(separator: ":"), "HOMEBREW_NO_AUTO_UPDATE": "1"]
            p.standardOutput = FileHandle.nullDevice
            p.standardError = FileHandle.nullDevice
            var failure: String?
            do {
                try p.run()
                p.waitUntilExit()
                if p.terminationStatus != 0 { failure = t("Homebrew could not install %@.", tool) }
            } catch {
                failure = String(describing: error)
            }
            DispatchQueue.main.async {
                self.installing = nil
                self.installFailure["tool:" + tool] = failure
                self.refresh()
            }
        }
    }

    var cliOnPath: Bool { cliPath != nil }

    /// Whether a setup step is left: the footer then offers the window.
    var setupLeft: Bool { !cliOnPath || !agentStartsAtLogin || (secretList?.secrets.isEmpty ?? true) }

    /// Whether this app carries a passess to link.
    var canLinkCLI: Bool { Passess.bundled() != nil }

    /// Links ~/.local/bin/passess to the copy inside the app: harness
    /// configs then name a path that outlives an update of the app.
    func linkCLI() {
        guard !frozen, let bundled = Passess.bundled() else { return }
        do {
            try Passess.linkBundled(bundled)
        } catch {
            let alert = NSAlert()
            alert.messageText = t("Could not put passess on your PATH")
            alert.informativeText = String(describing: error)
            alert.runModal()
        }
        cliPath = Passess.onSearchPath()?.executable.path
        refresh()
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

    func openConnect(_ found: Discovery.Found, tick: String? = nil) {
        show(ConnectModel(mode: .add(found), list: secretList, cli: Passess.locate(), tick: tick))
    }

    /// The Add tab: a new secret from 1Password, the keychain or a typed
    /// reference. 1Password first when doctor finds it usable.
    func openAdd() {
        let op = doctor?.backends.first { $0.scheme == "op" }?.ok == true
        show(ConnectModel(mode: .create, list: secretList, cli: Passess.locate(), valueCLI: Passess.bundled(),
                          source: op ? .onePassword : .keychain))
    }

    func openEdit(_ secret: SecretList.Secret, tick: String? = nil) {
        show(ConnectModel(mode: .edit(secret), list: secretList, cli: Passess.locate(), tick: tick))
    }

    /// Whether the vault is not set up: no config yet, or bws without a
    /// machine token. The panel then offers the vault window first.
    var needsVault: Bool {
        if let d = doctor, !d.config.ok { return true }
        return discovery?.bwsNotSetUp ?? false
    }

    /// The window that takes the bws machine token.
    func openVault() {
        vaultPanel?.close()
        let model = VaultModel(cli: Passess.bundled()) // never one from the search path: it gets the token
        let panel = VaultPanel(model: model) { [weak self] in self?.vaultPanel = nil }
        model.onDone = { [weak self, weak panel] in
            panel?.close()
            self?.refresh()
            self?.discover(maxAge: 0)
        }
        vaultPanel = panel
        NSApp.activate(ignoringOtherApps: true)
        panel.makeKeyAndOrderFront(nil)
    }

    /// Opens the window that connects the key an app asks for to that app:
    /// the secret passess has by that name, or the vault's, or the list.
    func connectKey(_ name: String, to app: String) {
        if let secret = secretList?.secrets.first(where: { $0.name == name }) {
            openEdit(secret, tick: app)
        } else if let found = discovery?.secrets.first(where: { $0.name == name || $0.key == name }) {
            openConnect(found, tick: app)
        } else {
            secretsFilter = name
            openSecrets()
        }
    }

    /// Names secret as the key an app's provider asks passess for, then opens
    /// the secret's window with the app ticked when it is not connected to
    /// it yet by name (every agent does not count for an app, ADR 11): the
    /// provider would ask for a key it may not have.
    func nameKey(_ provider: String, secret: SecretList.Secret, for app: String) {
        guard !frozen, installing == nil, let cli = Passess.locateForAgent() else { return }
        installing = app
        work.async {
            var failure: String?
            do { try cli.nameKey(app: app, provider: provider, secret: secret.name) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.installing = nil
                self.installFailure[app] = failure
                self.refresh()
                if failure == nil, !(secret.clients ?? []).contains(app) {
                    self.openEdit(secret, tick: app)
                }
            }
        }
    }

    /// `passess install ID --apply`, with the CLI harnesses run, so what it
    /// writes names that binary and not this app's copy.
    func install(_ id: String) {
        guard !frozen, installing == nil, let cli = Passess.locateForAgent() else { return }
        installing = id
        work.async {
            var failure: String?
            do { try cli.install(id) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.installing = nil
                self.installFailure[id] = failure
                self.refresh()
            }
        }
    }

    /// `passess install ID --apply` with --force (replace entries of the
    /// same name the user wrote) or --no-hooks. Leaving the hooks out drops a
    /// guard, so it asks for Touch ID first.
    func install(_ id: String, force: Bool, hooks: Bool) {
        guard !frozen, installing == nil, let cli = Passess.locateForAgent() else { return }
        let run = {
            self.installing = id
            self.work.async {
                var failure: String?
                do { try cli.install(id, force: force, hooks: hooks) } catch { failure = String(describing: error) }
                DispatchQueue.main.async {
                    self.installing = nil
                    self.installFailure[id] = failure
                    self.refresh()
                }
            }
        }
        if hooks { run(); return }
        Authenticator.confirm(t("set up a coding agent without passess's hooks")) { ok in if ok { run() } }
    }

    /// `passess uninstall ID --apply`, after the user says yes and Touch ID:
    /// passess comes out of that agent's config, after a backup.
    func uninstall(_ id: String, label: String) {
        guard !frozen, installing == nil, let cli = Passess.locateForAgent() else { return }
        let alert = NSAlert()
        alert.messageText = t("Take passess out of %@?", label)
        alert.informativeText = t("Its hooks, instructions and MCP entries go; a backup is kept. Agents there can then read secrets passess guarded.")
        alert.addButton(withTitle: t("Take it out"))
        alert.addButton(withTitle: t("Cancel"))
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        Authenticator.confirm(t("take passess out of a coding agent")) { ok in
            guard ok else { return }
            self.installing = id
            self.work.async {
                var failure: String?
                do { try cli.uninstall(id) } catch { failure = String(describing: error) }
                DispatchQueue.main.async {
                    self.installing = nil
                    self.installFailure[id] = failure
                    self.refresh()
                }
            }
        }
    }

    /// Whether the app an agent ID stands for is open.
    func isRunning(_ id: String) -> Bool {
        (AgentStyle.apps[id] ?? []).contains { !NSRunningApplication.runningApplications(withBundleIdentifier: $0).isEmpty }
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
            // The agent and the harnesses through the CLI on the PATH, which
            // harnesses run: what install writes names it, so status compares
            // against it, and the agent must be its build.
            let onPath = Passess.locateForAgent() ?? cli
            let agent = try? onPath.agentStatus()
            let harnesses = try? onPath.harnesses()
            let list = try? cli.list()
            let onSearchPath = Passess.onSearchPath()?.executable.path
            DispatchQueue.main.async {
                self.refreshing = false
                self.cliPath = onSearchPath
                self.doctor = doctor
                self.failure = failure
                self.agent = agent
                self.harnesses = harnesses
                self.secretList = list
                self.updateAgent()
            }
        }
    }

    /// After an upgrade the running agent is the old build and refuses the new
    /// passess: start replaces it. Once per build, so a start that fails is
    /// not retried every minute; the tile still offers it.
    private var updatedFrom: String?
    private func updateAgent() {
        guard let a = agent, a.outdated == true, let build = a.build, updatedFrom != build else { return }
        updatedFrom = build
        agentCommand("start")
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
        agentAtLogin = .enabled
        cliPath = nil
    }

    static let loginAgent = SMAppService.agent(plistName: "io.github.afsharid.passess.agent.plist")

    /// Whether the agent starts at login: on, waiting for the user's OK in
    /// System Settings, or off.
    var agentStartsAtLogin: Bool { agentAtLogin == .enabled || agentAtLogin == .requiresApproval }

    func setAgentAtLogin(_ on: Bool) {
        guard !frozen else { return }
        do {
            if on { try BarModel.loginAgent.register() } else { try BarModel.loginAgent.unregister() }
        } catch {
            let alert = NSAlert()
            alert.messageText = t("Could not change Start at Login")
            alert.informativeText = "\(error.localizedDescription)\n\n"
                + t("Move Passess.app to /Applications and try again. A copy built with swift run has no agent to register.")
            alert.runModal()
        }
        agentAtLogin = BarModel.loginAgent.status
        if agentAtLogin == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
        refresh()
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
