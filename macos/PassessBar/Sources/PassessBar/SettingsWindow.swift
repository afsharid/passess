import AppKit
import PassessKit
import SwiftUI

/// Everything in the config that is not a secret: backends, MCP servers,
/// profiles and the agent's timings. Each Save runs a passess command after
/// Touch ID, so nothing here edits config.toml; passess checks every change
/// and keeps it only if the config still loads.
final class SettingsModel: ObservableObject {
    enum Tab: String, CaseIterable, Identifiable {
        case backends, mcp, profiles, project, agent
        var id: String { rawValue }
        var title: String {
            switch self {
            case .backends: return t("Backends")
            case .mcp: return t("MCP servers")
            case .profiles: return t("Profiles")
            case .project: return t("Project")
            case .agent: return t("Agent")
            }
        }
    }

    @Published var tab: Tab
    @Published private(set) var busy = false
    @Published private(set) var error: String?
    @Published private(set) var saved: String? // what the last Save changed

    // Backends
    @Published private(set) var backends: BackendSettings?
    @Published var opAccount = ""
    @Published var vaultAddress = ""
    @Published var vaultNamespace = ""
    @Published var vaultCACert = ""
    @Published var bwsServerURL = ""
    @Published var vaultToken = ""
    @Published var bwSession = ""

    // MCP servers
    @Published private(set) var servers: [MCPServer] = []
    @Published var mcpForm: MCPForm?
    @Published var mcpAdding = false

    // Profiles
    @Published private(set) var profiles: [Profile] = []
    @Published var profileName = ""
    @Published var profileSecrets: Set<String> = []
    @Published var profileRequired: Set<String> = []
    @Published var profileInherit = ""
    @Published var profileAllow = ""
    @Published var profileEnv = ""
    @Published var profileTTY = false
    @Published var profileEditing: String? // the profile in the form; "" for a new one

    // Project: a passess.toml names secrets only, so its changes need no Touch ID
    @Published private(set) var projectFolder: String?
    @Published private(set) var projectNeeds: ProjectNeeds?
    @Published var needName = ""
    @Published var needNote = ""
    @Published var needAllow = ""

    // Agent
    @Published var agentConfig: AgentConfig?

    /// The secret names a server or profile can use.
    @Published private(set) var secretNames: [String] = []

    var onChange: (() -> Void)?
    /// Opens the Add tab, for a name the project needs and the config lacks.
    var onAddSecret: (() -> Void)?
    private let cli = Passess.locate()
    private let work = DispatchQueue(label: "passess.settings")

    init(tab: Tab = .backends) {
        self.tab = tab
        load()
    }

    /// Fixed state for previews: nothing runs.
    init(previewing tab: Tab, backends: BackendSettings, servers: [MCPServer], profiles: [Profile],
         agent: AgentConfig, secretNames: [String], project: (folder: String, needs: ProjectNeeds)? = nil) {
        self.tab = tab
        projectFolder = project?.folder
        projectNeeds = project?.needs
        if project != nil { onAddSecret = {} }
        self.backends = backends
        opAccount = backends.op.account
        vaultAddress = backends.vault.address
        vaultNamespace = backends.vault.namespace
        vaultCACert = backends.vault.caCert
        bwsServerURL = backends.bws.serverURL
        self.servers = servers
        self.profiles = profiles
        agentConfig = agent
        self.secretNames = secretNames
    }

    func load() {
        guard let cli = cli else {
            error = t("The passess command line tool is not installed.")
            return
        }
        work.async {
            let b = try? cli.backendSettings()
            let s = (try? cli.mcpServers()) ?? []
            let p = (try? cli.profiles()) ?? []
            let a = try? cli.agentConfig()
            let names = (try? cli.list())?.secrets.map(\.name).sorted() ?? []
            DispatchQueue.main.async {
                self.backends = b
                if let b = b {
                    self.opAccount = b.op.account
                    self.vaultAddress = b.vault.address
                    self.vaultNamespace = b.vault.namespace
                    self.vaultCACert = b.vault.caCert
                    self.bwsServerURL = b.bws.serverURL
                }
                self.servers = s
                self.profiles = p
                self.agentConfig = a
                self.secretNames = names
            }
        }
    }

    /// Runs change after Touch ID, then reloads; what passess said on a
    /// refusal is shown.
    private func confirmAndRun(_ reason: String, done message: String, _ change: @escaping (Passess) throws -> Void,
                               cli chosen: Passess? = nil) {
        guard let cli = chosen ?? cli, !busy else { return }
        Authenticator.confirm(reason) { ok in
            guard ok else { return }
            self.busy = true
            self.error = nil
            self.saved = nil
            self.work.async {
                var failure: String?
                do { try change(cli) } catch { failure = String(describing: error) }
                DispatchQueue.main.async {
                    self.busy = false
                    if let failure = failure {
                        self.error = failure
                    } else {
                        self.saved = message
                        self.load()
                        self.onChange?()
                    }
                }
            }
        }
    }

    // MARK: backends

    func saveBackends() {
        guard let b = backends else { return }
        let changes: [(String, String, String, String)] = [
            ("op", "account", b.op.account, opAccount),
            ("vault", "address", b.vault.address, vaultAddress),
            ("vault", "namespace", b.vault.namespace, vaultNamespace),
            ("vault", "ca-cert", b.vault.caCert, vaultCACert),
            ("bws", "server-url", b.bws.serverURL, bwsServerURL),
        ].map { ($0.0, $0.1, $0.2, $0.3.trimmingCharacters(in: .whitespaces)) }.filter { $0.2 != $0.3 }
        guard !changes.isEmpty else { return }
        confirmAndRun(t("change how passess reaches your vault"), done: t("Backends saved.")) { cli in
            for backend in ["op", "vault", "bws"] {
                let flags = changes.filter { $0.0 == backend }.map { (flag: $0.1, value: $0.3) }
                if !flags.isEmpty { try cli.setBackend(backend, flags) }
            }
        }
    }

    /// The Vault token or the bw session: to the keychain through the copy
    /// of passess inside the app only, never one from the search path.
    func storeCredential(_ backend: String) {
        let (flag, value) = backend == "vault" ? ("token", vaultToken) : ("session", bwSession)
        let v = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !v.isEmpty else { return }
        guard let bundled = Passess.bundled() else {
            error = t("This copy of the app has no passess inside it, so it cannot take the credential.")
            return
        }
        confirmAndRun(t("store a credential that opens your vault"), done: t("Kept in your keychain."), { cli in
            try cli.storeBackendCredential(backend, flag: flag, value: v)
        }, cli: bundled)
        if backend == "vault" { vaultToken = "" } else { bwSession = "" }
    }

    // MARK: MCP servers

    func newServer() {
        mcpForm = MCPForm()
        mcpAdding = true
    }

    func edit(_ s: MCPServer) {
        mcpForm = MCPForm(s)
        mcpAdding = false
    }

    func saveServer() {
        guard let form = mcpForm else { return }
        let adding = mcpAdding
        confirmAndRun(t("change which secrets an MCP server gets"),
                      done: t("Saved. Set up your coding agents again to register it.")) { cli in
            try cli.saveMCP(form, adding: adding)
        }
        mcpForm = nil
    }

    func removeServer(_ name: String) {
        confirmAndRun(t("remove an MCP server"), done: t("Removed. Set up your coding agents again to take it out.")) { cli in
            try cli.removeMCP(name)
        }
    }

    // MARK: profiles

    func newProfile() {
        profileEditing = ""
        profileName = ""
        profileSecrets = []
        profileRequired = []
        profileInherit = ""
        profileAllow = ""
        profileEnv = ""
        profileTTY = false
    }

    func edit(_ p: Profile) {
        profileEditing = p.name
        profileName = p.name
        profileSecrets = Set(p.secrets)
        profileRequired = Set(p.required ?? [])
        profileInherit = (p.inherit ?? []).joined(separator: ", ")
        profileAllow = (p.allow ?? []).joined(separator: ", ")
        profileEnv = (p.env ?? [:]).sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: "\n")
        profileTTY = p.tty
    }

    func saveProfile() {
        let adding = profileEditing == ""
        let name = profileName.trimmingCharacters(in: .whitespaces)
        let secrets = profileSecrets.sorted()
        let required = profileRequired.intersection(profileSecrets).sorted()
        let commaList = { (s: String) in s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }
        let allow = commaList(profileAllow)
        let inherit = commaList(profileInherit)
        let env = profileEnv.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        let tty = profileTTY
        confirmAndRun(t("change which secrets a program gets"), done: t("Profile saved.")) { cli in
            try cli.saveProfile(name: name, secrets: secrets, required: required, allow: allow, inherit: inherit,
                                env: env, tty: tty, adding: adding)
        }
        profileEditing = nil
    }

    func removeProfile(_ name: String) {
        confirmAndRun(t("remove a profile"), done: t("Profile removed.")) { cli in try cli.removeProfile(name) }
    }

    // MARK: project

    func chooseProject() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = t("Choose")
        if let folder = projectFolder { panel.directoryURL = URL(fileURLWithPath: folder) }
        guard panel.runModal() == .OK, let url = panel.url else { return }
        projectFolder = url.path
        loadNeeds()
    }

    func loadNeeds() {
        guard let cli = cli, let folder = projectFolder else { return }
        work.async {
            var got: ProjectNeeds?
            var failure: String?
            do { got = try cli.needs(dir: folder) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.projectNeeds = got
                self.error = failure
            }
        }
    }

    /// Runs a change that hands nothing to anyone, so without Touch ID.
    private func runNames(_ message: String, _ change: @escaping (Passess) throws -> Void) {
        guard let cli = cli, !busy else { return }
        busy = true
        error = nil
        saved = nil
        work.async {
            var failure: String?
            do { try change(cli) } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.busy = false
                if let failure = failure { self.error = failure } else { self.saved = message }
                self.loadNeeds()
            }
        }
    }

    func addNeed() {
        guard let folder = projectFolder else { return }
        let name = needName.trimmingCharacters(in: .whitespaces)
        let note = needNote.trimmingCharacters(in: .whitespaces)
        let allow = needAllow.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        runNames(t("The project now names %@.", name)) { cli in try cli.addNeed(name, dir: folder, note: note, allow: allow) }
        needName = ""
        needNote = ""
        needAllow = ""
    }

    func removeNeed(_ name: String) {
        guard let folder = projectFolder else { return }
        runNames(t("The project no longer names %@.", name)) { cli in try cli.removeNeed(name, dir: folder) }
    }

    // MARK: agent

    func saveAgent() {
        guard let c = agentConfig else { return }
        confirmAndRun(t("change how long approvals last"), done: t("Agent settings saved.")) { cli in try cli.setAgentConfig(c) }
    }
}

struct SettingsView: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TabBar(selection: $model.tab)

            Group {
                switch model.tab {
                case .backends: BackendsPane(model: model)
                case .mcp: MCPPane(model: model)
                case .profiles: ProfilesPane(model: model)
                case .project: ProjectPane(model: model)
                case .agent: AgentPane(model: model)
                }
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)

            if let error = model.error {
                Text(error)
                    .font(.system(size: 11))
                    .foregroundStyle(Tone.error.color)
                    .fixedSize(horizontal: false, vertical: true)
            } else if let saved = model.saved {
                Label(saved, systemImage: "checkmark.circle.fill")
                    .font(.system(size: 11))
                    .foregroundStyle(Tone.ok.color)
            }
        }
        .padding(20)
        .frame(width: 520, alignment: .topLeading)
        .disabled(model.busy)
    }
}

/// The Settings tabs, each an equal share of the width. The system's
/// segmented control sizes each segment to its text and widens the selected
/// one, so five Turkish titles ran past the window and the last one vanished.
private struct TabBar: View {
    @Binding var selection: SettingsModel.Tab

    var body: some View {
        HStack(spacing: 2) {
            ForEach(SettingsModel.Tab.allCases) { tab in
                let selected = tab == selection
                Button { selection = tab } label: {
                    Text(tab.title)
                        .font(.system(size: 12, weight: selected ? .semibold : .regular))
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                        .foregroundStyle(selected ? Color.white : Color.primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 5)
                        .background(RoundedRectangle(cornerRadius: 6, style: .continuous)
                            .fill(selected ? Brand.tint : Color.clear))
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
                .accessibilityAddTraits(selected ? .isSelected : [])
            }
        }
        .padding(2)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(Color.primary.opacity(0.06)))
    }
}

/// A label above a field, the field, and a line saying what it is for.
private struct Field<Content: View>: View {
    let title: String
    let help: String?
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.system(size: 12, weight: .semibold))
            content
            if let help = help {
                Text(help).font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

private struct BackendsPane: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Field(title: "1Password", help: t("The account op uses. Empty: its default account.")) {
                TextField("my.1password.com", text: $model.opAccount).textFieldStyle(.roundedBorder)
            }
            Field(title: "HashiCorp Vault / OpenBao", help: t("Empty fields fall back to VAULT_ADDR and the system's certificates.")) {
                TextField("https://vault.example.com:8200", text: $model.vaultAddress).textFieldStyle(.roundedBorder)
                HStack {
                    TextField(t("Namespace"), text: $model.vaultNamespace).textFieldStyle(.roundedBorder)
                    TextField(t("CA certificate file"), text: $model.vaultCACert).textFieldStyle(.roundedBorder)
                }
                HStack {
                    SecureField(model.backends?.vault.token.isEmpty == false ? t("Token kept in the keychain; paste to replace") : t("Token"),
                                text: $model.vaultToken)
                        .textFieldStyle(.roundedBorder)
                    Button(t("Keep in keychain…")) { model.storeCredential("vault") }
                        .disabled(model.vaultToken.isEmpty)
                }
            }
            Field(title: "Bitwarden", help: t("Paste what `bw unlock --raw` prints. It lasts until bw locks again.")) {
                HStack {
                    SecureField(model.backends?.bw.session.isEmpty == false ? t("Session kept in the keychain; paste to replace") : t("Session key"),
                                text: $model.bwSession)
                        .textFieldStyle(.roundedBorder)
                    Button(t("Keep in keychain…")) { model.storeCredential("bw") }
                        .disabled(model.bwSession.isEmpty)
                }
            }
            Field(title: "Bitwarden Secrets Manager", help: t("A self-hosted server. Empty: bitwarden.com.")) {
                TextField("https://vault.bitwarden.eu", text: $model.bwsServerURL).textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button(t("Save…"), action: model.saveBackends)
                    .buttonStyle(PrimaryButtonStyle())
            }
        }
    }
}

private struct MCPPane: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        if model.mcpForm != nil {
            MCPFormView(model: model)
        } else {
            VStack(alignment: .leading, spacing: 10) {
                Text(t("Coding agents start these servers through passess, which gives each one the secrets named here."))
                    .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if model.servers.isEmpty {
                    Text(t("No MCP servers yet.")).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                ForEach(model.servers) { s in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(s.name).font(.system(size: 13, weight: .semibold))
                            Text(s.summary).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                            if !s.secrets.isEmpty {
                                Text(t("Secrets: %@", s.secrets.joined(separator: ", "))).font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                        }
                        Spacer()
                        Button(t("Edit")) { model.edit(s) }.buttonStyle(.borderless)
                        Button(t("Remove…")) { model.removeServer(s.name) }.buttonStyle(.borderless)
                    }
                    .padding(10)
                    .surface()
                }
                HStack {
                    Spacer()
                    Button(t("Add a server"), action: model.newServer).buttonStyle(PrimaryButtonStyle())
                }
            }
        }
    }
}

private struct MCPFormView: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        let form = Binding(get: { model.mcpForm ?? MCPForm() }, set: { model.mcpForm = $0 })
        VStack(alignment: .leading, spacing: 10) {
            Field(title: t("Name"), help: nil) {
                TextField("github", text: form.name).textFieldStyle(.roundedBorder).disabled(!model.mcpAdding)
            }
            Picker("", selection: form.remote) {
                Text(t("Local (a command)")).tag(false)
                Text(t("Remote (a URL)")).tag(true)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            if form.wrappedValue.remote {
                Field(title: "URL", help: nil) {
                    TextField("https://api.example.com/mcp", text: form.url).textFieldStyle(.roundedBorder)
                }
                Field(title: t("Headers"), help: t("One per line, NAME=TEMPLATE. Write a secret as {{NAME}}, never its value.")) {
                    TextEditor(text: form.headers).font(.system(size: 12, design: .monospaced)).frame(height: 54).surface()
                }
            } else {
                Field(title: t("Command"), help: t("The program on the first line, then one argument per line.")) {
                    TextEditor(text: form.command).font(.system(size: 12, design: .monospaced)).frame(height: 66).surface()
                }
                Field(title: t("Secrets"), help: t("One per line, VARIABLE=SECRET: the server gets the secret in that variable. Known: %@",
                                                     model.secretNames.joined(separator: ", "))) {
                    TextEditor(text: form.env).font(.system(size: 12, design: .monospaced)).frame(height: 54).surface()
                }
                Field(title: t("Plain variables"), help: t("One per line, VARIABLE=VALUE. Not for secrets.")) {
                    TextEditor(text: form.vars).font(.system(size: 12, design: .monospaced)).frame(height: 40).surface()
                }
                Field(title: t("Passed through"), help: t("Variables of the coding agent's the server also gets, one per line.")) {
                    TextEditor(text: form.inherit).font(.system(size: 12, design: .monospaced)).frame(height: 32).surface()
                }
            }
            Field(title: t("Coding agents"), help: t("Their IDs, comma-separated (claude, codex). Empty: every one set up.")) {
                TextField("claude, codex", text: form.harnesses).textFieldStyle(.roundedBorder)
            }
            Toggle(t("Redact the server's output"), isOn: form.redact).toggleStyle(.checkbox).font(.system(size: 12))
            HStack {
                Spacer()
                Button(t("Cancel")) { model.mcpForm = nil }.keyboardShortcut(.cancelAction)
                Button(t("Save…"), action: model.saveServer)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(form.wrappedValue.name.isEmpty)
            }
        }
    }
}

private struct ProfilesPane: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        if model.profileEditing != nil {
            VStack(alignment: .leading, spacing: 10) {
                Field(title: t("Name"), help: nil) {
                    TextField("web", text: $model.profileName).textFieldStyle(.roundedBorder).disabled(model.profileEditing != "")
                }
                Field(title: t("Secrets"), help: nil) {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(model.secretNames, id: \.self) { name in
                                HStack {
                                    Toggle(name, isOn: Binding(get: { model.profileSecrets.contains(name) },
                                                               set: { on in if on { model.profileSecrets.insert(name) } else { model.profileSecrets.remove(name) } }))
                                        .toggleStyle(.checkbox).font(.system(size: 12, design: .monospaced))
                                    Spacer()
                                    if model.profileSecrets.contains(name) {
                                        Toggle(t("required"), isOn: Binding(get: { model.profileRequired.contains(name) },
                                                                            set: { on in if on { model.profileRequired.insert(name) } else { model.profileRequired.remove(name) } }))
                                            .toggleStyle(.checkbox).font(.system(size: 11))
                                            .help(t("The program does not start without it."))
                                    }
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .frame(height: 96)
                    .padding(6)
                    .surface()
                }
                Field(title: t("Programs"), help: t("The programs that may run under it, comma-separated (node, npm).")) {
                    TextField("node, npm", text: $model.profileAllow).textFieldStyle(.roundedBorder)
                }
                Field(title: t("Passed through"), help: t("Variables of yours the program also gets, comma-separated (NODE_OPTIONS).")) {
                    TextField("NODE_OPTIONS", text: $model.profileInherit).textFieldStyle(.roundedBorder)
                }
                Field(title: t("Plain variables"), help: t("One per line, VARIABLE=VALUE. Not for secrets.")) {
                    TextEditor(text: $model.profileEnv).font(.system(size: 12, design: .monospaced)).frame(height: 40).surface()
                }
                Toggle(t("Let a full-screen program have the terminal"), isOn: $model.profileTTY).toggleStyle(.checkbox).font(.system(size: 12))
                HStack {
                    Spacer()
                    Button(t("Cancel")) { model.profileEditing = nil }.keyboardShortcut(.cancelAction)
                    Button(t("Save…"), action: model.saveProfile)
                        .buttonStyle(PrimaryButtonStyle())
                        .disabled(model.profileName.isEmpty || model.profileSecrets.isEmpty || model.profileAllow.isEmpty)
                }
            }
        } else {
            VStack(alignment: .leading, spacing: 10) {
                Text(t("A profile gives a program a set of secrets: passess run NAME -- COMMAND."))
                    .font(.system(size: 12)).foregroundStyle(.secondary)
                if model.profiles.isEmpty {
                    Text(t("No profiles yet.")).font(.system(size: 12)).foregroundStyle(.secondary)
                }
                ForEach(model.profiles) { p in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.name).font(.system(size: 13, weight: .semibold))
                            Text(p.secrets.joined(separator: ", ")).font(.system(size: 11)).foregroundStyle(.secondary)
                            Text(p.run).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
                        }
                        Spacer()
                        Button(t("Edit")) { model.edit(p) }.buttonStyle(.borderless)
                        Button(t("Remove…")) { model.removeProfile(p.name) }.buttonStyle(.borderless)
                    }
                    .padding(10)
                    .surface()
                }
                HStack {
                    Spacer()
                    Button(t("Add a profile"), action: model.newProfile).buttonStyle(PrimaryButtonStyle())
                }
            }
        }
    }
}

private struct ProjectPane: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(t("A project's passess.toml names the secrets it uses, never where they come from, so it can be committed. Your config maps each name."))
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                Text(model.projectFolder.map { $0.replacingOccurrences(of: NSHomeDirectory(), with: "~") } ?? t("No project chosen"))
                    .font(.system(size: 12, design: .monospaced)).lineLimit(1).truncationMode(.middle)
                Spacer()
                Button(t("Choose a project…"), action: model.chooseProject).buttonStyle(PrimaryButtonStyle(compact: true))
            }
            if let p = model.projectNeeds {
                Text(p.path.isEmpty ? t("No passess.toml yet; adding a name starts one here.")
                    : p.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                    .font(.system(size: 11)).foregroundStyle(.secondary)
                ForEach(p.needs) { n in
                    HStack(alignment: .top) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(n.name).font(.system(size: 13, weight: .semibold, design: .monospaced))
                            let detail = [n.note, n.allow.map { t("for %@", $0.joined(separator: ", ")) }].compactMap { $0 }
                            if !detail.isEmpty {
                                Text(detail.joined(separator: " · ")).font(.system(size: 11)).foregroundStyle(.secondary)
                            }
                            Label(n.defined ? t("In your config") : t("Not in your config yet"),
                                  systemImage: n.defined ? "checkmark.circle.fill" : "exclamationmark.circle.fill")
                                .font(.system(size: 11)).foregroundStyle(n.defined ? Tone.ok.color : Tone.warning.color)
                        }
                        Spacer()
                        if !n.defined, let add = model.onAddSecret {
                            Button(t("Add the secret…"), action: add).buttonStyle(.borderless)
                        }
                        Button(t("Remove")) { model.removeNeed(n.name) }.buttonStyle(.borderless)
                    }
                    .padding(10)
                    .surface()
                }
                HStack {
                    TextField(t("Secret name"), text: $model.needName).textFieldStyle(.roundedBorder)
                    Button(t("Add"), action: model.addNeed)
                        .buttonStyle(PrimaryButtonStyle(compact: true))
                        .disabled(model.needName.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                HStack {
                    TextField(t("What for (optional)"), text: $model.needNote).textFieldStyle(.roundedBorder)
                    TextField(t("Programs (optional)"), text: $model.needAllow).textFieldStyle(.roundedBorder)
                }
            }
        }
    }
}

private struct AgentPane: View {
    @ObservedObject var model: SettingsModel

    var body: some View {
        let c = Binding(get: { model.agentConfig ?? AgentConfig(cacheTTL: "", approvalTTL: "", approvalTimeout: "") },
                        set: { model.agentConfig = $0 })
        VStack(alignment: .leading, spacing: 14) {
            Field(title: t("Keep resolved values for"), help: t("Durations such as 10m or 8h. 0 resolves every time.")) {
                TextField("10m", text: c.cacheTTL).textFieldStyle(.roundedBorder)
            }
            Field(title: t("An Allow lasts"), help: t("0 asks for every command.")) {
                TextField("8h", text: c.approvalTTL).textFieldStyle(.roundedBorder)
            }
            Field(title: t("A question waits"), help: t("How long the agent waits for your answer before it refuses.")) {
                TextField("60s", text: c.approvalTimeout).textFieldStyle(.roundedBorder)
            }
            HStack {
                Spacer()
                Button(t("Save…"), action: model.saveAgent)
                    .buttonStyle(PrimaryButtonStyle())
                    .disabled(model.agentConfig == nil)
            }
        }
    }
}

/// The settings window: a normal window, one at a time.
final class SettingsWindow: NSWindow, NSWindowDelegate {
    private var onClose: (() -> Void)?

    init(model: SettingsModel, onClose: @escaping () -> Void) {
        super.init(contentRect: .zero, styleMask: [.titled, .closable], backing: .buffered, defer: false)
        self.onClose = onClose
        title = t("passess settings")
        isReleasedWhenClosed = false
        delegate = self
        let controller = NSHostingController(rootView: SettingsView(model: model))
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
