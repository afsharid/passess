import AppKit
import PassessKit
import SwiftUI

/// What the Connect window edits: which coding agents may use a secret,
/// whether each new use asks the user, and the hosts `passess http` may send
/// it to. Nothing here holds a value. State
/// lives in @Published, not @State: see PanelView.
final class ConnectModel: ObservableObject {
    enum Mode {
        case add(Discovery.Found) // a vault secret passess does not use yet
        case edit(SecretList.Secret)
        case create // a new secret from any backend: the Add tab
    }

    /// Where a new secret comes from, in the Add tab.
    enum Source: Hashable {
        case onePassword, keychain, reference
    }

    let mode: Mode
    let agents: [SecretList.Agent]
    private let taken: [String]
    private let cli: Passess?
    /// The copy inside the app, for a value the user types: a passess on the
    /// search path could be one planted there (see Passess.bundled).
    private let valueCLI: Passess?
    /// Called on the main thread once passess has made the change.
    var onDone: (() -> Void)?

    @Published var name: String
    @Published var picked: Set<String>
    @Published var approve: Bool
    @Published var hosts: String // comma-separated, as typed
    private let hostsAtStart: [String]
    @Published private(set) var busy = false
    @Published private(set) var error: String?

    // The Add tab. Nothing here holds a value but `value`, which the user
    // types for the keychain and which is emptied once it is sent.
    @Published private(set) var source: Source = .onePassword
    @Published private(set) var vaults: [OPBrowse.Entry] = []
    @Published private(set) var items: [OPBrowse.Entry] = []
    @Published private(set) var fields: [OPBrowse.Entry] = []
    @Published private(set) var vault: String?
    @Published private(set) var item: String?
    @Published private(set) var fieldRef: String?
    @Published var itemFilter = ""
    @Published private(set) var loading = false
    @Published private(set) var browseError: String?
    @Published var value = ""
    @Published var reference = ""
    private var nameTyped = false
    private let browse = DispatchQueue(label: "passess.bar.browse")

    /// tick is an agent ticked from the start: the app whose row asked to
    /// connect this key. Saving still takes the user's Touch ID.
    init(mode: Mode, list: SecretList?, cli: Passess?, valueCLI: Passess? = nil, source: Source = .onePassword, tick: String? = nil) {
        self.mode = mode
        agents = list?.agents ?? []
        taken = list?.secrets.map(\.name) ?? []
        self.cli = cli
        self.valueCLI = valueCLI
        var typed = "" // a new secret goes nowhere through passess http
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
            typed = (secret.hosts ?? []).joined(separator: ", ")
        case .create:
            name = ""
            picked = []
            approve = true
        }
        hosts = typed
        hostsAtStart = hostList(typed)
        if let tick = tick { picked.insert(tick) }
        if case .create = mode { pickSource(source) }
    }

    var adding: Bool {
        if case .edit = mode { return false }
        return true
    }

    var creating: Bool {
        if case .create = mode { return true }
        return false
    }

    /// The name field, which stops following the picked field once typed in.
    func setName(_ typed: String) {
        name = typed
        nameTyped = true
    }

    func pickSource(_ next: Source) {
        source = next
        browseError = nil
        if next == .onePassword && vaults.isEmpty { loadVaults() }
    }

    /// `passess browse op`: 1Password may ask the user to unlock it first.
    func loadVaults() {
        load({ try $0.browseOP() }) { self.vaults = $0.vaults ?? [] }
    }

    func pickVault(_ id: String?) {
        vault = id
        item = nil
        fieldRef = nil
        items = []
        fields = []
        itemFilter = ""
        guard let id = id else { return }
        load({ try $0.browseOP(vault: id) }) { self.items = $0.items ?? [] }
    }

    func pickItem(_ id: String) {
        guard let vault = vault else { return }
        item = id
        fieldRef = nil
        fields = []
        load({ try $0.browseOP(vault: vault, item: id) }) { got in
            self.fields = orderedFields(got.fields ?? [])
            // The first field passess does not have yet, as a start.
            if let first = self.fields.first(where: { $0.ref != nil && $0.usedBy == nil }) { self.pickField(first) }
        }
    }

    func pickField(_ field: OPBrowse.Entry) {
        guard let ref = field.ref else { return }
        fieldRef = ref
        if !nameTyped, let title = items.first(where: { $0.id == item })?.name {
            name = suggestedName(item: title, field: field.name)
        }
    }

    /// Fixed 1Password state for previews: nothing is asked.
    func seedBrowse(_ vaults: OPBrowse, items: OPBrowse, fields: OPBrowse) {
        self.vaults = vaults.vaults ?? []
        vault = items.vault.flatMap { name in self.vaults.first { $0.name == name }?.id }
        self.items = items.items ?? []
        item = self.items.first?.id
        self.fields = orderedFields(fields.fields ?? [])
        if let first = self.fields.first(where: { $0.ref != nil && $0.usedBy == nil }) { pickField(first) }
    }

    var shownItems: [OPBrowse.Entry] {
        items.filter { matches($0.name, filter: itemFilter) }
    }

    private func load(_ ask: @escaping (Passess) throws -> OPBrowse, then use: @escaping (OPBrowse) -> Void) {
        guard let cli = cli else { return }
        loading = true
        browseError = nil
        browse.async {
            do {
                let got = try ask(cli)
                DispatchQueue.main.async {
                    self.loading = false
                    use(got)
                }
            } catch {
                DispatchQueue.main.async {
                    self.loading = false
                    self.browseError = String(describing: error)
                }
            }
        }
    }

    /// Whether a typed value can be stored: only through the app's own copy.
    var canStoreValue: Bool { valueCLI != nil }

    /// What keeps the Add tab from saving, or nil.
    var createProblem: String? {
        guard creating else { return nil }
        switch source {
        case .onePassword: return fieldRef == nil ? t("Pick a field.") : nil
        case .keychain:
            if valueCLI == nil {
                return t("This copy of the app has no passess inside it, so it cannot store a value. Run `passess add NAME --keychain` in a terminal.")
            }
            return value.isEmpty ? t("Type the value.") : nil
        case .reference: return referenceProblem(reference)
        }
    }

    var title: String {
        switch mode {
        case let .add(found): return t("Connect %@", found.key)
        case let .edit(secret): return secret.name
        case .create: return t("Add a secret")
        }
    }

    var sourceLine: String {
        switch mode {
        case let .add(found): return t("Source: %@", found.project.isEmpty ? "bws" : t("%@ · %@", "bws", found.project))
        case let .edit(secret): return t("Source: %@", secret.refs?.first.map(sourceText) ?? secret.backends.joined(separator: ", "))
        case .create: return t("From 1Password, the keychain or a reference")
        }
    }

    var nameError: String? { adding ? nameProblem(name, taken: taken) : nil }

    var hostsError: String? { hostsProblem(hosts) }

    /// The --hosts value to pass, or nil when the hosts did not change, so
    /// that a change of only the agents writes nothing else.
    private var hostsChange: String? {
        hostList(hosts) == hostsAtStart ? nil : hostsArgument(hosts)
    }

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
        guard !busy, nameError == nil, hostsError == nil, createProblem == nil, let cli = cli else { return }
        let name = name, approve = approve, clients = clientsArgument(picked, agents: agents), mode = mode
        let hosts = hostsChange
        let source = source, valueCLI = valueCLI
        let ref = source == .onePassword ? fieldRef : reference.trimmingCharacters(in: .whitespaces)
        let reason = adding ? t("connect %@ to coding agents", name) : t("change who may use %@", name)
        Authenticator.confirm(reason) { ok in
            guard ok else { return }
            let value = self.value
            if source == .keychain { self.value = "" } // typed again if the store fails
            self.perform {
                switch mode {
                case let .add(found): try cli.add(name: name, ref: found.ref, clients: clients, approve: approve, hosts: hosts)
                case .edit: try cli.set(name: name, clients: clients, approve: approve, hosts: hosts)
                case .create where source == .keychain:
                    try valueCLI?.addKeychain(name: name, value: value, clients: clients, approve: approve, hosts: hosts)
                case .create: try cli.add(name: name, ref: ref ?? "", clients: clients, approve: approve, hosts: hosts)
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
    private static let hostsExample = "api.github.com, *.example.com" // a String, so shown as typed

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .center, spacing: 14) {
                Badge(symbol: model.adding ? "link" : "key.fill", size: 46)
                VStack(alignment: .leading, spacing: 3) {
                    Text(model.title)
                        .font(.system(size: 17, weight: .bold))
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(model.sourceLine)
                        .font(.system(size: 12))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
                .accessibilityElement(children: .combine)
            }

            if model.creating {
                AddSourceView(model: model)
            }

            if model.adding {
                VStack(alignment: .leading, spacing: 6) {
                    Text(t("Name agents see"))
                        .font(.system(size: 13, weight: .semibold))
                    TextField("", text: Binding(get: { model.name }, set: { model.setName($0) }))
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

            VStack(alignment: .leading, spacing: 6) {
                Text(t("Where may it be sent?"))
                    .font(.system(size: 13, weight: .semibold))
                TextField(Self.hostsExample, text: Binding(get: { model.hosts }, set: { model.hosts = $0 }))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 13, design: .monospaced))
                    .accessibilityLabel(t("Where may it be sent?"))
                if let problem = model.hostsError {
                    Label(problem, systemImage: "exclamationmark.circle.fill")
                        .font(.system(size: 11))
                        .foregroundStyle(Tone.error.color)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    Text(t("passess http sends it only to these hosts. Separate them with commas. Empty: nowhere."))
                        .font(.system(size: 11))
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

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
                .disabled(model.busy || model.nameError != nil || model.hostsError != nil || model.createProblem != nil)
            }
        }
        .padding(22)
        .frame(width: 440)
        .background(Color(nsColor: .windowBackgroundColor))
        .tint(Brand.tint)
    }
}

/// The Add tab's first part: where the secret comes from. 1Password is
/// browsed vault → item → field by name; the keychain takes a value typed
/// here, which goes to passess on stdin; a reference is typed as it is.
struct AddSourceView: View {
    @ObservedObject var model: ConnectModel
    private static let referenceExample = "op://vault/item/field" // a String, so shown as typed

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Picker(t("From"), selection: Binding(get: { model.source }, set: { model.pickSource($0) })) {
                Text(verbatim: "1Password").tag(ConnectModel.Source.onePassword)
                Text(t("Keychain")).tag(ConnectModel.Source.keychain)
                Text(t("Reference")).tag(ConnectModel.Source.reference)
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .accessibilityLabel(t("From"))

            switch model.source {
            case .onePassword: onePassword
            case .keychain: keychain
            case .reference: reference
            }
        }
    }

    @ViewBuilder
    private var onePassword: some View {
        if let problem = model.browseError {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 12))
                    .foregroundStyle(Tone.warning.color)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)
                Spacer(minLength: 4)
                Button(t("Try again")) {
                    if model.vaults.isEmpty { model.loadVaults() } else { model.pickVault(model.vault) }
                }
                .buttonStyle(.borderless)
            }
        }
        if !model.vaults.isEmpty {
            Picker(t("Vault"), selection: Binding(get: { model.vault }, set: { model.pickVault($0) })) {
                Text(t("Choose a vault")).tag(String?.none)
                ForEach(model.vaults) { Text($0.name).tag(Optional($0.id)) }
            }
            .font(.system(size: 13))
        }
        if model.vault != nil && !model.items.isEmpty {
            VStack(alignment: .leading, spacing: 6) {
                TextField(t("Filter items"), text: Binding(get: { model.itemFilter }, set: { model.itemFilter = $0 }))
                    .textFieldStyle(.roundedBorder)
                    .font(.system(size: 12))
                ScrollView {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(model.shownItems) { it in
                            PickRow(title: it.name, detail: it.category?.lowercased().replacingOccurrences(of: "_", with: " ") ?? "",
                                    picked: model.item == it.id) { model.pickItem(it.id) }
                        }
                    }
                }
                .frame(maxHeight: 130)
                .surface()
            }
        }
        if model.item != nil && !model.fields.isEmpty {
            VStack(alignment: .leading, spacing: 2) {
                ForEach(model.fields) { f in
                    let text = fieldText(f)
                    PickRow(title: text.title, detail: text.detail, picked: model.fieldRef != nil && model.fieldRef == f.ref) { model.pickField(f) }
                        .disabled(f.ref == nil)
                }
            }
            .padding(4)
            .surface()
        }
        if model.loading {
            HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Text(t("Asking 1Password… it may ask you to unlock it."))
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var keychain: some View {
        SecureField(t("Value"), text: Binding(get: { model.value }, set: { model.value = $0 }))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 13, design: .monospaced))
            .accessibilityLabel(t("Value"))
        if !model.canStoreValue, let problem = model.createProblem {
            Label(problem, systemImage: "exclamationmark.circle.fill")
                .font(.system(size: 11))
                .foregroundStyle(Tone.error.color)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(t("It goes to your login keychain; passess keeps only its name. Agents never see it."))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    @ViewBuilder
    private var reference: some View {
        TextField(Self.referenceExample, text: Binding(get: { model.reference }, set: { model.reference = $0 }))
            .textFieldStyle(.roundedBorder)
            .font(.system(size: 13, design: .monospaced))
            .accessibilityLabel(t("Reference"))
        if !model.reference.isEmpty, let problem = model.createProblem {
            Label(problem, systemImage: "exclamationmark.circle.fill")
                .font(.system(size: 11))
                .foregroundStyle(Tone.error.color)
                .fixedSize(horizontal: false, vertical: true)
        } else {
            Text(t("For 1Password, Vault, Bitwarden or bws: where the secret is, never the value."))
                .font(.system(size: 11))
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// A row to pick in the Add tab's lists, lit when picked.
struct PickRow: View {
    let title: String
    let detail: String
    let picked: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                Image(systemName: picked ? "checkmark.circle.fill" : "circle")
                    .font(.system(size: 13))
                    .foregroundStyle(picked ? Brand.text : Color.secondary.opacity(0.55))
                Text(title)
                    .font(.system(size: 12, weight: picked ? .semibold : .regular))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                Spacer(minLength: 4)
                Text(detail)
                    .font(.system(size: 11))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            .padding(.horizontal, 8)
            .padding(.vertical, 5)
            .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(picked ? Brand.tint.opacity(0.11) : Color.clear))
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(picked ? [.isButton, .isSelected] : .isButton)
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
