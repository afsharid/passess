import AppKit
import PassessKit
import ServiceManagement

/// Owns the status item and its menu. The report comes from `passess doctor
/// --json`, refreshed in the background, when the menu opens and every few
/// minutes; secrets are only resolved when the user asks for a check.
final class StatusController: NSObject, NSMenuDelegate {
    private let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    private let menu = NSMenu()
    private let work = DispatchQueue(label: "passess.bar.work")
    private var timer: Timer?

    private var passess = Passess.locate()
    private var doctor: Doctor?
    private var failure: String?
    private var check: Check?
    private var checkedAt: Date?
    private var checking = false
    private var refreshing = false

    func start() {
        menu.delegate = self
        menu.autoenablesItems = false
        item.menu = menu
        setIcon(.unknown)
        rebuild()
        refresh()
        timer = Timer.scheduledTimer(withTimeInterval: 300, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func menuWillOpen(_ menu: NSMenu) {
        refresh()
    }

    // MARK: data

    private func refresh() {
        guard !refreshing else { return }
        guard let passess = passess ?? Passess.locate() else {
            doctor = nil
            failure = Passess.Failure.notFound.description
            setIcon(.unknown)
            rebuild()
            return
        }
        self.passess = passess
        refreshing = true
        work.async {
            var result: Doctor?
            var failure: String?
            do { result = try passess.doctor() } catch { failure = String(describing: error) }
            DispatchQueue.main.async {
                self.refreshing = false
                self.doctor = result
                self.failure = failure
                self.setIcon(health(result))
                self.rebuild()
            }
        }
    }

    @objc private func runCheck() {
        guard let passess = passess, !checking else { return }
        checking = true
        rebuild()
        work.async {
            let result = try? passess.check()
            DispatchQueue.main.async {
                self.checking = false
                self.check = result
                self.checkedAt = Date()
                self.rebuild()
            }
        }
    }

    // MARK: menu

    private func setIcon(_ health: Health) {
        let image = NSImage(systemSymbolName: health.symbol, accessibilityDescription: "passess")
        image?.isTemplate = true
        item.button?.image = image
        item.button?.toolTip = "passess"
    }

    private func rebuild() {
        menu.removeAllItems()
        for row in rows(doctor: doctor, failure: failure) {
            menu.addItem(menuItem(for: row))
        }
        menu.addItem(.separator())

        let checkItem = NSMenuItem(title: checking ? "Checking secrets…" : "Check secrets now",
                                   action: #selector(runCheck), keyEquivalent: "")
        checkItem.target = self
        checkItem.isEnabled = passess != nil && !checking
        menu.addItem(checkItem)
        if let check = check {
            let results = NSMenuItem(title: resultsTitle(check), action: nil, keyEquivalent: "")
            let sub = NSMenu()
            for row in rows(check: check) {
                sub.addItem(menuItem(for: row))
            }
            results.submenu = sub
            menu.addItem(results)
        }
        menu.addItem(.separator())

        let login = NSMenuItem(title: "Open at Login", action: #selector(toggleLogin), keyEquivalent: "")
        login.target = self
        login.state = SMAppService.mainApp.status == .enabled ? .on : .off
        menu.addItem(login)
        let docs = NSMenuItem(title: "passess on GitHub", action: #selector(openDocs), keyEquivalent: "")
        docs.target = self
        menu.addItem(docs)
        let refreshItem = NSMenuItem(title: "Refresh", action: #selector(refreshNow), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)
        menu.addItem(NSMenuItem(title: "Quit passess", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q"))
    }

    private func resultsTitle(_ check: Check) -> String {
        let ok = check.secrets.filter { $0.state == "ok" }.count
        var title = "Secrets: \(ok) of \(check.secrets.count) resolve"
        if let at = checkedAt {
            title += " (\(DateFormatter.localizedString(from: at, dateStyle: .none, timeStyle: .short)))"
        }
        return title
    }

    private func menuItem(for row: Row) -> NSMenuItem {
        let mi = NSMenuItem(title: row.title, action: nil, keyEquivalent: "")
        if let symbol = row.symbol {
            mi.image = NSImage(systemSymbolName: symbol, accessibilityDescription: nil)
        }
        switch row.action {
        case .none:
            mi.isEnabled = row.isHeader ? false : true
        case let .copy(text):
            mi.action = #selector(copyText(_:))
            mi.target = self
            mi.representedObject = text
            mi.toolTip = text
        case let .open(url):
            mi.action = #selector(openURL(_:))
            mi.target = self
            mi.representedObject = url
        }
        if row.isHeader {
            mi.isEnabled = false
        }
        return mi
    }

    // MARK: actions

    @objc private func copyText(_ sender: NSMenuItem) {
        guard let text = sender.representedObject as? String else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    @objc private func openURL(_ sender: NSMenuItem) {
        guard let url = sender.representedObject as? URL else { return }
        NSWorkspace.shared.open(url)
    }

    @objc private func openDocs() {
        NSWorkspace.shared.open(URL(string: "https://github.com/afsharid/passess#readme")!)
    }

    @objc private func refreshNow() {
        refresh()
    }

    @objc private func toggleLogin() {
        do {
            if SMAppService.mainApp.status == .enabled {
                try SMAppService.mainApp.unregister()
            } else {
                try SMAppService.mainApp.register()
            }
        } catch {
            let alert = NSAlert()
            alert.messageText = "Could not change Open at Login"
            alert.informativeText = "\(error.localizedDescription)\n\nMove Passess.app to /Applications and try again, or add it under System Settings → General → Login Items."
            alert.runModal()
        }
        rebuild()
    }
}
