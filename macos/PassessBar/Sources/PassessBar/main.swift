import AppKit
import PassessKit

// `PassessBar --print-report` prints what the menu would show and exits: a way
// to check the bundled CLI is found and readable without looking at the screen.
if CommandLine.arguments.contains("--print-report") {
    guard let passess = Passess.locate() else {
        print(Passess.Failure.notFound)
        exit(1)
    }
    print("cli: \(passess.executable.path)")
    do {
        let doctor = try passess.doctor()
        print("health: \(health(doctor))")
        for row in rows(doctor: doctor, failure: nil) {
            print("  \(row.title)")
        }
    } catch {
        print("error: \(error)")
        exit(1)
    }
    exit(0)
}

// A menu bar app: no Dock icon, no main window.
let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let controller = StatusController()
controller.start()
app.run()
