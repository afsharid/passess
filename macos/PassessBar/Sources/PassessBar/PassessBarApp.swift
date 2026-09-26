import AppKit
import PassessKit
import SwiftUI

/// `PassessBar --print-report` prints what the panel would say and exits: a
/// way to check that the CLI is found and readable without looking at the
/// screen. `--render-previews DIR` writes the panel and the approval window,
/// in sample states and both appearances, to PNG files.
@main
enum Entry {
    @MainActor
    static func main() {
        let args = CommandLine.arguments
        if args.contains("--print-report") {
            exit(printReport())
        }
        if let i = args.firstIndex(of: "--render-previews"), i + 1 < args.count {
            exit(renderPreviews(to: URL(fileURLWithPath: args[i + 1])))
        }
        PassessBarApp.main()
    }
}

/// A menu bar app: no Dock icon (LSUIElement), no main window.
struct PassessBarApp: App {
    @StateObject private var model: BarModel

    init() {
        let model = BarModel()
        model.start()
        _model = StateObject(wrappedValue: model)
    }

    var body: some Scene {
        MenuBarExtra {
            PanelView(model: model)
        } label: {
            Image(systemName: model.health.symbol)
                .accessibilityLabel("passess")
        }
        .menuBarExtraStyle(.window)
    }
}

private func printReport() -> Int32 {
    guard let cli = Passess.locate() else {
        print(Passess.Failure.notFound)
        return 1
    }
    print("cli: \(cli.executable.path)")
    do {
        for line in reportLines(doctor: try cli.doctor(), failure: nil) {
            print(line)
        }
        return 0
    } catch {
        print("error: \(error)")
        return 1
    }
}
