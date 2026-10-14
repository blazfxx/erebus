// Erebus.app — native macOS shell around the Erebus engine.
// Each opened binary gets its own window: the bundled `erebus` CLI analyses it into a cached database,
// a private local server presents it, and a WKWebView renders the UI. MIT licensed.

import Cocoa
import WebKit

// MARK: - Engine

enum Engine {
    static let githubURL = URL(string: "https://github.com/blazfxx/erebus")!

    /// The bundled CLI (Contents/Resources/bin/erebus), or $EREBUS_BIN / a dev build next to the sources.
    static var binary: String? {
        let fm = FileManager.default
        var candidates: [String] = []
        if let env = ProcessInfo.processInfo.environment["EREBUS_BIN"] { candidates.append(env) }
        if let res = Bundle.main.resourcePath { candidates.append(res + "/bin/erebus") }
        candidates.append("/opt/homebrew/bin/erebus")
        candidates.append("/usr/local/bin/erebus")
        return candidates.first { fm.isExecutableFile(atPath: $0) }
    }

    static let version: String = {
        guard let bin = binary else { return "unknown" }
        return run(bin, ["--version"]).out.trimmingCharacters(in: .whitespacesAndNewlines)
    }()

    static var databaseDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = base.appendingPathComponent("Erebus/Databases", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    /// Cache key: path + size + mtime + arch + engine version, so edits/updates re-analyse.
    static func databaseURL(for file: URL, arch: String?) -> URL {
        let attrs = (try? FileManager.default.attributesOfItem(atPath: file.path)) ?? [:]
        let size = (attrs[.size] as? NSNumber)?.uint64Value ?? 0
        let mtime = (attrs[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
        var h: UInt64 = 0xcbf29ce484222325
        for b in "\(file.path)|\(size)|\(mtime)|\(arch ?? "")|\(version)".utf8 { h = (h ^ UInt64(b)) &* 0x100000001b3 }
        let stem = file.deletingPathExtension().lastPathComponent
        return databaseDirectory.appendingPathComponent("\(stem)-\(String(h, radix: 16)).erdb")
    }

    @discardableResult
    static func run(_ path: String, _ args: [String]) -> (status: Int32, out: String, err: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let o = Pipe(), e = Pipe()
        p.standardOutput = o
        p.standardError = e
        do { try p.run() } catch { return (-1, "", "\(error)") }
        let outData = o.fileHandleForReading.readDataToEndOfFile()
        let errData = e.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: outData, as: UTF8.self), String(decoding: errData, as: UTF8.self))
    }

    /// Architectures inside a fat Mach-O ([] if the file is not fat).
    static func fatArchitectures(_ file: URL) -> [String] {
        let r = run("/usr/bin/lipo", ["-archs", file.path])
        guard r.status == 0 else { return [] }
        let archs = r.out.split(separator: " ").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        return archs.count > 1 ? archs : []
    }
}

// MARK: - Document window

final class DocumentWindowController: NSWindowController, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate {
    let source: URL
    let arch: String?
    private let webView: WKWebView
    private let overlay = NSVisualEffectView()
    private let spinner = NSProgressIndicator()
    private let status = NSTextField(labelWithString: "")
    private var server: Process?
    private var serverPort: Int?
    private(set) var databaseURL: URL?
    var onClose: ((DocumentWindowController) -> Void)?

    init(source: URL, arch: String?) {
        self.source = source
        self.arch = arch
        let cfg = WKWebViewConfiguration()
        cfg.preferences.javaScriptCanOpenWindowsAutomatically = false
        webView = WKWebView(frame: .zero, configuration: cfg)
        let win = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1440, height: 900),
                           styleMask: [.titled, .closable, .miniaturizable, .resizable],
                           backing: .buffered, defer: false)
        win.title = source.lastPathComponent
        win.representedURL = source
        win.minSize = NSSize(width: 900, height: 560)
        win.setFrameAutosaveName("ErebusDocument")
        super.init(window: win)
        win.delegate = self
        webView.navigationDelegate = self
        webView.uiDelegate = self
        webView.setValue(false, forKey: "drawsBackground")
        webView.translatesAutoresizingMaskIntoConstraints = false

        let content = NSView()
        win.contentView = content
        content.addSubview(webView)

        overlay.material = .underWindowBackground
        overlay.blendingMode = .withinWindow
        overlay.state = .active
        overlay.translatesAutoresizingMaskIntoConstraints = false
        spinner.style = .spinning
        spinner.controlSize = .large
        spinner.isIndeterminate = true
        spinner.translatesAutoresizingMaskIntoConstraints = false
        status.font = .systemFont(ofSize: 13)
        status.textColor = .secondaryLabelColor
        status.translatesAutoresizingMaskIntoConstraints = false
        overlay.addSubview(spinner)
        overlay.addSubview(status)
        content.addSubview(overlay)
        NSLayoutConstraint.activate([
            webView.topAnchor.constraint(equalTo: content.topAnchor),
            webView.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            webView.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            webView.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            overlay.topAnchor.constraint(equalTo: content.topAnchor),
            overlay.bottomAnchor.constraint(equalTo: content.bottomAnchor),
            overlay.leadingAnchor.constraint(equalTo: content.leadingAnchor),
            overlay.trailingAnchor.constraint(equalTo: content.trailingAnchor),
            spinner.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            spinner.centerYAnchor.constraint(equalTo: overlay.centerYAnchor, constant: -10),
            status.centerXAnchor.constraint(equalTo: overlay.centerXAnchor),
            status.topAnchor.constraint(equalTo: spinner.bottomAnchor, constant: 14),
        ])
    }

    required init?(coder: NSCoder) { fatalError("not used") }

    // MARK: lifecycle

    func start(forceReanalyze: Bool = false) {
        showOverlay("Analysing \(source.lastPathComponent)…")
        guard let bin = Engine.binary else {
            fail("The Erebus engine was not found inside the app bundle.")
            return
        }
        let isDB = source.pathExtension.lowercased() == "erdb"
        let db = isDB ? source : Engine.databaseURL(for: source, arch: arch)
        databaseURL = db
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }
            if !isDB {
                if forceReanalyze { try? FileManager.default.removeItem(at: db) }
                if !FileManager.default.fileExists(atPath: db.path) {
                    var args = ["open", self.source.path, "-o", db.path, "-q"]
                    if let a = self.arch { args += ["--arch", a] }
                    let r = Engine.run(bin, args)
                    if r.status != 0 {
                        let msg = r.err.trimmingCharacters(in: .whitespacesAndNewlines)
                        DispatchQueue.main.async { self.fail(msg.isEmpty ? "Analysis failed." : msg) }
                        return
                    }
                }
            }
            DispatchQueue.main.async { self.showOverlay("Starting…") }
            self.startServer(bin: bin, db: db)
        }
    }

    private func startServer(bin: String, db: URL) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["serve", db.path, "--port", "0", "--no-open", "--watch-pid", String(ProcessInfo.processInfo.processIdentifier)]
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        var buffer = ""
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let data = h.availableData
            if data.isEmpty { return }
            buffer += String(decoding: data, as: UTF8.self)
            guard let r = buffer.range(of: #"http://127\.0\.0\.1:(\d+)"#, options: .regularExpression) else { return }
            let url = String(buffer[r])
            h.readabilityHandler = nil
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.serverPort = Int(url.split(separator: ":").last ?? "")
                self.webView.load(URLRequest(url: URL(string: url)!))
            }
        }
        p.terminationHandler = { [weak self] proc in
            DispatchQueue.main.async {
                guard let self = self, self.window?.isVisible == true, proc.terminationReason != .uncaughtSignal || proc.terminationStatus != SIGTERM else { return }
                if self.server === proc, proc.terminationStatus != 0 && proc.terminationStatus != SIGTERM {
                    self.fail("The analysis engine stopped unexpectedly (status \(proc.terminationStatus)).")
                }
            }
        }
        do { try p.run(); server = p } catch { DispatchQueue.main.async { self.fail("Could not start the engine: \(error)") } }
    }

    func stopServer() {
        if let p = server, p.isRunning { p.terminate() }
        server = nil
    }

    func reanalyze() { stopServer(); webView.load(URLRequest(url: URL(string: "about:blank")!)); start(forceReanalyze: true) }
    func reload() { webView.reload() }
    func zoom(_ delta: CGFloat?) { webView.pageZoom = delta == nil ? 1.0 : max(0.5, min(3.0, webView.pageZoom + delta!)) }

    // MARK: overlay / errors

    private func showOverlay(_ text: String) {
        status.stringValue = text
        overlay.isHidden = false
        spinner.startAnimation(nil)
    }
    private func hideOverlay() { overlay.isHidden = true; spinner.stopAnimation(nil) }

    private func fail(_ message: String) {
        hideOverlay()
        let a = NSAlert()
        a.alertStyle = .warning
        a.messageText = "Couldn't open \(source.lastPathComponent)"
        a.informativeText = String(message.prefix(600))
        a.addButton(withTitle: "OK")
        if let w = window { a.beginSheetModal(for: w) { _ in w.close() } } else { a.runModal() }
    }

    // MARK: WKNavigationDelegate / WKUIDelegate

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        if let u = webView.url, u.host == "127.0.0.1" { hideOverlay() }
    }

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else { return decisionHandler(.cancel) }
        if url.scheme == "about" || url.host == "127.0.0.1" { return decisionHandler(.allow) }
        NSWorkspace.shared.open(url)       // anything external goes to the default browser
        decisionHandler(.cancel)
    }

    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK"); a.runModal(); completionHandler()
    }
    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK"); a.addButton(withTitle: "Cancel")
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    func windowWillClose(_ notification: Notification) {
        stopServer()
        onClose?(self)
    }
}

// MARK: - Welcome window

final class DropView: NSView {
    var onDrop: (([URL]) -> Void)?
    var highlighted = false { didSet { needsDisplay = true } }
    override init(frame: NSRect) { super.init(frame: frame); registerForDraggedTypes([.fileURL]) }
    required init?(coder: NSCoder) { fatalError("not used") }
    override func draggingEntered(_ s: NSDraggingInfo) -> NSDragOperation { highlighted = true; return .copy }
    override func draggingExited(_ s: NSDraggingInfo?) { highlighted = false }
    override func performDragOperation(_ s: NSDraggingInfo) -> Bool {
        highlighted = false
        let urls = s.draggingPasteboard.readObjects(forClasses: [NSURL.self], options: [.urlReadingFileURLsOnly: true]) as? [URL] ?? []
        if urls.isEmpty { return false }
        onDrop?(urls)
        return true
    }
    override func draw(_ dirtyRect: NSRect) {
        if highlighted {
            NSColor.controlAccentColor.withAlphaComponent(0.12).setFill()
            bounds.fill()
            let p = NSBezierPath(roundedRect: bounds.insetBy(dx: 14, dy: 14), xRadius: 16, yRadius: 16)
            p.lineWidth = 2
            NSColor.controlAccentColor.setStroke()
            p.setLineDash([8, 6], count: 2, phase: 0)
            p.stroke()
        }
    }
}

final class WelcomeWindowController: NSWindowController {
    var onOpenRequest: (() -> Void)?
    var onDrop: (([URL]) -> Void)?
    var onRecent: ((URL) -> Void)?
    private let recentStack = NSStackView()

    init() {
        let win = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 520, height: 430),
                           styleMask: [.titled, .closable, .miniaturizable, .fullSizeContentView],
                           backing: .buffered, defer: false)
        win.titlebarAppearsTransparent = true
        win.titleVisibility = .hidden
        win.isMovableByWindowBackground = true
        win.center()
        win.setFrameAutosaveName("ErebusWelcome")
        super.init(window: win)

        let drop = DropView(frame: win.contentView!.bounds)
        drop.autoresizingMask = [.width, .height]
        drop.onDrop = { [weak self] urls in self?.onDrop?(urls) }
        win.contentView = drop

        let icon = NSImageView(image: NSApp.applicationIconImage)
        icon.imageScaling = .scaleProportionallyUpOrDown
        icon.widthAnchor.constraint(equalToConstant: 96).isActive = true
        icon.heightAnchor.constraint(equalToConstant: 96).isActive = true
        let title = NSTextField(labelWithString: "Erebus")
        title.font = .systemFont(ofSize: 30, weight: .bold)
        let sub = NSTextField(labelWithString: "Open-source disassembler & decompiler")
        sub.font = .systemFont(ofSize: 13)
        sub.textColor = .secondaryLabelColor
        let hint = NSTextField(labelWithString: "Drop a binary anywhere in this window")
        hint.font = .systemFont(ofSize: 12)
        hint.textColor = .tertiaryLabelColor
        let open = NSButton(title: "Open Binary…", target: self, action: #selector(openTapped))
        open.bezelStyle = .rounded
        open.controlSize = .large
        open.keyEquivalent = "\r"
        let recentLabel = NSTextField(labelWithString: "Recent")
        recentLabel.font = .systemFont(ofSize: 11, weight: .semibold)
        recentLabel.textColor = .secondaryLabelColor
        recentStack.orientation = .vertical
        recentStack.alignment = .centerX
        recentStack.spacing = 2

        let stack = NSStackView(views: [icon, title, sub, open, hint, recentLabel, recentStack])
        stack.orientation = .vertical
        stack.alignment = .centerX
        stack.spacing = 8
        stack.setCustomSpacing(2, after: title)
        stack.setCustomSpacing(18, after: sub)
        stack.setCustomSpacing(18, after: hint)
        stack.translatesAutoresizingMaskIntoConstraints = false
        drop.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: drop.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: drop.centerYAnchor, constant: 6),
        ])
        refreshRecents()
    }
    required init?(coder: NSCoder) { fatalError("not used") }

    @objc private func openTapped() { onOpenRequest?() }
    @objc private func recentTapped(_ b: NSButton) {
        if let path = b.toolTip { onRecent?(URL(fileURLWithPath: path)) }
    }

    func refreshRecents() {
        recentStack.arrangedSubviews.forEach { recentStack.removeArrangedSubview($0); $0.removeFromSuperview() }
        let urls = Array(NSDocumentController.shared.recentDocumentURLs.prefix(5))
        if urls.isEmpty {
            let l = NSTextField(labelWithString: "Nothing yet")
            l.font = .systemFont(ofSize: 12); l.textColor = .tertiaryLabelColor
            recentStack.addArrangedSubview(l)
        }
        for u in urls {
            let b = NSButton(title: u.lastPathComponent, target: self, action: #selector(recentTapped(_:)))
            b.isBordered = false
            b.contentTintColor = .controlAccentColor
            b.toolTip = u.path
            recentStack.addArrangedSubview(b)
        }
    }
}

// MARK: - App delegate

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var documents: [DocumentWindowController] = []
    private var welcome: WelcomeWindowController?
    private let recentMenu = NSMenu(title: "Open Recent")
    private var launchedWithFiles = false

    func applicationDidFinishLaunching(_ n: Notification) {
        NSApp.setActivationPolicy(.regular)
        buildMenu()
        if Engine.binary == nil {
            let a = NSAlert()
            a.messageText = "Erebus engine missing"
            a.informativeText = "This app bundle does not contain the erebus command-line engine. Rebuild with scripts/build-app.sh."
            a.runModal()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { [weak self] in
            guard let self = self, !self.launchedWithFiles, self.documents.isEmpty else { return }
            self.showWelcome()
        }
        NSApp.activate(ignoringOtherApps: true)
    }

    func application(_ sender: NSApplication, openFiles filenames: [String]) {
        launchedWithFiles = true
        for f in filenames { open(URL(fileURLWithPath: f)) }
        sender.reply(toOpenOrPrint: .success)
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !flag && documents.isEmpty { showWelcome() }
        return true
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationWillTerminate(_ n: Notification) { documents.forEach { $0.stopServer() } }

    // MARK: opening

    func showWelcome() {
        if welcome == nil {
            let w = WelcomeWindowController()
            w.onOpenRequest = { [weak self] in self?.openPanel() }
            w.onDrop = { [weak self] urls in urls.forEach { self?.open($0) } }
            w.onRecent = { [weak self] u in self?.open(u) }
            welcome = w
        }
        welcome?.refreshRecents()
        welcome?.showWindow(nil)
        welcome?.window?.makeKeyAndOrderFront(nil)
    }

    @objc func openPanel() {
        let p = NSOpenPanel()
        p.canChooseFiles = true
        p.canChooseDirectories = false
        p.allowsMultipleSelection = true
        p.message = "Choose a binary (Mach-O, ELF, PE) or an Erebus database"
        if p.runModal() == .OK { p.urls.forEach { open($0) } }
    }

    func open(_ url: URL) {
        // already open? bring it to front
        if let existing = documents.first(where: { $0.source == url }) {
            existing.showWindow(nil); existing.window?.makeKeyAndOrderFront(nil); return
        }
        var arch: String? = nil
        if url.pathExtension.lowercased() != "erdb" {
            let archs = Engine.fatArchitectures(url)
            if !archs.isEmpty {
                let a = NSAlert()
                a.messageText = "\(url.lastPathComponent) contains several architectures"
                a.informativeText = "Choose the slice to analyse."
                let popup = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 220, height: 26))
                popup.addItems(withTitles: archs)
                a.accessoryView = popup
                a.addButton(withTitle: "Open")
                a.addButton(withTitle: "Cancel")
                if a.runModal() != .alertFirstButtonReturn { return }
                arch = popup.titleOfSelectedItem
            }
        }
        NSDocumentController.shared.noteNewRecentDocumentURL(url)
        let dc = DocumentWindowController(source: url, arch: arch)
        dc.onClose = { [weak self] c in
            self?.documents.removeAll { $0 === c }
        }
        documents.append(dc)
        welcome?.close()
        dc.showWindow(nil)
        dc.window?.center()
        dc.window?.makeKeyAndOrderFront(nil)
        dc.start()
    }

    private var frontDocument: DocumentWindowController? {
        documents.first { $0.window === NSApp.keyWindow } ?? documents.last
    }

    // MARK: menu actions

    @objc func reanalyze() { frontDocument?.reanalyze() }
    @objc func reloadPage() { frontDocument?.reload() }
    @objc func zoomIn() { frontDocument?.zoom(0.1) }
    @objc func zoomOut() { frontDocument?.zoom(-0.1) }
    @objc func zoomReset() { frontDocument?.zoom(nil) }
    @objc func revealDatabase() {
        if let db = frontDocument?.databaseURL { NSWorkspace.shared.activateFileViewerSelecting([db]) }
    }
    @objc func openGitHub() { NSWorkspace.shared.open(Engine.githubURL) }
    @objc func openReportIssue() { NSWorkspace.shared.open(Engine.githubURL.appendingPathComponent("issues/new/choose")) }
    @objc func openRecent(_ item: NSMenuItem) { if let u = item.representedObject as? URL { open(u) } }
    @objc func clearRecents() { NSDocumentController.shared.clearRecentDocuments(nil); welcome?.refreshRecents() }
    @objc func showAbout() {
        let credits = NSMutableAttributedString(string: "Open-source disassembler, analysis database and decompiler.\nMIT License · github.com/blazfxx/erebus\nEngine \(Engine.version)",
                                                attributes: [.font: NSFont.systemFont(ofSize: 11), .foregroundColor: NSColor.secondaryLabelColor])
        NSApp.orderFrontStandardAboutPanel(options: [.credits: credits, .applicationName: "Erebus"])
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        guard menu === recentMenu else { return }
        menu.removeAllItems()
        let urls = NSDocumentController.shared.recentDocumentURLs
        for u in urls.prefix(10) {
            let it = NSMenuItem(title: u.lastPathComponent, action: #selector(openRecent(_:)), keyEquivalent: "")
            it.representedObject = u
            it.target = self
            menu.addItem(it)
        }
        if !urls.isEmpty { menu.addItem(.separator()) }
        let clear = NSMenuItem(title: "Clear Menu", action: #selector(clearRecents), keyEquivalent: "")
        clear.target = self
        menu.addItem(clear)
    }

    // MARK: menu bar

    private func buildMenu() {
        let main = NSMenu()
        func add(_ title: String, to menu: NSMenu, action: Selector?, key: String = "", mods: NSEvent.ModifierFlags = .command, target: AnyObject? = nil) {
            let it = NSMenuItem(title: title, action: action, keyEquivalent: key)
            it.keyEquivalentModifierMask = mods
            it.target = target
            menu.addItem(it)
        }
        func submenu(_ title: String) -> NSMenu {
            let m = NSMenu(title: title)
            let it = NSMenuItem(title: title, action: nil, keyEquivalent: "")
            it.submenu = m
            main.addItem(it)
            return m
        }

        let app = submenu("Erebus")
        add("About Erebus", to: app, action: #selector(showAbout), target: self)
        app.addItem(.separator())
        add("Hide Erebus", to: app, action: #selector(NSApplication.hide(_:)), key: "h")
        add("Hide Others", to: app, action: #selector(NSApplication.hideOtherApplications(_:)), key: "h", mods: [.command, .option])
        app.addItem(.separator())
        add("Quit Erebus", to: app, action: #selector(NSApplication.terminate(_:)), key: "q")

        let file = submenu("File")
        add("Open…", to: file, action: #selector(openPanel), key: "o", target: self)
        let recentItem = NSMenuItem(title: "Open Recent", action: nil, keyEquivalent: "")
        recentMenu.delegate = self
        recentItem.submenu = recentMenu
        file.addItem(recentItem)
        file.addItem(.separator())
        add("Re-analyse", to: file, action: #selector(reanalyze), key: "r", mods: [.command, .shift], target: self)
        add("Reveal Database in Finder", to: file, action: #selector(revealDatabase), target: self)
        file.addItem(.separator())
        add("Close Window", to: file, action: #selector(NSWindow.performClose(_:)), key: "w")

        let edit = submenu("Edit")
        add("Cut", to: edit, action: #selector(NSText.cut(_:)), key: "x")
        add("Copy", to: edit, action: #selector(NSText.copy(_:)), key: "c")
        add("Paste", to: edit, action: #selector(NSText.paste(_:)), key: "v")
        add("Select All", to: edit, action: #selector(NSText.selectAll(_:)), key: "a")

        let view = submenu("View")
        add("Reload", to: view, action: #selector(reloadPage), key: "r", target: self)
        view.addItem(.separator())
        add("Zoom In", to: view, action: #selector(zoomIn), key: "+", target: self)
        add("Zoom Out", to: view, action: #selector(zoomOut), key: "-", target: self)
        add("Actual Size", to: view, action: #selector(zoomReset), key: "0", target: self)
        view.addItem(.separator())
        add("Enter Full Screen", to: view, action: #selector(NSWindow.toggleFullScreen(_:)), key: "f", mods: [.command, .control])

        let window = submenu("Window")
        add("Minimize", to: window, action: #selector(NSWindow.performMiniaturize(_:)), key: "m")
        add("Zoom", to: window, action: #selector(NSWindow.performZoom(_:)))
        NSApp.windowsMenu = window

        let help = submenu("Help")
        add("Erebus on GitHub", to: help, action: #selector(openGitHub), target: self)
        add("Report an Issue…", to: help, action: #selector(openReportIssue), target: self)
        NSApp.helpMenu = help

        NSApp.mainMenu = main
    }
}

// MARK: - entry point

let delegate = AppDelegate()
NSApplication.shared.delegate = delegate
NSApplication.shared.run()
