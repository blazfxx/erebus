// Generates the Erebus app icon (an .iconset directory) with CoreGraphics — no binary assets in the repo.
// usage: swift app/make_icon.swift <out.iconset>
import Cocoa

func render(size: Int) -> Data {
    let s = CGFloat(size)
    let cs = CGColorSpaceCreateDeviceRGB()
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    // macOS icon grid: art occupies ~80% of the canvas with a 22.4% corner radius
    let inset = s * 0.1
    let rect = CGRect(x: inset, y: inset, width: s - 2 * inset, height: s - 2 * inset)
    let radius = rect.width * 0.2237
    let path = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.012), blur: s * 0.03, color: CGColor(gray: 0, alpha: 0.45))
    ctx.addPath(path); ctx.setFillColor(CGColor(red: 0.07, green: 0.06, blue: 0.16, alpha: 1)); ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(path); ctx.clip()
    let grad = CGGradient(colorsSpace: cs, colors: [
        CGColor(red: 0.10, green: 0.08, blue: 0.27, alpha: 1),
        CGColor(red: 0.36, green: 0.22, blue: 0.86, alpha: 1)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(grad, start: CGPoint(x: rect.minX, y: rect.maxY), end: CGPoint(x: rect.maxX, y: rect.minY), options: [])
    // soft highlight
    let glow = CGGradient(colorsSpace: cs, colors: [CGColor(gray: 1, alpha: 0.18), CGColor(gray: 1, alpha: 0)] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(glow, startCenter: CGPoint(x: rect.midX, y: rect.maxY), startRadius: 0,
                           endCenter: CGPoint(x: rect.midX, y: rect.maxY), endRadius: rect.width * 0.8, options: [])

    // an "E" built from disassembly-listing bars: spine + three rows of instruction-like segments
    let w = rect.width, h = rect.height
    let x0 = rect.minX + w * 0.27, top = rect.minY + h * 0.76, rowH = h * 0.085, gap = h * 0.095
    func bar(_ x: CGFloat, _ y: CGFloat, _ len: CGFloat, _ color: CGColor) {
        let r = CGRect(x: x, y: y, width: len, height: rowH)
        ctx.addPath(CGPath(roundedRect: r, cornerWidth: rowH / 2, cornerHeight: rowH / 2, transform: nil))
        ctx.setFillColor(color); ctx.fillPath()
    }
    let white = CGColor(gray: 1, alpha: 0.96)
    let cyan = CGColor(red: 0.30, green: 0.88, blue: 0.95, alpha: 1)
    let violet = CGColor(red: 0.78, green: 0.62, blue: 1.0, alpha: 1)
    // spine
    let spine = CGRect(x: x0, y: top - 3 * gap - rowH + rowH * 0.0, width: rowH, height: 3 * gap + rowH)
    ctx.addPath(CGPath(roundedRect: spine, cornerWidth: rowH / 2, cornerHeight: rowH / 2, transform: nil))
    ctx.setFillColor(white); ctx.fillPath()
    // rows (top, middle, bottom of the E) with trailing "operand" segments
    bar(x0, top, w * 0.46, white);                      bar(x0 + w * 0.50, top, w * 0.07, cyan)
    bar(x0, top - 1.5 * gap, w * 0.34, white);          bar(x0 + w * 0.38, top - 1.5 * gap, w * 0.10, violet)
    bar(x0, top - 3 * gap, w * 0.46, white);            bar(x0 + w * 0.50, top - 3 * gap, w * 0.12, cyan)
    // a faint listing line under the E, like the next instruction
    bar(x0, top - 4.4 * gap, w * 0.18, CGColor(gray: 1, alpha: 0.35)); bar(x0 + w * 0.22, top - 4.4 * gap, w * 0.30, CGColor(gray: 1, alpha: 0.22))
    ctx.restoreGState()

    let img = ctx.makeImage()!
    let rep = NSBitmapImageRep(cgImage: img)
    return rep.representation(using: .png, properties: [:])!
}

guard CommandLine.arguments.count > 1 else { print("usage: make_icon.swift <out.iconset>"); exit(1) }
let out = URL(fileURLWithPath: CommandLine.arguments[1])
try? FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    try! render(size: base).write(to: out.appendingPathComponent("icon_\(base)x\(base).png"))
    try! render(size: base * 2).write(to: out.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
