import AppKit

// Draws the Passess.app icon at every size an .iconset wants: a white shield
// with a keyhole on a deep green squircle, the green of the menu bar's "All
// clear". Everything is a path, drawn afresh per size; no SF Symbols, whose
// license leaves out app icons.
//
//   swift run -c release --package-path macos/PassessBar IconMaker DIR/AppIcon.iconset
//   iconutil -c icns DIR/AppIcon.iconset -o macos/PassessBar/AppIcon.icns
//
// Coordinates are in a 1024-point canvas, y up, on Apple's icon grid: the
// body is the 824-point square at (100, 100).

func rgb(_ hex: UInt32, _ alpha: CGFloat = 1) -> CGColor {
    CGColor(srgbRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: alpha)
}

/// A superellipse, the continuous-corner shape of macOS icons.
func squircle(_ r: CGRect, exponent n: CGFloat = 5) -> CGPath {
    let path = CGMutablePath()
    let (cx, cy, a, b) = (r.midX, r.midY, r.width / 2, r.height / 2)
    let steps = 720
    for i in 0...steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi
        let (c, s) = (cos(t), sin(t))
        let x = cx + a * copysign(pow(abs(c), 2 / n), c)
        let y = cy + b * copysign(pow(abs(s), 2 / n), s)
        i == 0 ? path.move(to: CGPoint(x: x, y: y)) : path.addLine(to: CGPoint(x: x, y: y))
    }
    path.closeSubpath()
    return path
}

/// A shield in the box r: a top that rises to the middle, straight sides,
/// and a point at the bottom.
func shield(_ r: CGRect) -> CGPath {
    func p(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: r.minX + x * r.width, y: r.minY + y * r.height) }
    let path = CGMutablePath()
    path.move(to: p(0.5, 1))
    path.addCurve(to: p(1, 0.87), control1: p(0.7, 0.975), control2: p(0.87, 0.93))
    path.addLine(to: p(1, 0.55))
    path.addCurve(to: p(0.5, 0), control1: p(1, 0.26), control2: p(0.78, 0.09))
    path.addCurve(to: p(0, 0.55), control1: p(0.22, 0.09), control2: p(0, 0.26))
    path.addLine(to: p(0, 0.87))
    path.addCurve(to: p(0.5, 1), control1: p(0.13, 0.93), control2: p(0.3, 0.975))
    path.closeSubpath()
    return path
}

/// A keyhole: a round head over a slot that widens downward, as one shape.
func keyhole(center c: CGPoint, radius: CGFloat) -> CGPath {
    let head = CGPath(ellipseIn: CGRect(x: c.x - radius, y: c.y - radius, width: 2 * radius, height: 2 * radius), transform: nil)
    let slot = CGMutablePath()
    let top = c.y - radius * 0.3, bottom = c.y - radius * 2.2
    slot.move(to: CGPoint(x: c.x - radius * 0.38, y: top))
    slot.addLine(to: CGPoint(x: c.x + radius * 0.38, y: top))
    slot.addLine(to: CGPoint(x: c.x + radius * 0.6, y: bottom))
    slot.addLine(to: CGPoint(x: c.x - radius * 0.6, y: bottom))
    slot.closeSubpath()
    // Round the slot's corners: the slot plus a band around its edge.
    let rounded = slot.union(slot.copy(strokingWithWidth: radius * 0.2, lineCap: .round, lineJoin: .round, miterLimit: 1))
    return head.union(rounded)
}

func draw(_ ctx: CGContext, pixels: Int) {
    let small = pixels <= 32
    let body = squircle(CGRect(x: 100, y: 100, width: 824, height: 824))

    // The body, lifted off the page a little.
    ctx.saveGState()
    if !small { ctx.setShadow(offset: CGSize(width: 0, height: -10), blur: 24, color: rgb(0x000000, 0.32)) }
    ctx.addPath(body)
    ctx.setFillColor(rgb(0x14453B))
    ctx.fillPath()
    ctx.restoreGState()

    // A green that deepens downward, with light from above.
    ctx.saveGState()
    ctx.addPath(body)
    ctx.clip()
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let fill = CGGradient(colorsSpace: space, colors: [rgb(0x3FA58B), rgb(0x1E6B5A), rgb(0x0F3A32)] as CFArray,
                          locations: [0, 0.55, 1])!
    ctx.drawLinearGradient(fill, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
    let light = CGGradient(colorsSpace: space, colors: [rgb(0xFFFFFF, 0.22), rgb(0xFFFFFF, 0)] as CFArray, locations: [0, 1])!
    ctx.drawRadialGradient(light, startCenter: CGPoint(x: 400, y: 900), startRadius: 0,
                           endCenter: CGPoint(x: 400, y: 900), endRadius: 620, options: [])
    ctx.restoreGState()

    // A thin bright rim along the top edge.
    if !small {
        ctx.saveGState()
        ctx.addPath(body)
        ctx.clip()
        ctx.addPath(body)
        ctx.setLineWidth(6)
        let rim = CGGradient(colorsSpace: space, colors: [rgb(0xFFFFFF, 0.35), rgb(0xFFFFFF, 0)] as CFArray, locations: [0, 0.5])!
        ctx.replacePathWithStrokedPath()
        ctx.clip()
        ctx.drawLinearGradient(rim, start: CGPoint(x: 512, y: 924), end: CGPoint(x: 512, y: 100), options: [])
        ctx.restoreGState()
    }

    // The shield, white, with a keyhole through it. A transparency layer
    // gives the gradient-filled shape its shadow.
    let box = small ? CGRect(x: 262, y: 222, width: 500, height: 580) : CGRect(x: 292, y: 250, width: 440, height: 520)
    let hole = keyhole(center: CGPoint(x: 512, y: box.minY + box.height * 0.6), radius: box.width * (small ? 0.16 : 0.13))
    let guarded = shield(box).subtracting(hole)
    ctx.saveGState()
    if !small { ctx.setShadow(offset: CGSize(width: 0, height: -12), blur: 30, color: rgb(0x06221D, 0.45)) }
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    ctx.addPath(guarded)
    ctx.clip()
    let white = CGGradient(colorsSpace: space, colors: [rgb(0xFFFFFF), rgb(0xE3F4EE)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(white, start: CGPoint(x: 512, y: box.maxY), end: CGPoint(x: 512, y: box.minY), options: [])
    ctx.endTransparencyLayer()
    ctx.restoreGState()
}

func png(pixels: Int) -> Data {
    let space = CGColorSpace(name: CGColorSpace.sRGB)!
    let ctx = CGContext(data: nil, width: pixels, height: pixels, bitsPerComponent: 8, bytesPerRow: 0, space: space,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    ctx.interpolationQuality = .high
    ctx.setShouldAntialias(true)
    ctx.scaleBy(x: CGFloat(pixels) / 1024, y: CGFloat(pixels) / 1024)
    draw(ctx, pixels: pixels)
    return NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])!
}

let args = CommandLine.arguments
guard args.count == 2 else {
    FileHandle.standardError.write(Data("usage: IconMaker DIR/AppIcon.iconset\n".utf8))
    exit(64)
}
let dir = URL(fileURLWithPath: args[1])
try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
for points in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let name = scale == 1 ? "icon_\(points)x\(points).png" : "icon_\(points)x\(points)@2x.png"
        try png(pixels: points * scale).write(to: dir.appendingPathComponent(name))
    }
}
print(dir.path)
