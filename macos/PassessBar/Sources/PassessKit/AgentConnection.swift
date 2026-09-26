import Darwin
import Foundation

/// A connection to `passess agent` over its Unix socket: a one-byte preamble
/// (no descriptors), then one JSON object per line each way. The app uses it
/// only to answer questions; no value ever crosses it.
public final class AgentConnection {
    public enum Failure: Error, CustomStringConvertible {
        case notRunning
        case refused(String)
        case io(String)

        public var description: String {
            switch self {
            case .notRunning: return "the passess agent is not running"
            case let .refused(why): return why
            case let .io(why): return why
            }
        }
    }

    private let fd: Int32
    private var buffer = Data()
    private let writeLock = NSLock()
    private let closeLock = NSLock()
    private var closed = false

    public init(path: String) throws {
        var addr = sockaddr_un()
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
            throw Failure.io("the agent socket path is too long: \(path)")
        }
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.io(String(cString: strerror(errno))) }
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: bytes) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        if rc != 0 {
            let err = errno
            Darwin.close(fd)
            if err == ENOENT || err == ECONNREFUSED { throw Failure.notRunning }
            throw Failure.io(String(cString: strerror(err)))
        }
        var on: Int32 = 1 // a write after the agent left must not kill the app
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }

    // The descriptor is released only here, when no thread can be reading it:
    // close() from another thread shuts the socket down but leaves the number
    // taken, so a read in flight never lands on a reused descriptor.
    deinit {
        close()
        Darwin.close(fd)
    }

    /// Sends the request that opens the conversation.
    public func send(_ request: AgentRequest) throws {
        try writeAll(Data([0]))
        try write(request)
    }

    /// Sends one JSON line.
    public func write<T: Encodable>(_ value: T) throws {
        var data = try JSONEncoder().encode(value)
        data.append(0x0A)
        try writeAll(data)
    }

    /// Blocks until the next line arrives and decodes it.
    public func readFrame() throws -> AgentFrame {
        while true {
            if let newline = buffer.firstIndex(of: 0x0A) {
                let line = buffer[buffer.startIndex..<newline]
                buffer.removeSubrange(buffer.startIndex...newline)
                do {
                    return try AgentJSON.decoder.decode(AgentFrame.self, from: Data(line))
                } catch {
                    throw Failure.io("unreadable message from the agent: \(error)")
                }
            }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let n = Darwin.read(fd, &chunk, chunk.count)
            if n < 0 {
                if errno == EINTR { continue }
                throw Failure.io(String(cString: strerror(errno)))
            }
            if n == 0 { throw Failure.io("the agent closed the connection") }
            buffer.append(contentsOf: chunk[0..<n])
            if buffer.count > 1 << 20 { throw Failure.io("message from the agent too long") }
        }
    }

    /// Ends the conversation, from any thread; a read blocked on it returns.
    public func close() {
        closeLock.lock()
        defer { closeLock.unlock() }
        guard !closed else { return }
        closed = true
        shutdown(fd, SHUT_RDWR)
    }

    private func writeAll(_ data: Data) throws {
        writeLock.lock()
        defer { writeLock.unlock() }
        try data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) in
            guard let base = raw.baseAddress else { return }
            var offset = 0
            while offset < raw.count {
                let n = Darwin.write(fd, base + offset, raw.count - offset)
                if n < 0 {
                    if errno == EINTR { continue }
                    throw Failure.io(String(cString: strerror(errno)))
                }
                offset += n
            }
        }
    }
}
