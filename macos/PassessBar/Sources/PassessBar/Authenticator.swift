import Foundation
import LocalAuthentication

/// The user's Touch ID, or their password, before anything that decides who
/// gets a secret: an Allow, a connection, a change, a removal. An agent that
/// drives the screen can press the button but not the sensor.
enum Authenticator {
    /// Whether there is a Touch ID sensor to name on the button.
    static var hasTouchID: Bool {
        let context = LAContext()
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) && context.biometryType == .touchID
    }

    /// Calls done on the main thread with whether the user confirmed. A
    /// cancelled prompt is a no.
    static func confirm(_ reason: String, done: @escaping (Bool) -> Void) {
        LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) { ok, _ in
            DispatchQueue.main.async { done(ok) }
        }
    }
}
