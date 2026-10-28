import Foundation
import NetworkExtension

@main enum ExtensionMain {
    static func main() { NEProvider.startSystemExtensionMode(); dispatchMain() }
}
