// swift-tools-version: 6.0

import AppleProductTypes
import PackageDescription

let package = Package(
    name: "RemoteDavinciController",
    platforms: [.iOS("17.0")],
    products: [
        .iOSApplication(
            name: "Remote DaVinci",
            targets: ["Controller"],
            bundleIdentifier: "dev.remote-davinci.controller",
            displayVersion: "0.1.0",
            bundleVersion: "1",
            supportedDeviceFamilies: [.phone, .pad],
            supportedInterfaceOrientations: [
                .portrait,
                .landscapeRight,
                .landscapeLeft,
                .portraitUpsideDown(.when(deviceFamilies: [.pad])),
            ],
            additionalInfoPlistContentFilePath: "AdditionalInfo.plist"
        ),
    ],
    targets: [
        .executableTarget(
            name: "Controller",
            dependencies: ["ControllerCore"],
            path: "Sources/Controller"
        ),
        .target(name: "ControllerCore", path: "Sources/ControllerCore"),
        .testTarget(name: "ControllerTests", dependencies: ["ControllerCore"]),
    ],
    swiftLanguageModes: [.v6]
)
