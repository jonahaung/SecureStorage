# SecureStorage

## Usage

You just need to set a password to make it work.

Replace the following code:

```swift
UserDefaults.standard
```

by this one:

```swift
let defaults = SecureStorage.shared
// Ensures that a password has not already been set. 
// Setting a password multiple times will cause the key to be regenerated, 
// resulting in the loss of any previously encrypted data.
if !defaults.isKeyCreated {
    defaults.password = NSUUID().uuidString // Or any password you wish
}
```

To use the app and keychain groups:

```swift
let defaults = SecureStorage(suiteName: "app.group") // Sets a shared app group
defaults.keychainAccessGroup = "keychain.group" // Sets a shrared keychain group 
if !defaults.isKeyCreated {
    defaults.password = NSUUID().uuidString // Or any password you wish
}
```

`SecureStorage` is not able to catch that any particular data is encrypted, to obtain a raw value, use the following method:

```swift
public func rawObject(forKey defaultName: String) -> Any?
```

## Installation

### [Swift Package Manager](https://github.com/apple/swift-package-manager)
