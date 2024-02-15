import Foundation

final class KeychainManager {
    
    @discardableResult
    static func set(
        _ data: Data?,
        forKey key: String,
        group: String?,
        accessible: String
        ) -> Bool {
        guard let data = data else {
            var query = [
                kSecClass as String: kSecClassGenericPassword as String,
                kSecAttrAccessible as String: accessible,
                kSecAttrAccount as String: key
            ] as [String : Any]
            if let group = group {
                query[kSecAttrAccessGroup as String] = group
            }
            return (SecItemDelete(query as CFDictionary) == noErr)
        }
        var query = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrAccessible as String: accessible,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ] as [String : Any]
        if let group = group {
            query[kSecAttrAccessGroup as String] = group
        }
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        return status == noErr
    }
    
    @discardableResult
    static func get(
        forKey key: String,
        group: String?,
        accessible: String
        ) -> Data? {
        var query = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: accessible,
            kSecAttrAccount as String: key,
            kSecReturnData as String: kCFBooleanTrue as Any,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as [String : Any]
        if let group = group {
            query[kSecAttrAccessGroup as String] = group
        }
        var dataRef: AnyObject? = nil
        let status = SecItemCopyMatching(query as CFDictionary, &dataRef)
        if status == noErr {
            return dataRef as? Data
        }
        return nil
    }
    
    @discardableResult
    static func remove(forKey key: String, accessible: String) -> Bool {
        let query = [
            kSecClass as String: kSecClassGenericPassword as String,
            kSecAttrAccessible as String: accessible,
            kSecAttrAccount as String: key
        ] as [String : Any]
        return (SecItemDelete(query as CFDictionary) == noErr)
    }
}
