import BIP32
import Base58
import CryptoCore

public protocol CoinType {
    var id     :UInt32 { get }
    var symbol :String { get }
    
    func address(for privateKey: ExtendedKey, addressPrefix: String, using keyDerivator: KeyDerivator.Type) throws -> String
}

extension CoinType {
    public var index: KeyIndex { .hardened(id) }
}

public struct AnyCoinType: CoinType {
    public let symbol :String
    public let id     :UInt32
    
    public init(symbol: String, id: UInt32) {
        self.symbol = symbol
        self.id = id
    }
    
    public func address(for privateKey: ExtendedKey, addressPrefix: String = "", using keyDerivator: KeyDerivator.Type = DefaultKeyDerivator.self) throws -> String {
        switch symbol {
        case "eth", "ETH":
            return try keyDerivator
                .secp256k_1(data: privateKey.key.dropFirst(), compressed: false)
                .map { "0x" + $0.dropFirst().keccak256.suffix(20).hexString }
                .get()
        case "atom", "ATOM":
            let ripemd160 = try keyDerivator.hash160(data: privateKey.key).get()
            return try SegwitAddrCoder().encode2(hrp: addressPrefix, program: ripemd160)
        default:
            return privateKey.key.hexString
        }
    }
    
    public enum Error: Swift.Error {
        case badAddress
    }
}

extension AnyCoinType {
    public static var ETH :AnyCoinType { AnyCoinType(symbol: "ETH", id: 60) }
    public static var BTC :AnyCoinType { AnyCoinType(symbol: "BTC", id: 00) }
    public static var ATOM :AnyCoinType { AnyCoinType(symbol: "ATOM", id: 118) }
    
    public static var TestNet :some CoinType { AnyCoinType(symbol: "", id: 01) }
}
