import Foundation

extension Data {
    /// Calculates the Shannon entropy of the data.
    /// - Returns: Entropy value as a Double.
    func entropy() -> Double {
        guard !self.isEmpty else { return 0.0 }
        var frequencies = [Int](repeating: 0, count: 256)
        for byte in self {
            frequencies[Int(byte)] += 1
        }
        let length = Double(self.count)
        var entropy: Double = 0.0
        for count in frequencies where count > 0 {
            let p = Double(count) / length
            entropy -= p * log2(p)
        }
        return entropy
    }
}
