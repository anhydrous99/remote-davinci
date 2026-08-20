import Foundation

enum ProtocolJSON {
    static let maximumSafeInteger: Int64 = 9_007_199_254_740_991
    private static let maximumNumberBytes = 128
    private static let maximumNumberExponent = 4_096

    static func object(_ data: Data) -> [String: Any]? {
        let numberMarker = "__remote_davinci_number_\(UUID().uuidString)__"
        guard let markedData = markingNumbers(in: data, with: numberMarker),
              let value = try? JSONDecoder().decode(Value.self, from: markedData),
              case let .object(object) = value
        else {
            return nil
        }
        return object.mapValues { $0.any(numberMarker: numberMarker) }
    }

    private static func markingNumbers(in data: Data, with marker: String) -> Data? {
        let input = [UInt8](data)
        let marker = [UInt8](marker.utf8)
        var output = [UInt8]()
        output.reserveCapacity(input.count)
        var index = 0
        var inString = false
        var escaped = false

        while index < input.count {
            let byte = input[index]
            if inString {
                output.append(byte)
                if escaped {
                    escaped = false
                } else if byte == 0x5c {
                    escaped = true
                } else if byte == 0x22 {
                    inString = false
                }
                index += 1
                continue
            }
            if byte == 0x22 {
                inString = true
                output.append(byte)
                index += 1
                continue
            }
            if (byte == 0x2d || (0x30...0x39).contains(byte)),
               let end = numberEnd(in: input, from: index)
            {
                guard numberWithinLimits(in: input, from: index, to: end) else { return nil }
                output.append(0x22)
                output.append(contentsOf: marker)
                output.append(contentsOf: input[index..<end])
                output.append(0x22)
                index = end
                continue
            }
            output.append(byte)
            index += 1
        }
        return Data(output)
    }

    private static func numberWithinLimits(
        in input: [UInt8],
        from start: Int,
        to end: Int
    ) -> Bool {
        guard end - start <= maximumNumberBytes else { return false }
        guard let marker = input[start..<end].firstIndex(where: { $0 == 0x65 || $0 == 0x45 }) else {
            return true
        }
        var index = marker + 1
        if index < end, input[index] == 0x2b || input[index] == 0x2d { index += 1 }
        var exponent = 0
        while index < end {
            exponent = exponent * 10 + Int(input[index] - 0x30)
            if exponent > maximumNumberExponent { return false }
            index += 1
        }
        return true
    }

    private static func numberEnd(in input: [UInt8], from start: Int) -> Int? {
        var index = start
        if input[index] == 0x2d {
            index += 1
            guard index < input.count else { return nil }
        }
        if input[index] == 0x30 {
            index += 1
        } else {
            guard (0x31...0x39).contains(input[index]) else { return nil }
            repeat { index += 1 } while index < input.count && (0x30...0x39).contains(input[index])
        }
        if index < input.count, input[index] == 0x2e {
            let fractionStart = index + 1
            guard fractionStart < input.count, (0x30...0x39).contains(input[fractionStart]) else {
                return index
            }
            index = fractionStart
            repeat { index += 1 } while index < input.count && (0x30...0x39).contains(input[index])
        }
        if index < input.count, input[index] == 0x65 || input[index] == 0x45 {
            let exponentStart = index
            index += 1
            if index < input.count, input[index] == 0x2b || input[index] == 0x2d {
                index += 1
            }
            guard index < input.count, (0x30...0x39).contains(input[index]) else {
                return exponentStart
            }
            repeat { index += 1 } while index < input.count && (0x30...0x39).contains(input[index])
        }
        return index
    }

    private indirect enum Value: Decodable {
        case object([String: Value])
        case array([Value])
        case string(String)
        case number(Decimal)
        case bool(Bool)
        case null

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if container.decodeNil() {
                self = .null
            } else if let value = try? container.decode([String: Value].self) {
                self = .object(value)
            } else if let value = try? container.decode([Value].self) {
                self = .array(value)
            } else if let value = try? container.decode(String.self) {
                self = .string(value)
            } else if let value = try? container.decode(Bool.self) {
                self = .bool(value)
            } else if let value = try? container.decode(Decimal.self) {
                self = .number(value)
            } else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Unsupported JSON value"
                )
            }
        }

        func any(numberMarker: String) -> Any {
            switch self {
            case let .object(value): value.mapValues { $0.any(numberMarker: numberMarker) }
            case let .array(value): value.map { $0.any(numberMarker: numberMarker) }
            case let .string(value) where value.hasPrefix(numberMarker):
                JSONNumberLiteral(String(value.dropFirst(numberMarker.count)))
            case let .string(value): value
            case let .number(value): value
            case let .bool(value): value
            case .null: NSNull()
            }
        }
    }
}

private struct JSONNumberLiteral {
    let value: String

    init(_ value: String) {
        self.value = value
    }

    func exactSafeInt64() -> Int64? {
        let bytes = [UInt8](value.utf8)
        guard !bytes.isEmpty else { return nil }
        var index = 0
        let negative = bytes[index] == 0x2d
        if negative { index += 1 }

        let exponentIndex = bytes[index...].firstIndex { $0 == 0x65 || $0 == 0x45 } ?? bytes.endIndex
        var digits = [UInt8]()
        var fractionalDigits = 0
        var afterDecimal = false
        for byte in bytes[index..<exponentIndex] {
            if byte == 0x2e {
                afterDecimal = true
            } else {
                digits.append(byte - 0x30)
                if afterDecimal { fractionalDigits += 1 }
            }
        }

        guard let firstNonzero = digits.firstIndex(where: { $0 != 0 }) else { return 0 }
        digits.removeFirst(firstNonzero)

        var exponent = 0
        if exponentIndex < bytes.endIndex {
            index = exponentIndex + 1
            let exponentNegative = index < bytes.endIndex && bytes[index] == 0x2d
            if exponentNegative || (index < bytes.endIndex && bytes[index] == 0x2b) { index += 1 }
            let limit = bytes.count + 32
            while index < bytes.endIndex {
                if exponent < limit {
                    exponent = min(limit, exponent * 10 + Int(bytes[index] - 0x30))
                }
                index += 1
            }
            if exponentNegative { exponent = -exponent }
        }

        let scale = fractionalDigits - exponent
        if scale > 0 {
            guard scale <= digits.count, digits.suffix(scale).allSatisfy({ $0 == 0 }) else {
                return nil
            }
            digits.removeLast(scale)
        } else if scale < 0 {
            guard digits.count - scale <= 16 else { return nil }
            digits.append(contentsOf: repeatElement(0, count: -scale))
        }
        guard !digits.isEmpty else { return 0 }

        let maximum = [UInt8](String(ProtocolJSON.maximumSafeInteger).utf8).map { $0 - 0x30 }
        guard digits.count < maximum.count ||
            (digits.count == maximum.count && !maximum.lexicographicallyPrecedes(digits))
        else {
            return nil
        }
        var result: Int64 = 0
        for digit in digits { result = result * 10 + Int64(digit) }
        return negative ? -result : result
    }
}

func jsonInt64(_ value: Any?) -> Int64? {
    if let value = value as? JSONNumberLiteral {
        return value.exactSafeInt64()
    }
    let decimal: Decimal
    if let value = value as? Decimal {
        decimal = value
    } else if let number = value as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
    {
        decimal = number.decimalValue
    } else {
        return nil
    }

    let limit = Decimal(ProtocolJSON.maximumSafeInteger)
    guard decimal >= -limit, decimal <= limit else { return nil }
    let integer = NSDecimalNumber(decimal: decimal).int64Value
    return Decimal(integer) == decimal ? integer : nil
}

func jsonBool(_ value: Any?) -> Bool? {
    if let value = value as? Bool { return value }
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID()
    else {
        return nil
    }
    return number.boolValue
}

func isCanonicalUUID(_ value: String) -> Bool {
    UUID(uuidString: value)?.uuidString.lowercased() == value
}

func validDeviceLabel(_ value: String) -> Bool {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard value == trimmed, (1...80).contains(value.unicodeScalars.count) else { return false }
    return value.unicodeScalars.allSatisfy { scalar in
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator:
            false
        default:
            true
        }
    }
}

struct RendezvousEnvelope {
    static let errorCodes = Set([
        "INVALID_MESSAGE", "UNSUPPORTED_VERSION", "UNAUTHENTICATED", "FORBIDDEN",
        "PAIR_UNAVAILABLE", "PAIR_FULL", "PAIR_EXPIRED", "PEER_OFFLINE", "PEER_BUSY",
        "SESSION_NOT_FOUND", "PAYLOAD_TOO_LARGE", "RATE_LIMITED", "CONFLICT", "INTERNAL",
    ])

    let type: String
    let id: String
    let replyTo: String?
    let body: [String: Any]

    init?(_ data: Data, allowedTypes: Set<String>) {
        guard data.count <= 32 * 1_024,
              let envelope = ProtocolJSON.object(data),
              envelope["protocol"] as? String == "remote-davinci.rendezvous",
              jsonInt64(envelope["v"]) == 1,
              let type = envelope["type"] as? String,
              allowedTypes.contains(type),
              let id = envelope["id"] as? String,
              isCanonicalUUID(id),
              let body = envelope["body"] as? [String: Any]
        else {
            return nil
        }

        let replyTo: String?
        if let rawReplyTo = envelope["replyTo"] {
            guard let value = rawReplyTo as? String, isCanonicalUUID(value) else { return nil }
            replyTo = value
        } else {
            replyTo = nil
        }
        guard (type == "ok" || type == "error") == (replyTo != nil) else { return nil }

        self.type = type
        self.id = id
        self.replyTo = replyTo
        self.body = body
    }
}
