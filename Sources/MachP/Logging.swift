import Logging

struct LoggerFactory {
    static func setup(debug: Bool) {
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = debug ? .debug : .info
            return handler
        }
    }

    static func make(_ label: String) -> Logger {
        return Logger(label: label)
    }
}
