import 'errors.dart';

/// One log line describing a single HTTP attempt made by `sp_jwt_auth`.
///
/// Privacy contract: this type has no field for headers, request or response
/// bodies, or query strings, and none may ever be added. Passwords, one-time
/// codes and tokens therefore cannot reach a logger.
class AuthLogEntry {
  /// Upper-case HTTP method, e.g. `POST`.
  final String method;

  /// Request path without the query string.
  final String path;

  /// HTTP status when a response was received.
  final int? status;

  /// Wall-clock time the attempt took.
  final Duration duration;

  /// Server request id from `X-Request-Id` or `meta.request_id`, when present.
  final String? requestId;

  /// 1-based attempt number within one logical call.
  final int attempt;

  /// Failure classification, `null` on success.
  final SpAuthErrorCode? code;

  /// Backend `error_code` from the response body, when present.
  final int? errorCode;

  /// Creates an entry.
  const AuthLogEntry({
    required this.method,
    required this.path,
    required this.duration,
    required this.attempt,
    this.status,
    this.requestId,
    this.code,
    this.errorCode,
  });

  @override
  String toString() {
    final b = StringBuffer('$method $path -> ');
    b.write(status ?? 'ERR');
    b.write(' ${duration.inMilliseconds}ms');
    if (requestId != null) b.write(' rid=$requestId');
    b.write(' attempt=$attempt');
    if (code != null) b.write(' code=${code!.name}');
    if (errorCode != null) b.write(' errorCode=$errorCode');
    return b.toString();
  }
}

/// Receives [AuthLogEntry] values. The sink is yours, e.g. `debugPrint`.
///
/// The sink is invoked synchronously and inline on the request path, so it
/// should return quickly (hand slow work off, do not await it).
class AuthLogger {
  /// Called once per HTTP attempt; errors thrown by it are swallowed.
  final void Function(AuthLogEntry entry) sink;

  /// Creates a logger delivering entries to [sink].
  const AuthLogger({required this.sink});
}
