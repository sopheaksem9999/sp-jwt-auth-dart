/// Authentication error codes matching backend error taxonomy.
enum SpAuthErrorCode {
  unauthenticated,
  forbidden,
  invalidToken,
  tokenExpired,
  refreshReuseDetected,
  csrfFailed,
  storageError,
  network,
  timeout,
  unknown,
}

/// Authentication error thrown by `sp_jwt_auth`.
class SpAuthError implements Exception {
  final SpAuthErrorCode code;
  final String message;
  final int? status;
  final int? errorCode;
  final String? requestId;
  final Object? cause;

  const SpAuthError({
    required this.code,
    required this.message,
    this.status,
    this.errorCode,
    this.requestId,
    this.cause,
  });

  @override
  String toString() {
    final details = <String>[];
    if (status != null) details.add('status: $status');
    if (errorCode != null) details.add('error_code: $errorCode');
    if (requestId != null) details.add('request_id: $requestId');
    final suffix = details.isEmpty ? '' : ' [${details.join(', ')}]';
    return 'SpAuthError(${code.name}): $message$suffix';
  }
}
