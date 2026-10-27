import 'errors.dart';

/// Throws [SpAuthError] when [body] is a backend envelope with
/// `success == false`; returns normally for anything else.
void throwIfEnvelopeFailure(dynamic body) {
  if (body is! Map<String, dynamic> || body['success'] != false) return;
  final errorCode = body['error_code'];
  final meta = body['meta'];
  final requestId = meta is Map ? meta['request_id'] : null;
  throw SpAuthError(
    code: SpAuthErrorCode.unauthenticated,
    message: body['message']?.toString() ?? 'Request failed',
    errorCode: errorCode is int
        ? errorCode
        : (errorCode is String ? int.tryParse(errorCode) : null),
    requestId: requestId?.toString(),
  );
}
