import 'package:dio/dio.dart';
import '../auth_core.dart';
import '../envelope.dart';
import '../session.dart';

/// Module managing one-time password (OTP) delivery and verification.
class OtpModule {
  /// The underlying authentication client.
  final SpJwtAuth auth;

  /// Creates a new [OtpModule].
  OtpModule(this.auth);

  String? _challengeId;

  Map<String, dynamic> _sendBody(String identifier, String? channel) =>
      auth.otpOptions.sendBody?.call(identifier, channel) ??
      {'identifier': identifier, if (channel != null) 'channel': channel};

  Future<void> _post(String path, Map<String, dynamic> body) async {
    final response = await auth.dio.post<dynamic>(
      auth.endpointUri(path).toString(),
      data: body,
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final capture = auth.otpOptions.challengeIdFrom;
    if (capture != null) _challengeId = capture(response.data) ?? _challengeId;
  }

  /// Requests an OTP to be sent to the given [identifier] via optional [channel].
  Future<void> sendOtp({required String identifier, String? channel}) =>
      _post(auth.endpoints.otpSend, _sendBody(identifier, channel));

  /// Requests the OTP for [identifier] to be sent again.
  ///
  /// Throws [StateError] when `Endpoints.otpResend` is not configured.
  Future<void> resendOtp({required String identifier}) {
    final path = auth.endpoints.otpResend;
    if (path == null) {
      throw StateError('Endpoints.otpResend is not configured');
    }
    return _post(path, _sendBody(identifier, null));
  }

  /// Verifies an OTP [code] for [identifier], storing the resulting session on success.
  Future<LoginResult> verifyOtp({
    required String identifier,
    required String code,
  }) async {
    final uri = auth.endpointUri(auth.endpoints.otpVerify);
    final response = await auth.dio.post<dynamic>(
      uri.toString(),
      data:
          auth.otpOptions.verifyBody?.call(identifier, code, _challengeId) ??
          {'identifier': identifier, 'code': code},
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final data = response.data;
    if (data is Map<String, dynamic>) {
      final mfaRequired =
          data['mfa_required'] == true || data['requires_mfa'] == true;
      final challengeId = (data['challenge_id'] ?? data['challengeId'])
          ?.toString();
      if (mfaRequired && challengeId != null && challengeId.isNotEmpty) {
        return SecondFactorRequiredResult(challengeId);
      }
    }

    throwIfEnvelopeFailure(data);
    final session = auth.endpoints.parseSession(data);
    await auth.store.write(session);
    await auth.restore();
    return AuthenticatedResult(session);
  }
}
