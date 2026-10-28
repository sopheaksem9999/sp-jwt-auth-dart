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
  String? _channel;

  static String? _defaultChallengeIdFrom(dynamic body) {
    if (body is! Map) return null;
    final data = body['data'];
    final raw = body['otp_id'] ?? (data is Map ? data['otp_id'] : null);
    final id = raw?.toString();
    return (id == null || id.isEmpty) ? null : id;
  }

  Map<String, dynamic> _sendBody(
    String identifier,
    String? channel,
    String purpose,
  ) =>
      auth.otpOptions.sendBody?.call(identifier, channel) ??
      {
        'destination': identifier,
        if (channel != null) 'channel': channel,
        'purpose': purpose,
      };

  Future<void> _post(
    String path,
    Map<String, dynamic> body, {
    required bool keepPreviousId,
  }) async {
    final response = await auth.send(
      'POST',
      auth.endpointUri(path).toString(),
      data: body,
      options: Options(headers: {'Accept': 'application/json'}),
    );
    throwIfEnvelopeFailure(response.data);
    final capture = auth.otpOptions.challengeIdFrom ?? _defaultChallengeIdFrom;
    final id = capture(response.data);
    _challengeId = keepPreviousId ? (id ?? _challengeId) : id;
  }

  /// Requests an OTP to be sent to the given [identifier] via optional
  /// [channel] (`email` or `sms`) for [purpose] (default `login`).
  Future<void> sendOtp({
    required String identifier,
    String? channel,
    String purpose = 'login',
  }) async {
    await _post(
      auth.endpoints.otpSend,
      _sendBody(identifier, channel, purpose),
      keepPreviousId: false,
    );
    _channel = channel;
  }

  /// Requests the OTP for [identifier] to be sent again.
  ///
  /// Uses the challenge id and channel of the last [sendOtp]. Throws
  /// [StateError] when `Endpoints.otpResend` is null, or when the default body
  /// is used and no challenge id has been captured yet.
  Future<void> resendOtp({required String identifier}) async {
    final path = auth.endpoints.otpResend;
    if (path == null) {
      throw StateError('Endpoints.otpResend is not configured');
    }
    final builder = auth.otpOptions.sendBody;
    final Map<String, dynamic> body;
    if (builder != null) {
      body = builder(identifier, _channel);
    } else {
      final id = _challengeId;
      if (id == null) {
        throw StateError('No OTP challenge to resend; call sendOtp first');
      }
      body = {
        'otp_id': id,
        'destination': identifier,
        if (_channel != null) 'channel': _channel,
      };
    }
    await _post(path, body, keepPreviousId: true);
  }

  /// Verifies an OTP [code] for [identifier], storing the resulting session on success.
  Future<LoginResult> verifyOtp({
    required String identifier,
    required String code,
  }) async {
    final uri = auth.endpointUri(auth.endpoints.otpVerify);
    final response = await auth.send(
      'POST',
      uri.toString(),
      data:
          auth.otpOptions.verifyBody?.call(identifier, code, _challengeId) ??
          {
            if (_challengeId != null) 'otp_id': _challengeId,
            'code': code,
            'destination': identifier,
            if (_channel != null) 'channel': _channel,
          },
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
    _challengeId = null;
    _channel = null;
    await auth.restore();
    return AuthenticatedResult(session);
  }
}
