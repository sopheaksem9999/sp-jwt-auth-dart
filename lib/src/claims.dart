import 'dart:convert';
import 'errors.dart';

/// Parsed JWT claims representation.
class JwtClaims {
  final Map<String, dynamic> raw;
  final String? sub;
  final DateTime? exp;
  final List<String> scopes;
  final String? sid;
  final String? companyId;

  const JwtClaims({
    required this.raw,
    this.sub,
    this.exp,
    this.scopes = const [],
    this.sid,
    this.companyId,
  });

  /// Parse claims from an encoded JWT string.
  ///
  /// This parses and extracts payload claims; it does not perform cryptographic signature verification.
  static JwtClaims parse(String token, {String companyClaim = 'company_id'}) {
    final parts = token.trim().split('.');
    if (parts.length != 3) {
      throw const SpAuthError(
        code: SpAuthErrorCode.invalidToken,
        message: 'Invalid JWT format: expected 3 dot-separated parts.',
      );
    }

    try {
      final payloadRaw = parts[1];
      // Normalize base64url padding
      var normalized = payloadRaw.replaceAll('-', '+').replaceAll('_', '/');
      final remainder = normalized.length % 4;
      if (remainder > 0) {
        normalized = normalized.padRight(normalized.length + (4 - remainder), '=');
      }

      final jsonString = utf8.decode(base64.decode(normalized));
      final decoded = json.decode(jsonString);
      if (decoded is! Map<String, dynamic>) {
        throw const FormatException('JWT payload is not a JSON object');
      }

      final sub = decoded['sub']?.toString();

      DateTime? exp;
      final expVal = decoded['exp'];
      if (expVal is int) {
        exp = DateTime.fromMillisecondsSinceEpoch(expVal * 1000, isUtc: true);
      } else if (expVal is num) {
        exp = DateTime.fromMillisecondsSinceEpoch((expVal * 1000).toInt(), isUtc: true);
      }

      final scopes = <String>[];
      final scopesVal = decoded['scopes'] ?? decoded['scope'];
      if (scopesVal is List) {
        scopes.addAll(scopesVal.map((e) => e.toString()));
      } else if (scopesVal is String) {
        scopes.addAll(scopesVal.split(' ').where((s) => s.isNotEmpty));
      }

      final sid = decoded['sid']?.toString();
      final companyId = decoded[companyClaim]?.toString();

      return JwtClaims(
        raw: decoded,
        sub: sub,
        exp: exp,
        scopes: scopes,
        sid: sid,
        companyId: companyId,
      );
    } catch (e) {
      if (e is SpAuthError) rethrow;
      throw SpAuthError(
        code: SpAuthErrorCode.invalidToken,
        message: 'Failed to decode JWT payload: $e',
        cause: e,
      );
    }
  }
}
