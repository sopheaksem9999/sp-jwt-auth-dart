import 'errors.dart';

/// Persistent session structure held in secure storage.
class StoredSession {
  final String accessToken;
  final String? refreshToken;
  final DateTime? expiresAt;
  final Map<String, dynamic>? user;

  const StoredSession({
    required this.accessToken,
    this.refreshToken,
    this.expiresAt,
    this.user,
  });

  /// Returns a copy with [user] replaced when given; other fields are kept.
  StoredSession copyWith({Map<String, dynamic>? user}) => StoredSession(
    accessToken: accessToken,
    refreshToken: refreshToken,
    expiresAt: expiresAt,
    user: user ?? this.user,
  );

  Map<String, dynamic> toJson() => {
    'access_token': accessToken,
    if (refreshToken != null) 'refresh_token': refreshToken,
    if (expiresAt != null) 'expires_at': expiresAt!.toIso8601String(),
    if (user != null) 'user': user,
  };

  factory StoredSession.fromJson(Map<String, dynamic> json) {
    DateTime? exp;
    final expRaw = json['expires_at'];
    if (expRaw is String) {
      exp = DateTime.tryParse(expRaw);
    } else if (expRaw is int) {
      exp = DateTime.fromMillisecondsSinceEpoch(expRaw * 1000, isUtc: true);
    }

    return StoredSession(
      accessToken:
          json['access_token'] as String? ??
          json['accessToken'] as String? ??
          '',
      refreshToken:
          json['refresh_token'] as String? ?? json['refreshToken'] as String?,
      expiresAt: exp,
      user: json['user'] as Map<String, dynamic>?,
    );
  }

  /// Parses a backend response body that is either a `{success, data: {...}}`
  /// envelope or a flat token object.
  ///
  /// `data` is unwrapped only when it is a [Map]. `expires_at` wins over
  /// `expires_in` (seconds, int/num/numeric string, must be positive). Throws
  /// [SpAuthError] when no non-empty access token is present.
  factory StoredSession.fromEnvelope(dynamic body, {DateTime Function()? now}) {
    Map<String, dynamic>? map;
    if (body is Map) {
      final data = body['data'];
      final source = data is Map ? data : body;
      map = Map<String, dynamic>.from(source);
    }
    final token = map == null
        ? null
        : (map['access_token'] ?? map['accessToken']);
    if (map == null || token is! String || token.isEmpty) {
      throw const SpAuthError(
        code: SpAuthErrorCode.unauthenticated,
        message: 'Response did not contain an access token',
      );
    }

    final base = StoredSession.fromJson(map);
    if (base.expiresAt != null) return base;

    final raw = map['expires_in'] ?? map['expiresIn'];
    final seconds = raw is num
        ? raw
        : (raw is String ? num.tryParse(raw.trim()) : null);
    if (seconds == null || !seconds.isFinite || seconds <= 0) return base;
    return StoredSession(
      accessToken: base.accessToken,
      refreshToken: base.refreshToken,
      expiresAt: (now ?? DateTime.now().toUtc)().add(
        Duration(milliseconds: (seconds * 1000).round()),
      ),
      user: base.user,
    );
  }
}

/// Abstract storage seam for persisting auth sessions.
abstract interface class TokenStore {
  /// Read the stored session, or return null if no session exists.
  ///
  /// Throwing indicates a transient platform or storage failure (e.g. keychain locked),
  /// and must not be interpreted as an empty session.
  Future<StoredSession?> read();

  /// Persist session atomically.
  Future<void> write(StoredSession session);

  /// Remove stored session.
  Future<void> clear();
}

/// In-memory implementation of [TokenStore] for tests and transient environments.
class MemoryTokenStore implements TokenStore {
  StoredSession? _session;

  @override
  Future<StoredSession?> read() async => _session;

  @override
  Future<void> write(StoredSession session) async {
    _session = session;
  }

  @override
  Future<void> clear() async {
    _session = null;
  }
}
