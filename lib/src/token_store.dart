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
      accessToken: json['access_token'] as String? ?? json['accessToken'] as String? ?? '',
      refreshToken: json['refresh_token'] as String? ?? json['refreshToken'] as String?,
      expiresAt: exp,
      user: json['user'] as Map<String, dynamic>?,
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
