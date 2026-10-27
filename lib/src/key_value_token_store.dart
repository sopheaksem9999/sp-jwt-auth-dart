import 'dart:convert';

import 'errors.dart';
import 'token_store.dart';

/// Minimal string key-value storage seam (e.g. a secure keychain wrapper).
abstract interface class KeyValueStorage {
  Future<String?> read(String key);
  Future<void> write(String key, String value);

  /// Removes [key]. Deleting a key that does not exist MUST NOT throw:
  /// [KeyValueTokenStore.write] deletes the access token before writing and
  /// [KeyValueTokenStore.clear] deletes every key, including absent ones.
  Future<void> delete(String key);
}

/// Key names used by [KeyValueTokenStore]. Override to read sessions that an
/// existing app persisted under different names.
class StorageKeys {
  final String accessToken;
  final String refreshToken;
  final String expiresAt;
  final String user;

  const StorageKeys({
    this.accessToken = 'sp_access_token',
    this.refreshToken = 'sp_refresh_token',
    this.expiresAt = 'sp_access_token_expires_at',
    this.user = 'sp_user',
  });
}

/// [TokenStore] persisting each session field under its own key in a
/// [KeyValueStorage]. Pure Dart; platform stores plug in via the storage seam.
class KeyValueTokenStore implements TokenStore {
  final KeyValueStorage _storage;
  final StorageKeys keys;

  KeyValueTokenStore(KeyValueStorage storage, {this.keys = const StorageKeys()})
    : _storage = storage;

  @override
  Future<StoredSession?> read() async {
    final access = await _storage.read(keys.accessToken);
    if (access == null || access.isEmpty) return null;
    final refresh = await _storage.read(keys.refreshToken);
    final expRaw = await _storage.read(keys.expiresAt);
    final userRaw = await _storage.read(keys.user);

    Map<String, dynamic>? user;
    if (userRaw != null && userRaw.isNotEmpty) {
      try {
        final decoded = jsonDecode(userRaw);
        if (decoded is! Map) throw const FormatException('not an object');
        user = Map<String, dynamic>.from(decoded);
      } on FormatException catch (e) {
        throw SpAuthError(
          code: SpAuthErrorCode.storageError,
          message: 'Stored user is not valid JSON',
          cause: e,
        );
      }
    }

    return StoredSession(
      accessToken: access,
      refreshToken: (refresh == null || refresh.isEmpty) ? null : refresh,
      expiresAt: _parseExpiry(expRaw),
      user: user,
    );
  }

  @override
  Future<void> write(StoredSession session) async {
    // The access token is the presence marker for read(): remove it first and
    // write it last so a crash mid-write reads as logged out, never mixed.
    await _storage.delete(keys.accessToken);
    await _putOrDelete(keys.refreshToken, session.refreshToken);
    await _putOrDelete(
      keys.expiresAt,
      session.expiresAt?.toUtc().toIso8601String(),
    );
    await _putOrDelete(
      keys.user,
      session.user == null ? null : jsonEncode(session.user),
    );
    await _storage.write(keys.accessToken, session.accessToken);
  }

  @override
  Future<void> clear() async {
    await _storage.delete(keys.accessToken);
    await _storage.delete(keys.refreshToken);
    await _storage.delete(keys.expiresAt);
    await _storage.delete(keys.user);
  }

  Future<void> _putOrDelete(String key, String? value) =>
      value == null ? _storage.delete(key) : _storage.write(key, value);

  static DateTime? _parseExpiry(String? raw) {
    if (raw == null) return null;
    final text = raw.trim();
    if (text.isEmpty) return null;
    final seconds = int.tryParse(text);
    if (seconds != null) {
      return DateTime.fromMillisecondsSinceEpoch(seconds * 1000, isUtc: true);
    }
    return DateTime.tryParse(text)?.toUtc();
  }
}
