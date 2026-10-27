import 'dart:async';
import 'package:dio/dio.dart';
import 'claims.dart';
import 'endpoints.dart';
import 'errors.dart';
import 'refresh_lock.dart';
import 'session.dart';
import 'token_store.dart';

/// Authentication mode for the client.
enum AuthMode {
  /// Standard user session with access and rotating refresh tokens.
  userSession,

  /// Static bearer token that does not rotate.
  staticToken,

  /// OAuth2 client credentials grant.
  clientCredentials,

  /// API key authentication.
  apiKey,
}

/// Core authentication client managing session lifecycle, proactive rotation,
/// single-flight deduplication, and failure classification.
class SpJwtAuth {
  /// Base URL of the authentication server.
  final Uri baseUrl;

  /// Configured authentication endpoints.
  final Endpoints endpoints;

  /// Underlying persistent or in-memory token store.
  final TokenStore store;

  /// Authentication mode.
  final AuthMode mode;

  /// Duration before token expiry when proactive refresh is triggered.
  final Duration refreshAhead;

  final RefreshLock _refreshLock;

  /// HTTP client used for auth requests.
  final Dio dio;

  final StreamController<AuthState> _stateController =
      StreamController<AuthState>.broadcast();
  final StreamController<AuthEvent> _eventsController =
      StreamController<AuthEvent>.broadcast();

  AuthState _state = const Anonymous();
  StoredSession? _cachedSession;
  Future<String?>? _refreshInFlight;

  /// Creates a new [SpJwtAuth] client.
  SpJwtAuth({
    required this.baseUrl,
    required this.endpoints,
    required this.store,
    this.mode = AuthMode.userSession,
    this.refreshAhead = const Duration(seconds: 60),
    RefreshLock? refreshLock,
    Dio? dio,
  }) : _refreshLock = refreshLock ?? InProcessRefreshLock(),
       dio = dio ?? Dio();

  /// Current authentication state.
  AuthState get state => _state;

  /// Stream of authentication state changes.
  Stream<AuthState> get changes => _stateController.stream;

  /// Stream of discrete authentication events.
  Stream<AuthEvent> get events => _eventsController.stream;

  void _setState(AuthState newState) {
    if (_state != newState) {
      _state = newState;
      _stateController.add(newState);
    }
  }

  JwtClaims _extractClaims(String token) {
    try {
      return JwtClaims.parse(token);
    } catch (_) {
      return const JwtClaims(raw: {});
    }
  }

  /// Restores session state from the underlying [store].
  Future<void> restore() async {
    final session = await store.read();
    if (session != null) {
      _cachedSession = session;
      _setState(
        Authenticated(
          user: session.user ?? const {},
          claims: _extractClaims(session.accessToken),
        ),
      );
    } else {
      _cachedSession = null;
      _setState(const Anonymous());
    }
  }

  /// Returns a valid access token, proactively refreshing if near expiry.
  Future<String?> accessToken() async {
    if (_cachedSession == null) {
      await restore();
    }
    if (_cachedSession == null) {
      return null;
    }

    final now = DateTime.now().toUtc();
    final exp =
        _cachedSession!.expiresAt ??
        _extractClaims(_cachedSession!.accessToken).exp;
    if (exp != null && exp.difference(now) < refreshAhead) {
      return _doRefresh();
    }
    return _cachedSession!.accessToken;
  }

  /// Returns the authorization headers for authenticated requests.
  Future<Map<String, String>> headers() async {
    final token = await accessToken();
    if (token != null && token.isNotEmpty) {
      return {'Authorization': 'Bearer $token'};
    }
    return {};
  }

  /// Handles a 401 response by attempting a single refresh.
  ///
  /// Returns `true` if refresh succeeded and request should be retried.
  Future<bool> handleUnauthorized() async {
    try {
      final token = await _doRefresh();
      return token != null;
    } catch (_) {
      return false;
    }
  }

  /// Single-flight refresh entrypoint.
  Future<String?> _doRefresh() {
    if (_refreshInFlight != null) {
      return _refreshInFlight!;
    }
    final future = _executeRefresh();
    _refreshInFlight = future;
    return future.whenComplete(() {
      _refreshInFlight = null;
    });
  }

  Future<String?> _executeRefresh() async {
    return _refreshLock.synchronized('refresh', () async {
      // Re-read store first: another isolate or process may have refreshed already.
      final currentInStore = await store.read();
      final now = DateTime.now().toUtc();
      if (currentInStore != null) {
        final exp =
            currentInStore.expiresAt ??
            _extractClaims(currentInStore.accessToken).exp;
        if (exp != null && exp.difference(now) >= refreshAhead) {
          _cachedSession = currentInStore;
          _setState(
            Authenticated(
              user: currentInStore.user ?? const {},
              claims: _extractClaims(currentInStore.accessToken),
            ),
          );
          return currentInStore.accessToken;
        }
      }

      final rt = currentInStore?.refreshToken ?? _cachedSession?.refreshToken;
      if (rt == null || rt.isEmpty) {
        await _handleDefinitiveFailure('No refresh token available');
        throw const SpAuthError(
          code: SpAuthErrorCode.refreshReuseDetected,
          message: 'No refresh token available',
        );
      }

      final refreshUri = baseUrl.resolve(endpoints.refresh);
      try {
        final response = await dio.post<dynamic>(
          refreshUri.toString(),
          data: {'refresh_token': rt},
          options: Options(headers: {'Accept': 'application/json'}),
        );

        final data = response.data;
        if (data is Map<String, dynamic>) {
          if (data['success'] == false) {
            final errCode = data['error_code'];
            final msg = (data['message'] as String?)?.toLowerCase() ?? '';
            if (errCode == 10002 ||
                errCode == 10010 ||
                msg.contains('unauthenticated') ||
                msg.contains('revoked')) {
              final rawMsg = data['message']?.toString() ?? 'Token revoked';
              await _handleDefinitiveFailure(rawMsg);
              throw SpAuthError(
                code: SpAuthErrorCode.refreshReuseDetected,
                message: rawMsg,
                errorCode: errCode is int ? errCode : null,
              );
            }
          }
        }

        final newSession = endpoints.parseSession(data);
        await store.write(newSession);
        _cachedSession = newSession;
        _setState(
          Authenticated(
            user: newSession.user ?? const {},
            claims: _extractClaims(newSession.accessToken),
          ),
        );
        _eventsController.add(Refreshed(newSession));
        return newSession.accessToken;
      } on DioException catch (e) {
        final classified = _classifyDioError(e);
        if (classified.isDefinitive) {
          await _handleDefinitiveFailure(classified.message);
        }
        throw SpAuthError(
          code: classified.code,
          message: classified.message,
          cause: e,
        );
      } catch (e) {
        if (e is SpAuthError) rethrow;
        throw SpAuthError(
          code: SpAuthErrorCode.unknown,
          message: e.toString(),
          cause: e,
        );
      }
    });
  }

  Future<void> _handleDefinitiveFailure(String reason) async {
    await store.clear();
    _cachedSession = null;
    _setState(const Anonymous());
    _eventsController.add(SessionEnded(reason));
  }

  _ClassifiedError _classifyDioError(DioException e) {
    if (e.type == DioExceptionType.connectionTimeout ||
        e.type == DioExceptionType.sendTimeout ||
        e.type == DioExceptionType.receiveTimeout) {
      return _ClassifiedError(
        isDefinitive: false,
        code: SpAuthErrorCode.timeout,
        message: 'Request timed out: ${e.message ?? 'timeout'}',
      );
    }

    if (e.type == DioExceptionType.connectionError) {
      return _ClassifiedError(
        isDefinitive: false,
        code: SpAuthErrorCode.network,
        message:
            'Network connection error: ${e.message ?? 'connection failed'}',
      );
    }

    final response = e.response;
    if (response != null) {
      final status = response.statusCode ?? 500;
      final data = response.data;

      var bodyText = '';
      int? errorCode;
      if (data is Map<String, dynamic>) {
        bodyText = '${data['message'] ?? ''} ${data['error'] ?? ''}'
            .trim()
            .toLowerCase();
        final codeVal = data['error_code'];
        if (codeVal is int) {
          errorCode = codeVal;
        } else if (codeVal is String) {
          errorCode = int.tryParse(codeVal);
        }
      } else if (data is String) {
        bodyText = data.toLowerCase();
      }

      final hasUnauthenticated =
          bodyText.contains('unauthenticated') || bodyText.contains('revoked');
      final isDefinitiveCode = errorCode == 10002 || errorCode == 10010;
      final isDefinitiveStatus =
          status == 400 || status == 401 || status == 403 || status == 422;

      if (hasUnauthenticated || isDefinitiveCode || isDefinitiveStatus) {
        return _ClassifiedError(
          isDefinitive: true,
          code: isDefinitiveCode
              ? SpAuthErrorCode.refreshReuseDetected
              : (status == 403
                    ? SpAuthErrorCode.forbidden
                    : SpAuthErrorCode.unauthenticated),
          message: bodyText.isNotEmpty
              ? bodyText
              : 'Authentication failed (HTTP $status)',
        );
      }

      if (status >= 500) {
        return _ClassifiedError(
          isDefinitive: false,
          code: SpAuthErrorCode.network,
          message: 'Server error (HTTP $status)',
        );
      }
    }

    return _ClassifiedError(
      isDefinitive: false,
      code: SpAuthErrorCode.network,
      message: e.message ?? 'Network error',
    );
  }

  /// Authenticates with user credentials and stores the resulting session.
  Future<StoredSession> login(Map<String, dynamic> credentials) async {
    final uri = baseUrl.resolve(endpoints.login);
    final response = await dio.post<dynamic>(
      uri.toString(),
      data: credentials,
      options: Options(headers: {'Accept': 'application/json'}),
    );
    final session = endpoints.parseSession(response.data);
    await store.write(session);
    _cachedSession = session;
    _setState(
      Authenticated(
        user: session.user ?? const {},
        claims: _extractClaims(session.accessToken),
      ),
    );
    return session;
  }

  /// Logs out the user, attempting remote revocation and clearing local storage.
  Future<void> logout() async {
    final currentRt = _cachedSession?.refreshToken;
    final currentAt = _cachedSession?.accessToken;
    try {
      final uri = baseUrl.resolve(endpoints.logout);
      await dio.post<dynamic>(
        uri.toString(),
        data: currentRt != null ? {'refresh_token': currentRt} : null,
        options: Options(
          headers: {
            'Accept': 'application/json',
            if (currentAt != null) 'Authorization': 'Bearer $currentAt',
          },
        ),
      );
    } catch (_) {
      // Best-effort remote revocation: local session cleared regardless.
    } finally {
      await store.clear();
      _cachedSession = null;
      _setState(const Anonymous());
      _eventsController.add(const SessionEnded('User logged out'));
    }
  }

  /// Closes stream controllers and releases resources.
  Future<void> dispose() async {
    await _stateController.close();
    await _eventsController.close();
  }
}

class _ClassifiedError {
  final bool isDefinitive;
  final SpAuthErrorCode code;
  final String message;

  _ClassifiedError({
    required this.isDefinitive,
    required this.code,
    required this.message,
  });
}
