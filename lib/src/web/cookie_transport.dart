import 'cookie_env_stub.dart'
    if (dart.library.js_interop) 'cookie_env_web.dart';

/// Transport mode for authentication tokens.
enum Transport {
  /// Tokens delivered in response JSON payload and stored in token store.
  body,

  /// Refresh token held in httpOnly cookie; access token in memory only.
  cookie,
}

/// CSRF double-submit configuration for cookie transport.
class Csrf {
  /// Header name sent on requests (default `X-SP-CSRF`).
  final String header;

  /// Cookie name readable by client JavaScript (default `sp_csrf`).
  final String cookie;

  const Csrf({this.header = 'X-SP-CSRF', this.cookie = 'sp_csrf'});
}

/// Configuration options for web cookie transport.
class CookieTransportConfig {
  /// Bounded wait in milliseconds before retrying after a Web Lock grant.
  final int broadcastGraceMs;

  const CookieTransportConfig({this.broadcastGraceMs = 100});
}

/// Browser cookie environment seam allowing tests to inject mock environments.
abstract interface class BrowserCookieEnv {
  /// Read cookie by name.
  String? getCookie(String name);

  /// Set cookie value.
  void setCookie(String name, String value);

  /// Whether running in a browser environment that supports cookies.
  bool get isSupported;
}

/// In-memory mock implementation of [BrowserCookieEnv] for testing.
class MockBrowserCookieEnv implements BrowserCookieEnv {
  final Map<String, String> _cookies = {};

  @override
  bool get isSupported => true;

  @override
  String? getCookie(String name) => _cookies[name];

  @override
  void setCookie(String name, String value) {
    _cookies[name] = value;
  }
}

/// Returns the platform default [BrowserCookieEnv].
BrowserCookieEnv defaultCookieEnv() => createDefaultCookieEnv();
