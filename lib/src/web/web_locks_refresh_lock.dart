import '../refresh_lock.dart';
import 'web_locks_stub.dart' if (dart.library.js_interop) 'web_locks_web.dart';

/// Cross-tab refresh lock using the Web Locks API with fallback to in-process synchronization.
class WebLocksRefreshLock implements RefreshLock {
  final RefreshLock _delegate;

  /// Bounded wait before retrying after a lock grant.
  final Duration broadcastGraceMs;

  /// Creates a new [WebLocksRefreshLock].
  WebLocksRefreshLock({
    this.broadcastGraceMs = const Duration(milliseconds: 100),
  }) : _delegate = createWebLocksRefreshLock(
         broadcastGraceMs: broadcastGraceMs,
       );

  @override
  Future<T> synchronized<T>(String key, Future<T> Function() body) {
    return _delegate.synchronized(key, body);
  }
}
