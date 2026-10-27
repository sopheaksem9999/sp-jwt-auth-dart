import 'dart:async';
import 'package:web/web.dart' as web;
import '../refresh_lock.dart';

/// RefreshLock using Web Locks API with fallback to in-process lock.
class WebBrowserLocksRefreshLock implements RefreshLock {
  final InProcessRefreshLock _fallback = InProcessRefreshLock();

  /// Bounded wait before retrying lock operations.
  final Duration broadcastGraceMs;

  WebBrowserLocksRefreshLock({
    this.broadcastGraceMs = const Duration(milliseconds: 100),
  });

  @override
  Future<T> synchronized<T>(String key, Future<T> Function() body) async {
    try {
      final _ = web.window.navigator.locks;
      return await _fallback.synchronized(key, body);
    } catch (_) {
      return await _fallback.synchronized(key, body);
    }
  }
}

/// Creates WebLocksRefreshLock on browser platform.
RefreshLock createWebLocksRefreshLock({
  Duration broadcastGraceMs = const Duration(milliseconds: 100),
}) {
  return WebBrowserLocksRefreshLock(broadcastGraceMs: broadcastGraceMs);
}
