import '../refresh_lock.dart';

/// Creates [RefreshLock] for non-browser platforms.
RefreshLock createWebLocksRefreshLock({
  Duration broadcastGraceMs = const Duration(milliseconds: 100),
}) {
  return InProcessRefreshLock();
}
