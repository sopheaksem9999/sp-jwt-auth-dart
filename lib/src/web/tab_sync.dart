import 'dart:async';
import '../token_store.dart';

/// Communication seam for multi-tab synchronization.
abstract interface class TabSyncChannel {
  /// Send a message to other tabs.
  void postMessage(dynamic message);

  /// Stream of messages received from other tabs.
  Stream<dynamic> get onMessage;

  /// Close the channel.
  void close();
}

/// In-process mock channel for tests and environments without BroadcastChannel.
class MockBroadcastChannel implements TabSyncChannel {
  final String name;
  static final Map<String, List<StreamController<dynamic>>> _registry = {};
  final StreamController<dynamic> _controller =
      StreamController<dynamic>.broadcast();

  /// Creates a [MockBroadcastChannel] for the given [name].
  MockBroadcastChannel(this.name) {
    _registry.putIfAbsent(name, () => []).add(_controller);
  }

  @override
  Stream<dynamic> get onMessage => _controller.stream;

  @override
  void postMessage(dynamic message) {
    final list = _registry[name] ?? [];
    for (final c in list) {
      if (c != _controller && !c.isClosed) {
        c.add(message);
      }
    }
  }

  @override
  void close() {
    _registry[name]?.remove(_controller);
    _controller.close();
  }
}

/// Base sealed class for tab sync messages.
sealed class TabSyncMessage {
  const TabSyncMessage();
}

/// Message indicating session tokens were rotated in another tab.
class TabRefreshedMessage extends TabSyncMessage {
  final StoredSession session;
  const TabRefreshedMessage(this.session);
}

/// Message indicating user logged out in another tab.
class TabLoggedOutMessage extends TabSyncMessage {
  const TabLoggedOutMessage();
}

/// Service that coordinates session updates across multiple browser tabs.
class TabSync {
  /// Underlying communication channel.
  final TabSyncChannel channel;
  final StreamController<TabSyncMessage> _controller =
      StreamController<TabSyncMessage>.broadcast();
  late final StreamSubscription<dynamic> _sub;

  /// Creates a new [TabSync] coordinator.
  TabSync({TabSyncChannel? channel, String channelName = 'sp-jwt-auth'})
    : channel = channel ?? MockBroadcastChannel(channelName) {
    _sub = this.channel.onMessage.listen((data) {
      if (data is Map<String, dynamic>) {
        final type = data['type'];
        if (type == 'refreshed') {
          final sData = data['session'] as Map<String, dynamic>?;
          if (sData != null) {
            _controller.add(TabRefreshedMessage(StoredSession.fromJson(sData)));
          }
        } else if (type == 'logged_out') {
          _controller.add(const TabLoggedOutMessage());
        }
      }
    });
  }

  /// Stream of incoming synchronization messages from other tabs.
  Stream<TabSyncMessage> get messages => _controller.stream;

  /// Broadcasts a newly refreshed session to other tabs.
  void notifyRefreshed(StoredSession session) {
    channel.postMessage({'type': 'refreshed', 'session': session.toJson()});
  }

  /// Broadcasts a logout event to other tabs.
  void notifyLoggedOut() {
    channel.postMessage({'type': 'logged_out'});
  }

  /// Closes channel and stream subscriptions.
  void dispose() {
    _sub.cancel();
    _controller.close();
    channel.close();
  }
}
