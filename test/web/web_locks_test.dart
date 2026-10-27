import 'dart:async';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:sp_jwt_auth/web.dart';
import 'package:test/test.dart';

void main() {
  test(
    'WebLocksRefreshLock implements RefreshLock and falls back cleanly when Web Locks unavailable',
    () async {
      final lock = WebLocksRefreshLock();
      expect(lock, isA<RefreshLock>());

      var counter = 0;
      final futures = <Future<void>>[];
      for (var i = 0; i < 5; i++) {
        futures.add(
          lock.synchronized('test_key', () async {
            final current = counter;
            await Future<void>.delayed(const Duration(milliseconds: 10));
            counter = current + 1;
          }),
        );
      }

      await Future.wait(futures);
      expect(counter, equals(5));
    },
  );

  test('TabSync notifies other tabs upon token refresh', () async {
    final tabSync1 = TabSync(channel: MockBroadcastChannel('sp-jwt-auth'));
    final tabSync2 = TabSync(channel: MockBroadcastChannel('sp-jwt-auth'));

    final receivedEvents = <TabSyncMessage>[];
    tabSync2.messages.listen(receivedEvents.add);

    tabSync1.notifyRefreshed(
      const StoredSession(
        accessToken: 'shared_access_token_999',
        user: {'name': 'Alice'},
      ),
    );

    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(receivedEvents.length, equals(1));
    final msg = receivedEvents.first;
    expect(msg, isA<TabRefreshedMessage>());
    expect(
      (msg as TabRefreshedMessage).session.accessToken,
      equals('shared_access_token_999'),
    );

    tabSync1.dispose();
    tabSync2.dispose();
  });

  test('TabSync notifies other tabs upon logout', () async {
    final tabSync1 = TabSync(
      channel: MockBroadcastChannel('sp-jwt-auth-logout'),
    );
    final tabSync2 = TabSync(
      channel: MockBroadcastChannel('sp-jwt-auth-logout'),
    );

    final receivedEvents = <TabSyncMessage>[];
    tabSync2.messages.listen(receivedEvents.add);

    tabSync1.notifyLoggedOut();

    await Future<void>.delayed(const Duration(milliseconds: 20));
    expect(receivedEvents.length, equals(1));
    expect(receivedEvents.first, isA<TabLoggedOutMessage>());

    tabSync1.dispose();
    tabSync2.dispose();
  });
}
