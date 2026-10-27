import 'dart:io';
import 'package:sp_jwt_auth/sp_jwt_auth.dart';
import 'package:test/test.dart';

void main() {
  test('scaffold exports valid packageVersion', () {
    expect(packageVersion, matches(r'^\d+\.\d+\.\d+(-beta\.\d+)?$'));
  });

  test('pubspec specifies floor Dart 3.8 and no flutter sdk', () {
    final pubspec = File('pubspec.yaml').readAsStringSync();
    expect(pubspec, contains("sdk: '>=3.8.0 <4.0.0'"));
    expect(pubspec, contains('name: sp_jwt_auth'));
    expect(pubspec, isNot(contains('sdk: flutter')));
  });
}
