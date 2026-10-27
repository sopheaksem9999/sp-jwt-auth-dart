/// Resolves an endpoint [path] against [base].
///
/// When [relativeToBase] is false, standard RFC 3986 resolution applies: a
/// path starting with `/` replaces any path on [base]. When true, [path] is
/// appended beneath the path of [base], with exactly one `/` between them.
Uri resolveEndpoint(Uri base, String path, {required bool relativeToBase}) {
  if (!relativeToBase) return base.resolve(path);
  final basePath = base.path.endsWith('/') ? base.path : '${base.path}/';
  final rel = path.startsWith('/') ? path.substring(1) : path;
  return base.resolve('$basePath$rel');
}
