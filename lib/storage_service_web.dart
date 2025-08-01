import 'dart:html' as html;
import 'storage_service.dart';

class WebStorageService implements StorageService {
  @override
  Future<String?> read(String key) async {
    return html.window.localStorage[key];
  }

  @override
  Future<void> write(String key, String value) async {
    html.window.localStorage[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    html.window.localStorage.remove(key);
  }
}

StorageService getStorageServiceImpl() {
  return WebStorageService();
}
