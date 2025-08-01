import 'storage_service_stub.dart'
    if (dart.library.html) 'storage_service_web.dart'
    if (dart.library.io) 'storage_service_io.dart';

// Abstract storage interface
abstract class StorageService {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
}

// Factory to get the appropriate storage service
class StorageFactory {
  static StorageService getStorageService() {
    return getStorageServiceImpl();
  }
}
