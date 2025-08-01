import 'dart:io';
import 'package:path_provider/path_provider.dart';
import 'storage_service.dart';

class FileStorageService implements StorageService {
  @override
  Future<String?> read(String key) async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final file = File('${directory.path}/$key.json');
      if (await file.exists()) {
        return await file.readAsString();
      }
    } catch (e) {
      print('Error reading from file: $e');
    }
    return null;
  }

  @override
  Future<void> write(String key, String value) async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final file = File('${directory.path}/$key.json');
      await file.writeAsString(value);
    } catch (e) {
      print('Error writing to file: $e');
    }
  }

  @override
  Future<void> delete(String key) async {
    try {
      final directory = await getApplicationDocumentsDirectory();
      final file = File('${directory.path}/$key.json');
      if (await file.exists()) {
        await file.delete();
      }
    } catch (e) {
      print('Error deleting file: $e');
    }
  }
}

StorageService getStorageServiceImpl() {
  return FileStorageService();
}
