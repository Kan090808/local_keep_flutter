import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import 'package:encrypt/encrypt.dart' as encrypt;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_staggered_grid_view/flutter_staggered_grid_view.dart';
import 'package:pointycastle/export.dart' as pc;
import 'package:provider/provider.dart';
import 'storage_service.dart';

// Model for a Note
class Note {
  final String encrypted;
  final String salt;
  final String iv;
  Note({required this.encrypted, required this.salt, required this.iv});

  Map<String, dynamic> toJson() => {
    'encrypted': encrypted,
    'salt': salt,
    'iv': iv,
  };

  factory Note.fromJson(Map<String, dynamic> json) =>
      Note(encrypted: json['encrypted'], salt: json['salt'], iv: json['iv']);
}

// Encryption data class for isolate communication
class EncryptionData {
  final String plainText;
  final Uint8List baseKeyBytes;
  final Uint8List salt;
  final Uint8List iv;

  EncryptionData({
    required this.plainText,
    required this.baseKeyBytes,
    required this.salt,
    required this.iv,
  });
}

// Background key derivation function for password
Map<String, dynamic> _deriveKeyFromPassword(String password) {
  final salt = utf8.encode('fixedSaltForDemo');
  final pbkdf2 = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64));
  pbkdf2.init(pc.Pbkdf2Parameters(Uint8List.fromList(salt), 1000, 32));
  final keyBytes = pbkdf2.process(Uint8List.fromList(utf8.encode(password)));
  return {'keyBytes': keyBytes};
}

// Background encryption function - must be top-level function for compute()
Map<String, String> _encryptInBackground(EncryptionData data) {
  // Derive key with salt in background
  final pbkdf2 = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64));
  pbkdf2.init(
    pc.Pbkdf2Parameters(data.salt, 1000, 32),
  ); // Reduced from 100,000 to 1,000
  final keyBytes = pbkdf2.process(data.baseKeyBytes);
  final derivedKey = encrypt.Key(Uint8List.fromList(keyBytes));

  final iv = encrypt.IV(data.iv);
  final encrypter = encrypt.Encrypter(
    encrypt.AES(derivedKey, mode: encrypt.AESMode.cbc),
  );
  final encrypted = encrypter.encrypt(data.plainText, iv: iv);

  return {
    'encrypted': encrypted.base64,
    'salt': base64Encode(data.salt),
    'iv': base64Encode(data.iv),
  };
}

// App state for password and notes
class AppState extends ChangeNotifier {
  List<Note> _notes = [];
  encrypt.Key? _key;
  late StorageService _storage;

  List<Note> get notes => _notes;
  encrypt.Key? get key => _key;

  AppState() {
    _initializeStorage();
  }

  Future<void> _initializeStorage() async {
    _storage = StorageFactory.getStorageService();
    await _loadNotes();
  }

  Future<void> _loadNotes() async {
    try {
      final jsonString = await _storage.read('encrypted_notes');
      if (jsonString != null) {
        final List<dynamic> jsonList = json.decode(jsonString);
        _notes = jsonList.map((json) => Note.fromJson(json)).toList();
        notifyListeners();
      }
    } catch (e) {
      print('Error loading notes: $e');
    }
  }

  Future<void> _saveNotes() async {
    try {
      final jsonList = _notes.map((note) => note.toJson()).toList();
      final jsonString = json.encode(jsonList);
      await _storage.write('encrypted_notes', jsonString);
    } catch (e) {
      print('Error saving notes: $e');
    }
  }

  Future<void> setKeyFromPassword(String password) async {
    // Derive key in background to avoid blocking UI
    final result = await compute(_deriveKeyFromPassword, password);
    _key = encrypt.Key(Uint8List.fromList(result['keyBytes']));
    notifyListeners();
  }

  Future<void> addNote(String plainText) async {
    if (_key == null) return;

    final salt = _randomSalt();
    final iv = _randomSalt(); // Use same function for IV

    final encryptionData = EncryptionData(
      plainText: plainText,
      baseKeyBytes: _key!.bytes,
      salt: salt,
      iv: iv,
    );

    // Encrypt in background isolate using compute
    final result = await compute(_encryptInBackground, encryptionData);

    _notes.add(
      Note(
        encrypted: result['encrypted']!,
        salt: result['salt']!,
        iv: result['iv']!,
      ),
    );

    // Save to file after adding to memory
    await _saveNotes();
    notifyListeners();
  }

  String? decryptNote(Note note) {
    if (_key == null) return null;
    final salt = base64Decode(note.salt);
    final iv = base64Decode(note.iv);
    final key = _deriveKeyWithSalt(_key!, salt);
    final ivObj = encrypt.IV(iv);
    final encrypter = encrypt.Encrypter(
      encrypt.AES(key, mode: encrypt.AESMode.cbc),
    );
    try {
      return encrypter.decrypt64(note.encrypted, iv: ivObj);
    } catch (e) {
      return null;
    }
  }

  Uint8List _randomSalt() {
    final rand = Random.secure();
    return Uint8List.fromList(List.generate(16, (_) => rand.nextInt(256)));
  }

  encrypt.Key _deriveKeyWithSalt(encrypt.Key baseKey, Uint8List salt) {
    final pbkdf2 = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64));
    pbkdf2.init(
      pc.Pbkdf2Parameters(salt, 1000, 32),
    ); // Reduced from 100,000 to 1,000
    final keyBytes = pbkdf2.process(baseKey.bytes);
    return encrypt.Key(Uint8List.fromList(keyBytes));
  }

  void deleteNote(int index) {
    if (index >= 0 && index < _notes.length) {
      _notes.removeAt(index);
      _saveNotes();
      notifyListeners();
    }
  }

  Future<void> deleteNotePermanently(int index) async {
    _notes.removeAt(index);
    await _saveNotes();
    notifyListeners();
  }

  Future<void> removeAllNotes() async {
    _notes.clear();
    await _saveNotes();
    notifyListeners();
  }
}

class PasswordScreen extends StatefulWidget {
  final Future<void> Function(String password) onPasswordEntered;
  final bool isProcessing;
  const PasswordScreen({
    required this.onPasswordEntered,
    this.isProcessing = false,
    super.key,
  });

  @override
  State<PasswordScreen> createState() => _PasswordScreenState();
}

class _PasswordScreenState extends State<PasswordScreen> {
  final _controller = TextEditingController();
  final _focusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    // Auto-focus the password field when screen loads
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _focusNode.requestFocus();
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(32.0),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              const Text('Enter Password'),
              TextField(
                controller: _controller,
                focusNode: _focusNode,
                obscureText: true,
                decoration: const InputDecoration(labelText: 'Password'),
                enabled: !widget.isProcessing,
                onSubmitted: (value) {
                  if (value.isNotEmpty && !widget.isProcessing) {
                    widget.onPasswordEntered(value);
                  }
                },
              ),
              const SizedBox(height: 16),
              widget.isProcessing
                  ? const CircularProgressIndicator()
                  : ElevatedButton(
                      onPressed: () {
                        widget.onPasswordEntered(_controller.text);
                      },
                      child: const Text('Enter'),
                    ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    super.dispose();
  }
}

void main() {
  runApp(
    ChangeNotifierProvider(create: (_) => AppState(), child: const MyApp()),
  );
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Local Keep',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
      ),
      home: const PasswordGate(),
    );
  }
}

class PasswordGate extends StatefulWidget {
  const PasswordGate({super.key});
  @override
  State<PasswordGate> createState() => _PasswordGateState();
}

class _PasswordGateState extends State<PasswordGate> {
  bool _unlocked = false;
  bool _processing = false;

  @override
  Widget build(BuildContext context) {
    if (!_unlocked) {
      return PasswordScreen(
        onPasswordEntered: (password) async {
          setState(() => _processing = true);
          await Provider.of<AppState>(
            context,
            listen: false,
          ).setKeyFromPassword(password);
          setState(() {
            _processing = false;
            _unlocked = true;
          });
        },
        isProcessing: _processing,
      );
    }
    return const MyHomePage(title: 'Local Keep');
  }
}

class MyHomePage extends StatefulWidget {
  const MyHomePage({super.key, required this.title});
  final String title;
  @override
  State<MyHomePage> createState() => _MyHomePageState();
}

class _MyHomePageState extends State<MyHomePage> {
  @override
  Widget build(BuildContext context) {
    final appState = Provider.of<AppState>(context);
    final decryptedNotes = appState.notes
        .map((note) => {'note': note, 'decrypted': appState.decryptNote(note)})
        .where((item) => item['decrypted'] != null)
        .toList();

    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: Text(widget.title),
        actions: [
          IconButton(
            icon: const Icon(Icons.settings),
            onPressed: () {
              Navigator.push(
                context,
                MaterialPageRoute(builder: (context) => const SettingsPage()),
              );
            },
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(8.0),
        child: MasonryGridView.count(
          crossAxisCount: 2,
          crossAxisSpacing: 8.0,
          mainAxisSpacing: 8.0,
          itemCount: decryptedNotes.length,
          itemBuilder: (context, index) {
            final item = decryptedNotes[index];
            final note = item['note'] as Note;
            final decrypted = item['decrypted'] as String;

            // Convert newlines to spaces for display and limit to reasonable length
            final displayText = decrypted.replaceAll('\n', ' ').trim();

            return Card(
              elevation: 2,
              child: InkWell(
                onTap: () {
                  Navigator.push(
                    context,
                    MaterialPageRoute(
                      builder: (context) => NoteDetailPage(
                        note: note,
                        noteIndex: appState.notes.indexOf(note),
                      ),
                    ),
                  );
                },
                child: Container(
                  padding: const EdgeInsets.all(12.0),
                  width: double.infinity,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        displayText,
                        style: const TextStyle(fontSize: 14, height: 1.3),
                        maxLines: 5,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ],
                  ),
                ),
              ),
            );
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(
        onPressed: () {
          Navigator.push(
            context,
            MaterialPageRoute(builder: (context) => const AddNotePage()),
          );
        },
        child: const Icon(Icons.add),
      ),
    );
  }
}

class AddNotePage extends StatefulWidget {
  const AddNotePage({super.key});

  @override
  State<AddNotePage> createState() => _AddNotePageState();
}

class _AddNotePageState extends State<AddNotePage> {
  final _noteController = TextEditingController();
  final _focusNode = FocusNode();

  @override
  void initState() {
    super.initState();
    // Auto-focus the text field when page loads
    WidgetsBinding.instance.addPostFrameCallback((_) {
      _focusNode.requestFocus();
    });
  }

  Future<bool> _onWillPop() async {
    if (_noteController.text.isEmpty) {
      return true; // No content, allow navigation
    }

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unsaved Note'),
        content: const Text(
          'You have unsaved content. What would you like to do?',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(false), // Discard
            child: const Text('Discard'),
          ),
          TextButton(
            onPressed: () async {
              // Save and then navigate
              final appState = Provider.of<AppState>(context, listen: false);
              await appState.addNote(_noteController.text);
              if (mounted) {
                Navigator.of(context).pop(true); // Allow navigation
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );

    return result ?? false; // Default to not allowing navigation
  }

  @override
  Widget build(BuildContext context) {
    final appState = Provider.of<AppState>(context, listen: false);

    return WillPopScope(
      onWillPop: _onWillPop,
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            _noteController.text.isNotEmpty ? 'Add Note*' : 'Add Note',
          ),
          backgroundColor: Theme.of(context).colorScheme.inversePrimary,
          actions: [
            IconButton(
              icon: const Icon(Icons.save),
              onPressed: _noteController.text.isNotEmpty
                  ? () async {
                      // Show loading indicator
                      showDialog(
                        context: context,
                        barrierDismissible: false,
                        builder: (context) =>
                            const Center(child: CircularProgressIndicator()),
                      );

                      await appState.addNote(_noteController.text);

                      // Close loading dialog
                      if (context.mounted) {
                        Navigator.pop(context);
                        Navigator.pop(context);
                      }
                    }
                  : null, // Disable save button if no content
            ),
          ],
        ),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: TextField(
            controller: _noteController,
            focusNode: _focusNode,
            decoration: const InputDecoration(
              hintText: 'Enter your note...',
              border: InputBorder.none,
            ),
            maxLines: null,
            expands: true,
            textAlignVertical: TextAlignVertical.top,
            onChanged: (text) {
              setState(() {}); // Refresh to update title and save button state
            },
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _noteController.dispose();
    _focusNode.dispose();
    super.dispose();
  }
}

class SettingsPage extends StatefulWidget {
  const SettingsPage({super.key});

  @override
  State<SettingsPage> createState() => _SettingsPageState();
}

class _SettingsPageState extends State<SettingsPage> {
  final _passwordController = TextEditingController();

  @override
  Widget build(BuildContext context) {
    final appState = Provider.of<AppState>(context); // Listen to changes

    // Print note counts to console for debugging
    print('Total Notes: ${appState.notes.length}');
    print(
      'Decryptable Notes: ${appState.notes.where((note) => appState.decryptNote(note) != null).length}',
    );

    return Scaffold(
      appBar: AppBar(
        title: const Text('Settings'),
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Password System',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 8),
            const Card(
              child: Padding(
                padding: EdgeInsets.all(12.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'How it works:',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                    SizedBox(height: 8),
                    Text(
                      '• Your password is encrypted using PBKDF2 and stored in memory only',
                      style: TextStyle(fontSize: 14),
                    ),
                    SizedBox(height: 4),
                    Text(
                      '• Password is required every time you open the app',
                      style: TextStyle(fontSize: 14),
                    ),
                    SizedBox(height: 4),
                    Text(
                      '• You can use different passwords to store different sets of notes',
                      style: TextStyle(fontSize: 14),
                    ),
                    SizedBox(height: 4),
                    Text(
                      '• Notes encrypted with other passwords will be hidden',
                      style: TextStyle(fontSize: 14),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),
            const Text(
              'Change Password',
              style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: 16),
            TextField(
              controller: _passwordController,
              obscureText: true,
              decoration: const InputDecoration(
                labelText: 'New Password',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: () async {
                if (_passwordController.text.isNotEmpty) {
                  // Show loading
                  showDialog(
                    context: context,
                    barrierDismissible: false,
                    builder: (context) =>
                        const Center(child: CircularProgressIndicator()),
                  );

                  await appState.setKeyFromPassword(_passwordController.text);
                  _passwordController.clear();

                  if (context.mounted) {
                    Navigator.pop(context); // Close loading dialog
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text(
                          'Password updated! Notes will refresh with new key.',
                        ),
                      ),
                    );
                  }
                }
              },
              child: const Text('Update Password'),
            ),
            const SizedBox(height: 32),
            const Text(
              'Danger Zone',
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: Colors.red,
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton(
              onPressed: appState.notes.isEmpty
                  ? null
                  : () {
                      showDialog(
                        context: context,
                        builder: (context) => AlertDialog(
                          title: const Text('Remove All Notes'),
                          content: const Text(
                            'Are you sure you want to permanently delete all notes? This action cannot be undone.',
                          ),
                          actions: [
                            TextButton(
                              onPressed: () => Navigator.pop(context),
                              child: const Text('Cancel'),
                            ),
                            TextButton(
                              onPressed: () async {
                                Navigator.pop(context); // Close dialog

                                // Show loading
                                showDialog(
                                  context: context,
                                  barrierDismissible: false,
                                  builder: (context) => const Center(
                                    child: CircularProgressIndicator(),
                                  ),
                                );

                                await appState.removeAllNotes();

                                if (context.mounted) {
                                  Navigator.pop(
                                    context,
                                  ); // Close loading dialog
                                  ScaffoldMessenger.of(context).showSnackBar(
                                    const SnackBar(
                                      content: Text(
                                        'All notes have been removed.',
                                      ),
                                    ),
                                  );
                                }
                              },
                              style: TextButton.styleFrom(
                                foregroundColor: Colors.red,
                              ),
                              child: const Text('Delete All'),
                            ),
                          ],
                        ),
                      );
                    },
              style: ElevatedButton.styleFrom(
                backgroundColor: Colors.red,
                foregroundColor: Colors.white,
              ),
              child: const Text('Remove All Notes'),
            ),
          ],
        ),
      ),
    );
  }

  @override
  void dispose() {
    _passwordController.dispose();
    super.dispose();
  }
}

class NoteDetailPage extends StatefulWidget {
  final Note note;
  final int noteIndex;

  const NoteDetailPage({
    required this.note,
    required this.noteIndex,
    super.key,
  });

  @override
  State<NoteDetailPage> createState() => _NoteDetailPageState();
}

class _NoteDetailPageState extends State<NoteDetailPage> {
  late TextEditingController _noteController;
  late FocusNode _focusNode;
  late String _originalText;
  bool _hasChanges = false;

  @override
  void initState() {
    super.initState();
    final appState = Provider.of<AppState>(context, listen: false);
    final decryptedText = appState.decryptNote(widget.note) ?? '';
    _originalText = decryptedText;
    _noteController = TextEditingController(text: decryptedText);
    _focusNode = FocusNode();

    // Listen for text changes
    _noteController.addListener(() {
      final currentHasChanges = _noteController.text != _originalText;
      if (currentHasChanges != _hasChanges) {
        setState(() {
          _hasChanges = currentHasChanges;
        });
      }
    });
  }

  Future<bool> _onWillPop() async {
    if (!_hasChanges) {
      return true; // No changes, allow navigation
    }

    final result = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Unsaved Changes'),
        content: const Text(
          'You have unsaved changes. What would you like to do?',
        ),
        actions: [
          TextButton(
            onPressed: () =>
                Navigator.of(context).pop(true), // Allow leaving without saving
            child: const Text('Discard'),
          ),
          TextButton(
            onPressed: () async {
              // Save and then navigate
              final appState = Provider.of<AppState>(context, listen: false);
              if (_noteController.text.isNotEmpty) {
                appState.deleteNote(widget.noteIndex);
                await appState.addNote(_noteController.text);
              }
              if (mounted) {
                Navigator.of(context).pop(true); // Allow navigation
              }
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );

    return result ?? false; // Default to not allowing navigation
  }

  @override
  Widget build(BuildContext context) {
    final appState = Provider.of<AppState>(context, listen: false);

    return WillPopScope(
      onWillPop: _onWillPop,
      child: Scaffold(
        appBar: AppBar(
          title: Text(
            _hasChanges ? 'Note*' : 'Note',
          ), // Show asterisk for changes
          backgroundColor: Theme.of(context).colorScheme.inversePrimary,
          actions: [
            IconButton(
              icon: const Icon(Icons.copy),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: _noteController.text));
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(content: Text('Copied to clipboard')),
                );
              },
            ),
            IconButton(
              icon: const Icon(Icons.save),
              onPressed: _hasChanges
                  ? () async {
                      if (_noteController.text.isNotEmpty) {
                        // Show loading indicator
                        showDialog(
                          context: context,
                          barrierDismissible: false,
                          builder: (context) =>
                              const Center(child: CircularProgressIndicator()),
                        );

                        // Remove old note and add updated one
                        appState.deleteNote(widget.noteIndex);
                        await appState.addNote(_noteController.text);

                        if (context.mounted) {
                          Navigator.pop(context); // Close loading
                          Navigator.pop(context); // Close note detail page
                        }
                      } else {
                        // If text is empty, just delete the note and navigate back
                        appState.deleteNote(widget.noteIndex);
                        Navigator.pop(context);
                      }
                    }
                  : null, // Disable save button if no changes
            ),
            PopupMenuButton(
              itemBuilder: (context) => [
                PopupMenuItem(
                  child: const Text('Delete'),
                  onTap: () {
                    // Show confirmation dialog
                    Future.delayed(Duration.zero, () {
                      showDialog(
                        context: context,
                        builder: (context) => AlertDialog(
                          title: const Text('Delete Note'),
                          content: const Text(
                            'Are you sure you want to delete this note?',
                          ),
                          actions: [
                            TextButton(
                              onPressed: () => Navigator.pop(context),
                              child: const Text('Cancel'),
                            ),
                            TextButton(
                              onPressed: () {
                                appState.deleteNote(widget.noteIndex);
                                Navigator.pop(context); // Close dialog
                                Navigator.pop(
                                  context,
                                ); // Close note detail page
                              },
                              child: const Text('Delete'),
                            ),
                          ],
                        ),
                      );
                    });
                  },
                ),
              ],
            ),
          ],
        ),
        body: Padding(
          padding: const EdgeInsets.all(16.0),
          child: GestureDetector(
            onTap: () {
              _focusNode.requestFocus();
            },
            child: TextField(
              controller: _noteController,
              focusNode: _focusNode,
              decoration: const InputDecoration(
                border: InputBorder.none,
                hintText: 'Start typing your note...',
              ),
              maxLines: null,
              expands: true,
              textAlignVertical: TextAlignVertical.top,
              style: const TextStyle(fontSize: 16, height: 1.5),
              onChanged: (text) {
                // Trigger UI update to show * in title
                setState(() {});
              },
            ),
          ),
        ),
      ),
    );
  }

  @override
  void dispose() {
    _noteController.dispose();
    _focusNode.dispose();
    super.dispose();
  }
}
