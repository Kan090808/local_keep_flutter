# Local Keep - Encrypted Notes App

A secure, local-first notes application built with Flutter that uses AES encryption to protect your notes.

## Project Status & License

- **Open Source**: You may use, study, and fork this project for non-profit and personal purposes only.
- **No Commercial Use**: Commercial/profit use is strictly prohibited.
- **No Pull Requests**: This repository does not accept pull requests. For improvements, please fork for non-profit use.
- **License**: See the License section below for details.

## Features

- Strong AES-256 encryption (PBKDF2 key derivation)
- Local-only storage (no cloud, no analytics)
- Multiple passwords for different note collections
- Cross-platform: iOS, Android, desktop
- Material Design UI with staggered grid

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/local-keep.git
   cd local-keep
   ```
2. Install dependencies:
   ```bash
   flutter pub get
   ```
3. Run the app:
   ```bash
   flutter run
   ```

## Security Notes

- Passwords are never stored or sent anywhere
- Each note uses a unique salt and IV
- All data remains on your device
- Use strong, unique passwords

## License

This project is licensed for non-profit, educational, and personal use only. Commercial use is not permitted. Forks for non-profit use are welcome. Pull requests will not be accepted.

See the LICENSE file for full terms.

---

**Remember:** Your security is only as strong as your weakest link. Keep your devices secure and use strong passwords! 🔒
