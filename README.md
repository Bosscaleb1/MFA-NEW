# Multi-Factor Authentication (MFA) System

A complete authentication system with TOTP-based two-factor authentication built with Flask, SQLite, and vanilla HTML/CSS/JavaScript.

## Features

User Registration & Login
TOTP-based Two-Factor Authentication (Google Authenticator compatible)
Passkey (WebAuthn) registration and sign-in
QR Code generation for easy authenticator app setup
Backup codes for account recovery
SQLite Database for user storage
Responsive UI with modern design
Session management
Password hashing with Werkzeug

## Tech Stack

- **Backend:** Python Flask
- **Database:** SQLite with SQLAlchemy ORM
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Authentication:** Flask-Login
- **MFA:** PyOTP (TOTP implementation)
- **Passkeys:** WebAuthn
- **QR Codes:** qrcode library

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Setup Steps

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the application:**
   ```bash
   python run.py
   ```

3. **Access the application:**
   - Open your browser and go to: `http://localhost:5000`
   - Or from another device on the same network: `http://YOUR_LAPTOP_IP:5000`

## Usage

### Registration
1. Click "Register" on the login page
2. Enter username, email, and password
3. Click "Register"

### First Login (without MFA)
1. Click "Login"
2. Enter your credentials
3. You'll be taken to the dashboard

### Setting up MFA
1. From the dashboard, click "Enable MFA"
2. Click "Generate QR Code"
3. Scan the QR code with an authenticator app:
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - FreeOTP
   - Any TOTP-compatible app
4. Enter the 6-digit code from your app
5. Save your backup codes in a safe place
6. Your account is now protected with MFA!

### Login with MFA Enabled
1. Enter your credentials on the login page
2. You'll be prompted for a 6-digit code from your authenticator app
3. Alternative: Click "Don't have your authenticator app?" to use a backup code

### Passkey Setup and Login
1. Log in normally and open Dashboard
2. In the Passkey section, click "Enable Passkey"
3. Complete your browser/device passkey prompt (Face ID, fingerprint, PIN, or security key)
4. On the login page, enter your username and click "Sign In with Passkey"

### Backup Codes
- Backup codes are generated when you enable MFA
- Each backup code can be used once
- Download and save them securely
- Use them if you lose access to your authenticator app

## Project Structure

```
mfa-auth-system/
├── app/
│   ├── __init__.py          # Flask app factory
│   ├── models.py            # User model with MFA logic
│   ├── auth.py              # Authentication routes
│   ├── templates/
│   │   ├── base.html        # Base template
│   │   ├── register.html    # Registration page
│   │   ├── login.html       # Login page
│   │   ├── setup_mfa.html   # MFA setup page
│   │   ├── verify_mfa.html  # MFA verification page
│   │   └── dashboard.html   # User dashboard
│   └── static/
│       └── css/
│           └── style.css    # Styling
├── run.py                   # Application entry point
├── requirements.txt         # Python dependencies
└── README.md               # This file
```

## Database

The application uses SQLite which automatically creates `mfa_auth.db` in the root directory on first run.

**User Table Columns:**
- `id` - User ID (primary key)
- `username` - Unique username
- `email` - Unique email address
- `password_hash` - Hashed password
- `mfa_enabled` - Boolean indicating if MFA is active
- `totp_secret` - TOTP secret key (base32 encoded)
- `backup_codes` - Comma-separated backup codes
- `passkey_enabled` - Boolean indicating if a passkey is active
- `passkey_credential_id` - Stored WebAuthn credential ID (base64url)
- `passkey_public_key` - Stored WebAuthn credential public key (base64url)
- `passkey_sign_count` - Signature counter for replay protection
- `created_at` - Account creation timestamp

## Testing on Multiple Devices

### Same Network
1. Find your laptop's IP address:
   ```bash
   # Windows
   ipconfig
   
   # Linux/Mac
   ifconfig
   ```
   
2. Access from another device:
   ```
   http://YOUR_LAPTOP_IP:5000
   ```

### Testing with Different Browsers
- Open multiple browser tabs on the same device
- Each tab will have independent sessions

## Security Notes

**Important for Production:**
- Change the `SECRET_KEY` in `app/__init__.py` to a secure random value
- Use environment variables for sensitive configuration
- Enable HTTPS/SSL for production
- Ensure RP ID / origin are configured correctly for passkeys in production
- Use a production WSGI server (Gunicorn, uWSGI)
- Add CSRF protection
- Implement rate limiting on login/MFA endpoints

## Default Configuration

- Database: SQLite (`mfa_auth.db`)
- Host: `0.0.0.0` (accessible from any network interface)
- Port: `5000`
- Debug Mode: `True` (set to `False` in production)

## Troubleshooting

### "Address already in use" error
The port 5000 is already in use. Change the port in `run.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Use 5001 instead
```

### QR Code not showing
Ensure `qrcode` and `Pillow` libraries are installed:
```bash
pip install qrcode pillow
```

### TOTP codes not matching
- Ensure your authenticator app and server time are synchronized
- Try the next TOTP code if the current one fails
- The valid time window is usually ±30 seconds

### Passkey not available
- Passkeys require a secure context in the browser (`https://` or `http://localhost`)
- Make sure dependencies are updated: `pip install -r requirements.txt`

## License

This project is for educational purposes.

## Support

For issues or questions, please refer to the documentation or check the code comments.
