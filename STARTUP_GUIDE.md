# Quick Start Guide for 2FA and WebAuthn Features

## Prerequisites

1. **MongoDB**: Make sure your local MongoDB is running
   - Start MongoDB service:
     - Windows: `net start MongoDB` (as administrator) or start MongoDB Compass
     - macOS: `brew services start mongodb-community`
     - Linux: `sudo systemctl start mongod`
   - The connection string is configured for local MongoDB in `.env.example`

2. **Node.js**: Ensure Node.js is installed (version 22+ recommended)

## Starting the Application

### Windows PowerShell Execution Policy Fix
If you encounter "running scripts is disabled" error, use one of these solutions:

**Option 1: Use Command Prompt instead of PowerShell**
```cmd
cmd /c "npm install"
cmd /c "npm start"
```

**Option 2: Temporarily allow scripts in PowerShell (as Administrator)**
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Installation Steps:

1. **Install Dependencies** (if not already done):
   ```bash
   # Use cmd if PowerShell has execution policy issues
   cmd /c "npm install"
   ```

2. **Start the Server**:
   ```bash
   # Use cmd if PowerShell has execution policy issues
   cmd /c "npm start"
   ```
   Or directly:
   ```bash
   cmd /c "node app.js"
   ```

3. **Access the Application**:
   - Open your browser and go to: http://localhost:8080

## Testing the Features

### 1. Create an Account
1. Go to http://localhost:8080/signup
2. Create a new account with email and password
3. Log in to your account

### 2. Enable 2FA
1. After logging in, go to "Account Management"
2. In the "Two-Factor Authentication" section, click "Enable 2FA"
3. Install an authenticator app on your phone (Google Authenticator, Microsoft Authenticator, etc.)
4. Scan the QR code or enter the secret manually
5. Enter the 6-digit code from your app
6. Save the backup codes in a secure location

### 3. Test 2FA Login
1. Log out of your account
2. Log in again with your email and password
3. You'll be redirected to enter your 2FA code
4. Enter the 6-digit code from your authenticator app

### 4. Setup Biometric Login
1. Go to "Account Management"
2. In the "Biometric Login" section, click "Setup Biometric Login"
3. Follow your browser's prompts to register your biometric (fingerprint, face, etc.)
4. Your device will be registered

### 5. Test Biometric Login
1. Log out of your account
2. On the login page, enter your email address
3. Click "Biometric Login" button
4. Use your registered biometric method
5. If 2FA is enabled, you'll still need to enter your 2FA code

## Troubleshooting

### Common Issues

1. **MongoDB Connection Error**:
   - Make sure MongoDB is running
   - Check if the connection string in `.env.example` is correct

2. **Server Won't Start**:
   - Check if port 8080 is available
   - Make sure all dependencies are installed

3. **WebAuthn Not Working**:
   - Ensure you're using a supported browser (Chrome 67+, Firefox 60+, Safari 14+, Edge 18+)
   - For production, HTTPS is required for WebAuthn

4. **2FA Codes Not Working**:
   - Check that your system time is synchronized
   - Make sure you're entering the current code (codes change every 30 seconds)

### Browser Console Errors
If you encounter issues, check the browser console (F12) for error messages.

## Features Available

✅ **Two-Factor Authentication (2FA)**
- TOTP code generation with QR codes
- Backup codes for account recovery
- Integration with popular authenticator apps

✅ **Biometric Login (WebAuthn)**
- Fingerprint authentication
- Face ID support (on supported devices)
- Windows Hello integration
- Hardware security key support

✅ **Security Features**
- Rate limiting on authentication attempts
- Secure token storage
- Challenge-response authentication
- Origin validation

## Next Steps

- For production deployment, set up HTTPS
- Configure proper environment variables
- Set up email service for notifications
- Consider additional security measures like IP whitelisting

Enjoy your enhanced security features! 🔐
