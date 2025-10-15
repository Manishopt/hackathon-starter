# 2FA Code Generator and Biometric Login Implementation

This implementation adds Two-Factor Authentication (2FA) using TOTP (Time-based One-Time Password) and biometric login support using WebAuthn to the hackathon-starter project.

## Features Implemented

### 1. Two-Factor Authentication (2FA)
- **TOTP Code Generation**: Uses `speakeasy` library to generate time-based one-time passwords
- **QR Code Setup**: Generates QR codes for easy setup with authenticator apps
- **Backup Codes**: Provides 10 single-use backup codes for account recovery
- **Integration with Login Flow**: Seamlessly integrates with existing authentication

### 2. Biometric Login (WebAuthn)
- **Fingerprint/Face ID Support**: Uses WebAuthn API for biometric authentication
- **Multiple Device Support**: Users can register multiple biometric devices
- **Fallback to 2FA**: If 2FA is enabled, biometric login still requires 2FA verification
- **Cross-Platform Compatibility**: Works with Windows Hello, Touch ID, Face ID, and hardware security keys

## Files Added/Modified

### Controllers
- `controllers/auth.js` - New controller handling 2FA and WebAuthn functionality
- `controllers/user.js` - Modified to integrate 2FA verification in login flow

### Models
- `models/User.js` - Extended with 2FA and WebAuthn credential fields

### Views
- `views/account/2fa-setup.pug` - 2FA setup page with QR code
- `views/account/2fa-backup-codes.pug` - Display backup codes after setup
- `views/account/2fa-verify.pug` - 2FA verification during login
- `views/account/profile.pug` - Updated with 2FA and biometric management
- `views/account/login.pug` - Added biometric login button

### Routes
- `app.js` - Added new routes for 2FA and WebAuthn endpoints

## Dependencies Added
- `speakeasy` - TOTP generation and verification
- `qrcode` - QR code generation for 2FA setup
- `@simplewebauthn/server` - WebAuthn server-side implementation
- `@simplewebauthn/browser` - WebAuthn client-side implementation

## Usage Instructions

### Setting up 2FA
1. Log in to your account
2. Go to Account Management page
3. Click "Enable 2FA" in the Two-Factor Authentication section
4. Install an authenticator app (Google Authenticator, Microsoft Authenticator, etc.)
5. Scan the QR code or enter the secret manually
6. Enter the 6-digit code from your app to verify
7. Save the backup codes in a secure location

### Setting up Biometric Login
1. Log in to your account
2. Go to Account Management page
3. Click "Setup Biometric Login" in the Biometric Login section
4. Follow your browser's prompts to register your biometric (fingerprint, face, etc.)
5. Your device will be registered and can be used for future logins

### Using Biometric Login
1. Go to the login page
2. Enter your email address
3. Click "Biometric Login" button
4. Use your registered biometric method
5. If 2FA is enabled, you'll be redirected to enter your 2FA code

## Security Features

### 2FA Security
- Secrets are stored encrypted in the database
- Backup codes are single-use and removed after consumption
- Time window validation prevents replay attacks
- Rate limiting on authentication attempts

### WebAuthn Security
- Public key cryptography ensures credentials never leave the device
- Challenge-response authentication prevents replay attacks
- Counter validation prevents cloned authenticators
- Origin validation prevents phishing attacks

## Environment Variables

For production deployment, consider setting:
- `WEBAUTHN_RP_ID` - Your domain name for WebAuthn
- `BASE_URL` - Your application's base URL (required for WebAuthn)

## Browser Compatibility

### WebAuthn Support
- Chrome 67+
- Firefox 60+
- Safari 14+
- Edge 18+

### Required Features
- HTTPS (required for WebAuthn in production)
- Secure context (localhost works for development)

## Testing

To test the implementation:

1. **2FA Testing**:
   - Create an account and enable 2FA
   - Test login with TOTP codes
   - Test backup code usage
   - Test disabling 2FA

2. **WebAuthn Testing**:
   - Register a biometric credential
   - Test biometric login
   - Test with multiple devices
   - Test credential removal

3. **Integration Testing**:
   - Test biometric login with 2FA enabled
   - Test fallback scenarios
   - Test error handling

## Production Considerations

1. **HTTPS Required**: WebAuthn requires HTTPS in production
2. **Database Backup**: Ensure 2FA secrets and WebAuthn credentials are backed up
3. **Rate Limiting**: Consider additional rate limiting for authentication endpoints
4. **Monitoring**: Monitor failed authentication attempts
5. **User Education**: Provide clear instructions for users on setup and usage

## Troubleshooting

### Common Issues
1. **WebAuthn not working**: Ensure HTTPS and proper domain configuration
2. **2FA codes not working**: Check server time synchronization
3. **QR codes not displaying**: Verify QRCode library installation
4. **Backup codes not working**: Ensure proper case handling (uppercase)

### Debug Tips
- Check browser console for WebAuthn errors
- Verify CSRF tokens are properly handled
- Ensure session management works correctly
- Test with different browsers and devices
