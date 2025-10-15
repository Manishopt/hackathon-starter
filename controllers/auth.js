const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');
const User = require('../models/User');

// WebAuthn configuration
const rpName = 'Hackathon Starter';
const rpID = process.env.WEBAUTHN_RP_ID || 'localhost';
const origin = process.env.BASE_URL || 'http://localhost:3000';

/**
 * GET /account/2fa/setup
 * Setup 2FA page
 */
exports.get2FASetup = async (req, res, next) => {
  try {
    if (req.user.twoFactorEnabled) {
      req.flash('info', { msg: '2FA is already enabled for your account.' });
      return res.redirect('/account');
    }

    // Generate a secret for the user
    const secret = speakeasy.generateSecret({
      name: req.user.email,
      issuer: 'Hackathon Starter',
      length: 32,
    });

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);

    res.render('account/2fa-setup', {
      title: '2FA Setup',
      secret: secret.base32,
      qrCode: qrCodeUrl,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/2fa/setup
 * Enable 2FA
 */
exports.post2FASetup = async (req, res, next) => {
  try {
    const { secret, token } = req.body;

    if (!secret || !token) {
      req.flash('errors', { msg: 'Secret and verification token are required.' });
      return res.redirect('/account/2fa/setup');
    }

    // Verify the token
    const verified = speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2,
    });

    if (!verified) {
      req.flash('errors', { msg: 'Invalid verification code. Please try again.' });
      return res.redirect('/account/2fa/setup');
    }

    // Generate backup codes
    const backupCodes = [];
    for (let i = 0; i < 10; i++) {
      backupCodes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }

    // Save 2FA settings to user
    const user = await User.findById(req.user.id);
    user.twoFactorSecret = secret;
    user.twoFactorEnabled = true;
    user.twoFactorBackupCodes = backupCodes;
    await user.save();

    req.flash('success', { msg: '2FA has been enabled successfully!' });
    res.render('account/2fa-backup-codes', {
      title: '2FA Backup Codes',
      backupCodes,
    });
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/2fa/disable
 * Disable 2FA
 */
exports.post2FADisable = async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!token) {
      req.flash('errors', { msg: 'Verification token is required.' });
      return res.redirect('/account');
    }

    const user = await User.findById(req.user.id);

    // Check if it's a backup code
    const backupCodeIndex = user.twoFactorBackupCodes.indexOf(token.toUpperCase());
    let verified = false;

    if (backupCodeIndex !== -1) {
      // Remove used backup code
      user.twoFactorBackupCodes.splice(backupCodeIndex, 1);
      verified = true;
    } else {
      // Verify TOTP token
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token,
        window: 2,
      });
    }

    if (!verified) {
      req.flash('errors', { msg: 'Invalid verification code.' });
      return res.redirect('/account');
    }

    // Disable 2FA
    user.twoFactorSecret = undefined;
    user.twoFactorEnabled = false;
    user.twoFactorBackupCodes = [];
    await user.save();

    req.flash('success', { msg: '2FA has been disabled.' });
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account/2fa/verify
 * 2FA verification page during login
 */
exports.get2FAVerify = (req, res) => {
  if (!req.session.pendingUser) {
    return res.redirect('/login');
  }

  res.render('account/2fa-verify', {
    title: '2FA Verification',
  });
};

/**
 * POST /account/2fa/verify
 * Verify 2FA token during login
 */
exports.post2FAVerify = async (req, res, next) => {
  try {
    const { token } = req.body;

    if (!req.session.pendingUser || !token) {
      req.flash('errors', { msg: 'Invalid session or missing token.' });
      return res.redirect('/login');
    }

    const user = await User.findById(req.session.pendingUser);
    if (!user || !user.twoFactorEnabled) {
      req.flash('errors', { msg: 'Invalid user or 2FA not enabled.' });
      return res.redirect('/login');
    }

    // Check if it's a backup code
    const backupCodeIndex = user.twoFactorBackupCodes.indexOf(token.toUpperCase());
    let verified = false;

    if (backupCodeIndex !== -1) {
      // Remove used backup code
      user.twoFactorBackupCodes.splice(backupCodeIndex, 1);
      await user.save();
      verified = true;
    } else {
      // Verify TOTP token
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token,
        window: 2,
      });
    }

    if (!verified) {
      req.flash('errors', { msg: 'Invalid verification code.' });
      return res.redirect('/account/2fa/verify');
    }

    // Complete login
    delete req.session.pendingUser;
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      req.flash('success', { msg: 'Success! You are logged in.' });
      res.redirect(req.session.returnTo || '/');
    });
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account/webauthn/register
 * Start WebAuthn registration
 */
exports.getWebAuthnRegister = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user._id.toString(),
      userName: user.email,
      userDisplayName: user.profile.name || user.email,
      attestationType: 'none',
      excludeCredentials: user.webAuthnCredentials.map(cred => ({
        id: Buffer.from(cred.id, 'base64'),
        type: 'public-key',
        transports: cred.transports,
      })),
      authenticatorSelection: {
        residentKey: 'discouraged',
        userVerification: 'preferred',
      },
    });

    req.session.currentChallenge = options.challenge;
    res.json(options);
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/webauthn/register
 * Complete WebAuthn registration
 */
exports.postWebAuthnRegister = async (req, res, next) => {
  try {
    const { body } = req;
    const expectedChallenge = req.session.currentChallenge;

    if (!expectedChallenge) {
      return res.status(400).json({ error: 'No challenge found in session' });
    }

    const verification = await verifyRegistrationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    const { verified, registrationInfo } = verification;

    if (verified && registrationInfo) {
      const user = await User.findById(req.user.id);
      
      const newCredential = {
        id: Buffer.from(registrationInfo.credentialID).toString('base64'),
        publicKey: Buffer.from(registrationInfo.credentialPublicKey).toString('base64'),
        counter: registrationInfo.counter,
        transports: body.response.transports || [],
      };

      user.webAuthnCredentials.push(newCredential);
      await user.save();

      delete req.session.currentChallenge;
      res.json({ verified: true });
    } else {
      res.status(400).json({ error: 'Registration failed' });
    }
  } catch (err) {
    next(err);
  }
};

/**
 * GET /account/webauthn/authenticate
 * Start WebAuthn authentication
 */
exports.getWebAuthnAuthenticate = async (req, res, next) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const user = await User.findOne({ email });
    if (!user || user.webAuthnCredentials.length === 0) {
      return res.status(400).json({ error: 'No credentials found for user' });
    }

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: user.webAuthnCredentials.map(cred => ({
        id: Buffer.from(cred.id, 'base64'),
        type: 'public-key',
        transports: cred.transports,
      })),
      userVerification: 'preferred',
    });

    req.session.currentChallenge = options.challenge;
    req.session.pendingUserEmail = email;
    res.json(options);
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/webauthn/authenticate
 * Complete WebAuthn authentication
 */
exports.postWebAuthnAuthenticate = async (req, res, next) => {
  try {
    const { body } = req;
    const expectedChallenge = req.session.currentChallenge;
    const userEmail = req.session.pendingUserEmail;

    if (!expectedChallenge || !userEmail) {
      return res.status(400).json({ error: 'Invalid session state' });
    }

    const user = await User.findOne({ email: userEmail });
    if (!user) {
      return res.status(400).json({ error: 'User not found' });
    }

    const credential = user.webAuthnCredentials.find(
      cred => cred.id === Buffer.from(body.id, 'base64url').toString('base64')
    );

    if (!credential) {
      return res.status(400).json({ error: 'Credential not found' });
    }

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: Buffer.from(credential.id, 'base64'),
        credentialPublicKey: Buffer.from(credential.publicKey, 'base64'),
        counter: credential.counter,
        transports: credential.transports,
      },
    });

    const { verified, authenticationInfo } = verification;

    if (verified) {
      // Update counter
      credential.counter = authenticationInfo.newCounter;
      await user.save();

      delete req.session.currentChallenge;
      delete req.session.pendingUserEmail;

      // Check if 2FA is enabled
      if (user.twoFactorEnabled) {
        req.session.pendingUser = user._id;
        res.json({ verified: true, requires2FA: true });
      } else {
        req.logIn(user, (err) => {
          if (err) {
            return next(err);
          }
          res.json({ verified: true, requires2FA: false });
        });
      }
    } else {
      res.status(400).json({ error: 'Authentication failed' });
    }
  } catch (err) {
    next(err);
  }
};

/**
 * POST /account/webauthn/remove
 * Remove WebAuthn credential
 */
exports.postWebAuthnRemove = async (req, res, next) => {
  try {
    const { credentialId } = req.body;

    if (!credentialId) {
      req.flash('errors', { msg: 'Credential ID is required.' });
      return res.redirect('/account');
    }

    const user = await User.findById(req.user.id);
    user.webAuthnCredentials = user.webAuthnCredentials.filter(
      cred => cred.id !== credentialId
    );
    await user.save();

    req.flash('success', { msg: 'Biometric credential removed successfully.' });
    res.redirect('/account');
  } catch (err) {
    next(err);
  }
};
