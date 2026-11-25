'use strict';

// License server configuration. All values adjustable here.
module.exports = {
  // Network
  host: '0.0.0.0',
  port: 3000,

  // The domain/path the iOS app calls. Point DNS or the app's URL here.
  // Extracted from the app binary: https://mygold.squareweb.app/api/public/verify
  verifyPath: '/api/public/verify',

  // License owner identity baked into issued licenses
  licenseName: 'iyed',
  packageId: '7e6b6ee2de499840ff99257d62440c2de6048f6474bcb6c76493eb9c1cd92f6a',
  packageToken: '280b',

  // Default license duration when issuing (days). Override with --days.
  defaultDays: 3650,

  // Key sizes
  rsaModulusLength: 2048,

  // Storage
  keysFile: 'keys.json',
  licensesFile: 'licenses.json',

  // Response fields expected by the app (from __cstring xrefs)
  appVersion: '7.0',
  responseMessage: 'OK',
};
