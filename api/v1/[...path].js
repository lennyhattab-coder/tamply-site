const walletRegister = require('../wallet-register');
const walletPasses = require('../wallet-passes');
const walletPass = require('../wallet-pass');
const walletLog = require('../wallet-log');

// Catch-all qui route les URLs du Web Service PassKit (webServiceURL = https://tamply.fr/api)
// vers les handlers correspondants :
//   /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}/{serialNumber}  (POST/DELETE)
//   /v1/devices/{deviceLibraryIdentifier}/registrations/{passTypeIdentifier}                 (GET)
//   /v1/passes/{passTypeIdentifier}/{serialNumber}                                           (GET)
//   /v1/log                                                                                  (POST)
module.exports = async (req, res) => {
  const segments = Array.isArray(req.query.path) ? req.query.path : [req.query.path].filter(Boolean);

  if (segments[0] === 'devices' && segments[2] === 'registrations') {
    req.query.deviceLibraryIdentifier = segments[1];
    req.query.passTypeIdentifier = segments[3];
    if (segments[4]) {
      req.query.serialNumber = segments[4];
      return walletRegister(req, res);
    }
    return walletPasses(req, res);
  }

  if (segments[0] === 'passes' && segments[1] && segments[2]) {
    req.query.passTypeIdentifier = segments[1];
    req.query.serialNumber = segments[2];
    return walletPass(req, res);
  }

  if (segments[0] === 'log') {
    return walletLog(req, res);
  }

  return res.status(404).end();
};
