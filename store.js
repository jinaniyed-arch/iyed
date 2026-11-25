'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');

const KEYS_PATH = path.join(__dirname, config.keysFile);
const LICENSES_PATH = path.join(__dirname, config.licensesFile);

function readJson(file, fallback) {
  try {
    if (!fs.existsSync(file)) return fallback;
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    throw new Error(`Cannot read ${file}: ${e.message}`);
  }
}

function writeJson(file, obj) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, file);
}

const store = {
  getKeys() { return readJson(KEYS_PATH, { publicKeyPem: null, privateKeyPem: null, createdAt: null }); },
  saveKeys(k) { writeJson(KEYS_PATH, k); },
  getLicenses() { return readJson(LICENSES_PATH, {}); },
  saveLicenses(l) { writeJson(LICENSES_PATH, l); },
};

module.exports = store;
