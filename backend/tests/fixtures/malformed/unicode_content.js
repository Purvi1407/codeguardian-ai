// -*- coding: utf-8 -*-
// Module with non-ASCII content to check the analyzer handles encoding
// correctly instead of crashing on decode/index errors.

function grüße(name) {
  // Uses a non-ASCII identifier (valid in JS) and emoji in a string
  // literal 😀, plus a real vulnerability nearby to confirm
  // unicode content doesn't break line-number tracking.
  const message = `Hallo, ${name}! 👋`;
  return message;
}

function weak_crypto_hash__near_unicode() {
  // The unicode content above must not shift or break detection here.
  return crypto.createHash('md5');
}
