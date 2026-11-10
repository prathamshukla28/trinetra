// Math.random() used for security-sensitive values.

function generateToken() {
  return Math.random().toString(36).slice(2); // expect: insecure-random
}

const sessionId = Math.random().toString(16).slice(2); // expect: insecure-random

function resetPassword(user) {
  const resetCode = Math.floor(Math.random() * 1e6); // expect: insecure-random
  return { user, resetCode };
}

module.exports = { generateToken, sessionId, resetPassword };
