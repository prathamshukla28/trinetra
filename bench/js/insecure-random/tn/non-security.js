// Tricky negatives: randomness with no security role.

function jitter(base) {
  return base + Math.random() * 100; // ok: insecure-random (timing jitter)
}

const shuffle = (arr) => arr.sort(() => Math.random() - 0.5); // ok: insecure-random (UI shuffle)

function authRetryDelay(attempt) {
  return 2 ** attempt * 100 + Math.random() * 50; // ok: insecure-random (backoff jitter in an auth-named function)
}

module.exports = { jitter, shuffle, authRetryDelay };
