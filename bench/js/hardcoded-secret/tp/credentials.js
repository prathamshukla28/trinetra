// Credentials committed to source. (All values are fake; the AWS key is AWS's
// documented example key.)

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"; // expect: hardcoded-secret

const dbPassword = "Tr0ub4dor&3xyz"; // expect: hardcoded-secret

const config = {
  apiKey: "9f8e7d6c5b4a39281706f5e4d3c2b1a0", // expect: hardcoded-secret
  authToken: "tok3f9a8b7c6d5e4f3a2b1c", // expect: hardcoded-secret
};

let adminSecret;
adminSecret = "s3cr3t-admin-value-42"; // expect: hardcoded-secret

class Client {
  privateKey = "k9Q2mX7pL4vR8sT1wZ6y"; // expect: hardcoded-secret
}

const headers = { "x-api-key": "c0ffee00deadbeef1234" }; // expect: hardcoded-secret

module.exports = { AWS_ACCESS_KEY_ID, dbPassword, config, adminSecret, Client, headers };
