// Adapter for Claude (Anthropic SDK) — powers the REBUILD stage's code
// generation. Isolated here so the rest of the pipeline never touches the SDK.
//
// Uses claude-opus-5-5 with adaptive thinking. Credentials resolve from the
// environment (ANTHROPIC_API_KEY / ANTHROPIC_AUTH_TOKEN) or an `ant auth login`
// profile; if none are available the caller falls back to scaffolding.

import Anthropic from "@anthropic-ai/sdk";

const MODEL = "claude-opus-5-5";

export function isLlmConfigured() {
  return Boolean(process.env.ANTHROPIC_API_KEY || process.env.ANTHROPIC_AUTH_TOKEN);
}

// Pull a ```json ... ``` (or bare JSON) object out of the model's reply.
export function extractJson(text) {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  const raw = fenced ? fenced[1] : text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
  return JSON.parse(raw);
}

/**
 * Reimplement a unit of code cleanly, test-first.
 * @returns {Promise<{test: string, impl: string, notes: string}>}
 */
export async function reimplement({ name, language, source, priorError }) {
  const client = new Anthropic();

  const system =
    "You are a senior engineer rebuilding code from a reverse-engineered artifact. " +
    "Work test-first: write a focused test that pins the observable behavior, then the " +
    "cleanest modern implementation that passes it. Preserve behavior; do not invent features. " +
    "Reply with ONLY a JSON object: " +
    '{"test": "<test file source>", "impl": "<implementation file source>", "notes": "<one line>"}. ' +
    `Target language: ${language}. The implementation file is imported by the test as "./${name}.js" ` +
    `and must export its functions. Tests use node:test and node:assert.`;

  const retry = priorError ? `\n\nThe previous attempt failed its test with:\n${priorError}\nFix it.` : "";

  const response = await client.messages.create({
    model: MODEL,
    max_tokens: 16000,
    thinking: { type: "adaptive" },
    system,
    messages: [
      {
        role: "user",
        content: `Reverse-engineered source for \`${name}\`:\n\n\`\`\`\n${source}\n\`\`\`${retry}`,
      },
    ],
  });

  const text = response.content
    .filter((b) => b.type === "text")
    .map((b) => b.text)
    .join("\n");
  return extractJson(text);
}
