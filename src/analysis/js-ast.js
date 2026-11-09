// Trinetra's own JavaScript analyzer: parses each file to an AST (acorn) and
//   1. resolves module bindings (import / require / destructuring) so a call is
//      matched by *what it is* — `child_process.exec` — not by its spelling
//      (so `regex.exec(str)` is never mistaken for a shell call);
//   2. tracks simple intra-function taint from obvious untrusted sources
//      (process.argv, process.env, req.query/body/params/…, location.*) through
//      assignments, destructuring, concatenation, templates and calls;
//   3. applies security rules at sinks (eval/Function/vm, child_process,
//      dynamic require/import, innerHTML/document.write, weak hashes, secrets,
//      fs paths, SQL strings, outbound requests);
//   4. records facts — imports, exports, functions, and the capabilities each
//      function exercises — which the UNDERSTAND stage turns into a summary.

import * as acorn from "acorn";
import jsx from "acorn-jsx";

const Parser = acorn.Parser.extend(jsx());
const BASE_OPTS = {
  ecmaVersion: "latest",
  locations: true,
  allowHashBang: true,
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  allowImportExportEverywhere: true,
};

export function parseJs(text) {
  try {
    return Parser.parse(text, { ...BASE_OPTS, sourceType: "module" });
  } catch (moduleErr) {
    try {
      return Parser.parse(text, { ...BASE_OPTS, sourceType: "script" });
    } catch {
      throw moduleErr;
    }
  }
}

// ---------------------------------------------------------------------------
// Generic AST helpers

const SKIP_KEYS = new Set(["type", "start", "end", "loc", "range", "raw", "regex", "bigint"]);

function* childNodes(node) {
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const v = node[key];
    if (Array.isArray(v)) {
      for (const x of v) if (x && typeof x.type === "string") yield x;
    } else if (v && typeof v === "object" && typeof v.type === "string") {
      yield v;
    }
  }
}

const FUNCTION_TYPES = new Set(["FunctionDeclaration", "FunctionExpression", "ArrowFunctionExpression"]);
const HTTP_VERBS = new Set(["get", "post", "put", "patch", "delete", "all", "use", "head", "options"]);

const normalizeModule = (m) => String(m).replace(/^node:/, "");

const propName = (member) => {
  if (!member || member.type !== "MemberExpression") return null;
  if (!member.computed && member.property.type === "Identifier") return member.property.name;
  if (member.computed && member.property.type === "Literal" && typeof member.property.value === "string")
    return member.property.value;
  return null;
};

const keyName = (key) =>
  key?.type === "Identifier" ? key.name : key?.type === "Literal" ? String(key.value) : null;

const isRequireCall = (n) =>
  n?.type === "CallExpression" &&
  n.callee.type === "Identifier" &&
  n.callee.name === "require" &&
  n.arguments[0]?.type === "Literal" &&
  typeof n.arguments[0].value === "string";

// A string fixed at authoring time: "x", `x`, "a" + "b".
export function isStaticString(n) {
  if (!n) return false;
  if (n.type === "Literal") return typeof n.value === "string";
  if (n.type === "TemplateLiteral") return n.expressions.length === 0;
  if (n.type === "BinaryExpression" && n.operator === "+")
    return isStaticString(n.left) && isStaticString(n.right);
  return false;
}

const staticValue = (n) =>
  n.type === "Literal"
    ? n.value
    : n.type === "TemplateLiteral"
      ? n.quasis.map((q) => q.value.cooked).join("")
      : null;

// ---------------------------------------------------------------------------
// Rule metadata

const RULES = {
  "dynamic-eval": {
    severity: "high",
    title: "Dynamic code execution with a non-literal argument",
    why: "eval / new Function / vm run strings as code; attacker-influenced input becomes arbitrary code.",
  },
  "command-injection": {
    severity: "high",
    title: "Shell command built from a non-literal value",
    why: "child_process exec/execSync (or spawn with shell:true) passes the string to /bin/sh — any input in it is command injection.",
  },
  "dynamic-require": {
    severity: "medium",
    title: "Module loaded from a non-literal path",
    why: "require()/import() of a computed path can load attacker-chosen code.",
  },
  "dom-xss": {
    severity: "medium",
    title: "HTML injected into the DOM from a non-literal value",
    why: "innerHTML / outerHTML / document.write with untrusted data is DOM-based XSS.",
  },
  "weak-hash": {
    severity: "medium",
    title: "Weak hashing algorithm (MD5 / SHA-1)",
    why: "MD5 and SHA-1 are broken for integrity, signatures, and password storage.",
  },
  "hardcoded-secret": {
    severity: "high",
    title: "Hardcoded secret",
    why: "Credentials in source leak through the repo, logs, and shipped builds.",
  },
  "insecure-random": {
    severity: "low",
    title: "Math.random() used for a security-sensitive value",
    why: "Math.random is predictable — unsafe for tokens, IDs, nonces, or keys. Use crypto.randomUUID / randomBytes.",
  },
  "path-traversal": {
    severity: "high",
    title: "Filesystem path built from untrusted input",
    why: "Unsanitized input in a file path allows ../ traversal to read or write arbitrary files.",
  },
  "sql-injection": {
    severity: "high",
    title: "SQL query built from untrusted input",
    why: "String-built SQL with user input is SQL injection; use parameterized queries.",
  },
  ssrf: {
    severity: "medium",
    title: "Outbound request to a URL built from untrusted input",
    why: "User-controlled request targets enable SSRF against internal services.",
  },
};

const SECRET_PATTERNS = [
  /AKIA[0-9A-Z]{16}/,
  /ASIA[0-9A-Z]{16}/,
  /(?:sk|rk)_live_[0-9A-Za-z]{10,}/,
  /gh[pousr]_[A-Za-z0-9]{36}/,
  /github_pat_[A-Za-z0-9_]{22,}/,
  /xox[baprs]-[A-Za-z0-9-]{10,}/,
  /AIza[0-9A-Za-z_-]{35}/,
  /sk-ant-[A-Za-z0-9_-]{20,}/,
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/,
];
const SECRET_NAME =
  /(pass(word|wd)?|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|token|private[_-]?key)/i;
const NOT_SECRET_NAME =
  /(url|uri|path|file|field|name|label|placeholder|header|type|length|min|max|regex|pattern|prompt|message|env|endpoint|count|policy|hint)$/i;
const PLACEHOLDER =
  /^(x+|\*+|<.*>|\$\{.*\}|your[_-].*|changeme|change[_-]me|example.*|dummy.*|placeholder.*|redacted.*)$/i;

export function looksLikeSecretValue(v) {
  if (typeof v !== "string") return false;
  if (SECRET_PATTERNS.some((re) => re.test(v))) return true;
  return false;
}

function plausibleNamedSecret(name, value) {
  if (!name || typeof value !== "string") return false;
  if (!SECRET_NAME.test(name) || NOT_SECRET_NAME.test(name)) return false;
  if (value.length < 8 || /\s/.test(value) || PLACEHOLDER.test(value)) return false;
  if (/^(.)\1+$/.test(value)) return false;
  if (/^[A-Z][A-Z0-9_]+$/.test(value)) return false; // an env var *name*, not a value
  return true;
}

export const redact = (v) => (v.length <= 6 ? "***" : `${v.slice(0, 4)}…(redacted, ${v.length} chars)`);

const SENSITIVE_NAME = /token|secret|key|pass|nonce|salt|session|otp|uuid|csrf|auth|code|^id$|Id$|_id$/i;

// Untrusted-input sources, recognised by shape.
const REQUEST_OBJECTS = new Set(["req", "request", "ctx"]);
const REQUEST_PROPS = new Set([
  "query",
  "body",
  "params",
  "headers",
  "cookies",
  "url",
  "path",
  "originalUrl",
  "files",
]);
const DOM_PROPS = new Set(["hash", "search", "href", "pathname"]);

function sourceOf(n) {
  if (n.type !== "MemberExpression") return null;
  const p = propName(n);
  const obj = n.object;
  if (obj.type === "Identifier") {
    if (obj.name === "process" && p === "argv") return "process.argv";
    if (obj.name === "process" && p === "env") return "process.env";
    if (REQUEST_OBJECTS.has(obj.name) && REQUEST_PROPS.has(p)) return `${obj.name}.${p}`;
    if (obj.name === "location" && DOM_PROPS.has(p)) return `location.${p}`;
    if (obj.name === "document" && ["URL", "cookie", "referrer", "documentURI"].includes(p))
      return `document.${p}`;
  }
  if (obj.type === "MemberExpression") {
    const inner = propName(obj);
    if (
      obj.object.type === "Identifier" &&
      obj.object.name === "ctx" &&
      inner === "request" &&
      REQUEST_PROPS.has(p)
    )
      return `ctx.request.${p}`;
    if (
      obj.object.type === "Identifier" &&
      obj.object.name === "window" &&
      inner === "location" &&
      DOM_PROPS.has(p)
    )
      return `location.${p}`;
  }
  return null;
}

const SANITIZERS = new Set([
  "path.basename",
  "global.Number",
  "global.parseInt",
  "global.parseFloat",
  "global.Boolean",
  "global.encodeURIComponent",
  "global.encodeURI",
  "?.escape",
  "?.escapeHtml",
  "?.quote",
  "?.sanitize",
  "?.isInteger",
]);

const FS_PATH_SINKS = new Set([
  "readFile",
  "readFileSync",
  "createReadStream",
  "writeFile",
  "writeFileSync",
  "createWriteStream",
  "appendFile",
  "appendFileSync",
  "unlink",
  "unlinkSync",
  "rm",
  "rmSync",
  "readdir",
  "readdirSync",
  "open",
  "openSync",
  "copyFile",
  "copyFileSync",
]);
const FS_WRITES = /^(write|append|createWrite|unlink|rm|mkdir|rename|copyFile|chmod)/;

// Map a resolved callee to a capability (what the code can *do*).
function capabilityOf(callee) {
  if (!callee) return null;
  const [mod, member] = splitCallee(callee);
  if (mod === "child_process") return "runs shell commands / processes";
  if (callee === "global.eval" || callee === "global.Function" || mod === "vm")
    return "evaluates dynamic code";
  if (mod === "fs" || mod === "fs/promises")
    return FS_WRITES.test(member) ? "writes to the filesystem" : "reads the filesystem";
  if (mod === "crypto") return "uses cryptography";
  if (callee === "Math.random") return "generates random values";
  if (callee === "global.fetch" || ((mod === "http" || mod === "https") && /^(request|get)$/.test(member)))
    return "makes network requests";
  if ((mod === "http" || mod === "https") && member === "createServer") return "serves HTTP";
  if (mod === "net" || mod === "dgram" || mod === "tls") return "opens raw network sockets";
  if (mod === "os") return "inspects the host system";
  if (mod === "worker_threads" || mod === "cluster") return "spawns workers";
  return null;
}

function splitCallee(callee) {
  const i = callee.lastIndexOf(".");
  return i < 0 ? [callee, ""] : [callee.slice(0, i), callee.slice(i + 1)];
}

// ---------------------------------------------------------------------------
// The analyzer

class FunctionCtx {
  constructor(name, line, parent, params = []) {
    this.name = name;
    this.line = line;
    this.parent = parent;
    this.params = params;
    this.tainted = new Map();
    this.capabilities = new Map(); // capability → Set(callee)
    this.calls = [];
  }

  lookup(name) {
    for (let c = this; c; c = c.parent) if (c.tainted.has(name)) return c.tainted.get(name);
    return null;
  }

  addCapability(cap, evidence) {
    if (!cap) return;
    if (!this.capabilities.has(cap)) this.capabilities.set(cap, new Set());
    this.capabilities.get(cap).add(evidence);
  }
}

const GLOBAL_CALLS = new Set([
  "eval",
  "Function",
  "require",
  "fetch",
  "Number",
  "parseInt",
  "parseFloat",
  "Boolean",
]);
const GLOBAL_CALLS_MORE = new Set(["encodeURIComponent", "encodeURI", "setTimeout", "setInterval"]);
const GLOBAL_OBJECTS = new Set([
  "process",
  "Math",
  "JSON",
  "document",
  "window",
  "location",
  "console",
  "res",
  "Reflect",
]);

class JsAnalyzer {
  constructor(file, text, ast) {
    this.file = file;
    this.lines = text.split("\n");
    this.ast = ast;
    this.ns = new Map(); // local → module (namespace/default import)
    this.members = new Map(); // local → { mod, name }
    this.imports = [];
    this.exported = new Set();
    this.functions = [];
    this.findings = [];
    this.declNames = [];
  }

  // ---- pass 1: imports, requires, exports --------------------------------
  collectBindings() {
    const visit = (n) => {
      switch (n.type) {
        case "ImportDeclaration": {
          const mod = normalizeModule(n.source.value);
          const names = [];
          for (const s of n.specifiers) {
            if (s.type === "ImportSpecifier") {
              const imported = keyName(s.imported);
              this.members.set(s.local.name, { mod, name: imported });
              names.push(imported);
            } else {
              this.ns.set(s.local.name, mod);
              names.push(s.type === "ImportNamespaceSpecifier" ? "*" : "default");
            }
          }
          this.imports.push({ module: n.source.value, names, line: n.loc.start.line, kind: "import" });
          break;
        }
        case "VariableDeclarator":
          this.bindRequire(n);
          break;
        case "CallExpression":
          if (isRequireCall(n))
            this.imports.push({
              module: n.arguments[0].value,
              names: [],
              line: n.loc.start.line,
              kind: "require",
            });
          break;
        case "ImportExpression":
          if (isStaticString(n.source))
            this.imports.push({
              module: staticValue(n.source),
              names: [],
              line: n.loc.start.line,
              kind: "dynamic-import",
            });
          break;
        case "ExportNamedDeclaration":
          if (n.declaration) {
            if (n.declaration.id) this.exported.add(n.declaration.id.name);
            for (const d of n.declaration.declarations ?? [])
              if (d.id.type === "Identifier") this.exported.add(d.id.name);
          }
          for (const s of n.specifiers ?? []) this.exported.add(keyName(s.local));
          break;
        case "ExportDefaultDeclaration":
          if (n.declaration.type === "Identifier") this.exported.add(n.declaration.name);
          else if (n.declaration.id) this.exported.add(n.declaration.id.name);
          break;
        case "AssignmentExpression":
          this.collectCommonJsExport(n);
          break;
      }
      for (const c of childNodes(n)) visit(c);
    };
    visit(this.ast);
    // Merge duplicate require() records produced by the declarator + call visits.
    const seen = new Set();
    this.imports = this.imports.filter((i) => {
      const k = `${i.module}|${i.line}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  bindRequire(decl) {
    let init = decl.init;
    if (init?.type === "AwaitExpression") init = init.argument;
    let mod = null;
    let member = null;
    if (isRequireCall(init)) mod = normalizeModule(init.arguments[0].value);
    else if (init?.type === "ImportExpression" && isStaticString(init.source))
      mod = normalizeModule(staticValue(init.source));
    else if (init?.type === "MemberExpression" && isRequireCall(init.object)) {
      mod = normalizeModule(init.object.arguments[0].value);
      member = propName(init);
    }
    if (!mod) return;
    if (member) {
      if (decl.id.type === "Identifier") {
        if (mod === "fs" && member === "promises") this.ns.set(decl.id.name, "fs/promises");
        else this.members.set(decl.id.name, { mod, name: member });
      }
      return;
    }
    if (decl.id.type === "Identifier") this.ns.set(decl.id.name, mod);
    else if (decl.id.type === "ObjectPattern") {
      for (const p of decl.id.properties) {
        if (p.type !== "Property") continue;
        const imported = keyName(p.key);
        const local = p.value.type === "AssignmentPattern" ? p.value.left : p.value;
        if (local.type !== "Identifier") continue;
        if (mod === "fs" && imported === "promises") this.ns.set(local.name, "fs/promises");
        else this.members.set(local.name, { mod, name: imported });
      }
    }
  }

  collectCommonJsExport(n) {
    const l = n.left;
    if (l.type !== "MemberExpression") return;
    const isModuleExports =
      l.object.type === "Identifier" && l.object.name === "module" && propName(l) === "exports";
    if (isModuleExports) {
      if (n.right.type === "Identifier") this.exported.add(n.right.name);
      if (n.right.type === "ObjectExpression")
        for (const p of n.right.properties) {
          if (p.type !== "Property") continue;
          this.exported.add(p.value.type === "Identifier" ? p.value.name : keyName(p.key));
        }
      return;
    }
    const target = l.object;
    const isExportsObj =
      (target.type === "Identifier" && target.name === "exports") ||
      (target.type === "MemberExpression" &&
        target.object.type === "Identifier" &&
        target.object.name === "module" &&
        propName(target) === "exports");
    if (isExportsObj && propName(l)) this.exported.add(propName(l));
  }

  // ---- callee resolution ---------------------------------------------------
  resolve(callee) {
    if (!callee) return null;
    if (callee.type === "ChainExpression") return this.resolve(callee.expression);
    if (callee.type === "Identifier") {
      const m = this.members.get(callee.name);
      if (m) return `${m.mod}.${m.name}`;
      if (this.ns.has(callee.name)) return `${this.ns.get(callee.name)}.default`;
      if (GLOBAL_CALLS.has(callee.name) || GLOBAL_CALLS_MORE.has(callee.name)) return `global.${callee.name}`;
      return null;
    }
    if (callee.type !== "MemberExpression") return null;
    const p = propName(callee);
    if (!p) return null;
    const obj = callee.object;
    if (obj.type === "Identifier") {
      if (this.ns.has(obj.name)) return `${this.ns.get(obj.name)}.${p}`;
      const m = this.members.get(obj.name);
      if (m) return m.mod === "fs" && m.name === "promises" ? `fs/promises.${p}` : `${m.mod}.${m.name}.${p}`;
      if (GLOBAL_OBJECTS.has(obj.name)) return `${obj.name}.${p}`;
    }
    if (obj.type === "MemberExpression" && propName(obj) === "promises" && obj.object.type === "Identifier") {
      if (this.ns.get(obj.object.name) === "fs") return `fs/promises.${p}`;
    }
    if (isRequireCall(obj)) return `${normalizeModule(obj.arguments[0].value)}.${p}`;
    return `?.${p}`; // unknown receiver: method name only
  }

  // ---- taint ---------------------------------------------------------------
  taintOf(n, ctx) {
    if (!n) return null;
    switch (n.type) {
      case "Identifier":
        return ctx.lookup(n.name);
      case "MemberExpression":
        return sourceOf(n) ?? this.taintOf(n.object, ctx);
      case "ChainExpression":
      case "ParenthesizedExpression":
        return this.taintOf(n.expression, ctx);
      case "TemplateLiteral":
        return this.firstTaint(n.expressions, ctx);
      case "TaggedTemplateExpression":
        return this.taintOf(n.quasi, ctx);
      case "BinaryExpression":
      case "LogicalExpression":
        return this.taintOf(n.left, ctx) ?? this.taintOf(n.right, ctx);
      case "ConditionalExpression":
        return this.taintOf(n.consequent, ctx) ?? this.taintOf(n.alternate, ctx);
      case "AssignmentExpression":
        return this.taintOf(n.right, ctx);
      case "SequenceExpression":
        return this.taintOf(n.expressions.at(-1), ctx);
      case "AwaitExpression":
      case "SpreadElement":
        return this.taintOf(n.argument, ctx);
      case "UnaryExpression":
        return n.operator === "typeof" || n.operator === "!" ? null : this.taintOf(n.argument, ctx);
      case "ArrayExpression":
        return this.firstTaint(n.elements, ctx);
      case "ObjectExpression":
        return this.firstTaint(
          n.properties.map((p) => (p.type === "Property" ? p.value : p.argument)),
          ctx,
        );
      case "CallExpression":
      case "NewExpression": {
        const callee = this.resolve(n.callee);
        if (callee && SANITIZERS.has(callee)) return null;
        if (callee && SANITIZERS.has(`?.${splitCallee(callee)[1]}`)) return null;
        const recv = n.callee.type === "MemberExpression" ? this.taintOf(n.callee.object, ctx) : null;
        return recv ?? this.firstTaint(n.arguments, ctx);
      }
      default:
        return null;
    }
  }

  firstTaint(list, ctx) {
    for (const x of list) {
      const t = x && this.taintOf(x, ctx);
      if (t) return t;
    }
    return null;
  }

  bindPattern(pattern, label, ctx) {
    if (!pattern) return;
    switch (pattern.type) {
      case "Identifier":
        if (label) ctx.tainted.set(pattern.name, label);
        else ctx.tainted.delete(pattern.name);
        break;
      case "ObjectPattern":
        for (const p of pattern.properties)
          this.bindPattern(p.type === "Property" ? p.value : p.argument, label, ctx);
        break;
      case "ArrayPattern":
        for (const e of pattern.elements) this.bindPattern(e, label, ctx);
        break;
      case "AssignmentPattern":
        this.bindPattern(pattern.left, label ?? this.taintOf(pattern.right, ctx), ctx);
        break;
      case "RestElement":
        this.bindPattern(pattern.argument, label, ctx);
        break;
    }
  }

  // ---- findings ------------------------------------------------------------
  report(ruleId, node, ctx, { taint = null, severity, confidence, evidence, detail } = {}) {
    const rule = RULES[ruleId];
    const line = node.loc.start.line;
    const text = (evidence ?? this.lines[line - 1] ?? "").trim().slice(0, 160);
    this.findings.push({
      rule: ruleId,
      severity: severity ?? rule.severity,
      title: rule.title,
      why: taint
        ? `${rule.why} Untrusted data flows here from \`${taint}\`.`
        : detail
          ? `${rule.why} ${detail}`
          : rule.why,
      where: `${this.file}:${line}`,
      evidence: text,
      engine: "trinetra-ast",
      confidence: confidence ?? (taint ? "high" : "medium"),
      function: ctx.name,
      ...(taint ? { taint: { source: taint, sink: ruleId } } : {}),
    });
  }

  checkCall(n, ctx) {
    const callee = this.resolve(n.callee);
    const args = n.arguments;
    const first = args[0];
    if (callee) {
      ctx.calls.push({ callee, line: n.loc.start.line });
      ctx.addCapability(capabilityOf(callee), callee);
    }

    // Dynamic code.
    const isFunctionCtor = callee === "global.Function";
    if (
      (callee === "global.eval" && first && !isStaticString(first)) ||
      (isFunctionCtor && args.some((a) => !isStaticString(a)))
    ) {
      this.report("dynamic-eval", n, ctx, { taint: this.firstTaint(args, ctx) });
    } else if (
      callee &&
      /^vm\.(runInThisContext|runInNewContext|runInContext|compileFunction|Script)$/.test(callee)
    ) {
      if (first && !isStaticString(first))
        this.report("dynamic-eval", n, ctx, { taint: this.taintOf(first, ctx) });
    }

    // Commands.
    if (callee === "child_process.exec" || callee === "child_process.execSync") {
      if (first && !isStaticString(first))
        this.report("command-injection", n, ctx, { taint: this.taintOf(first, ctx) });
    } else if (callee && /^child_process\.(spawn|spawnSync|execFile|execFileSync)$/.test(callee)) {
      const opts = args.findLast((a) => a.type === "ObjectExpression");
      const shell = opts?.properties.find((p) => p.type === "Property" && keyName(p.key) === "shell");
      const shellOn = shell && !(shell.value.type === "Literal" && !shell.value.value);
      if (shellOn) {
        const dynamic =
          args.some((a) => a !== opts && !isStaticString(a) && a.type !== "ArrayExpression") ||
          args.some((a) => a.type === "ArrayExpression" && a.elements.some((e) => e && !isStaticString(e)));
        const taint = this.firstTaint(
          args.filter((a) => a !== opts),
          ctx,
        );
        this.report("command-injection", n, ctx, {
          taint,
          severity: dynamic || taint ? "high" : "medium",
          detail: "`shell: true` makes the arguments shell-interpreted.",
        });
      }
    }

    // Dynamic module loading.
    if (callee === "global.require" && first && !isStaticString(first))
      this.report("dynamic-require", n, ctx, { taint: this.taintOf(first, ctx) });

    // DOM sinks.
    if ((callee === "document.write" || callee === "document.writeln") && first && !isStaticString(first)) {
      const taint = this.taintOf(first, ctx);
      this.report("dom-xss", n, ctx, { taint, severity: taint ? "high" : undefined });
    }
    if (callee === "?.insertAdjacentHTML" && args[1] && !isStaticString(args[1])) {
      const taint = this.taintOf(args[1], ctx);
      this.report("dom-xss", n, ctx, { taint, severity: taint ? "high" : undefined });
    }

    // Weak hashes.
    if (callee && /(^crypto|^\?)\.createHash$/.test(callee) && first && isStaticString(first)) {
      const alg = String(staticValue(first)).toLowerCase();
      if (["md5", "sha1", "md4", "md2", "sha-1"].includes(alg))
        this.report("weak-hash", n, ctx, { confidence: "high", detail: `Algorithm: ${alg}.` });
    }

    // Insecure randomness — only where the value is evidently security-relevant.
    if (callee === "Math.random") {
      const names = [ctx.name, this.declNames.at(-1)].filter(Boolean);
      if (names.some((x) => SENSITIVE_NAME.test(x)))
        this.report("insecure-random", n, ctx, {
          confidence: "medium",
          detail: `Used in \`${names.join(" / ")}\`.`,
        });
    }

    // Taint-only sinks.
    if (!first) return;
    const [mod, member] = callee ? splitCallee(callee) : [null, null];
    if ((mod === "fs" || mod === "fs/promises") && FS_PATH_SINKS.has(member)) {
      const taint = this.taintOf(first, ctx);
      if (taint)
        this.report("path-traversal", n, ctx, {
          taint,
          severity: taint.startsWith("process.") ? "medium" : "high",
        });
    }
    if (callee === "?.sendFile" || callee === "res.sendFile") {
      const taint = this.taintOf(first, ctx);
      if (taint) this.report("path-traversal", n, ctx, { taint });
    }
    if (callee && /^\?\.(query|execute|raw|exec)$/.test(callee) && !isStaticString(first)) {
      const taint =
        first.type === "TemplateLiteral" || first.type === "BinaryExpression"
          ? this.taintOf(first, ctx)
          : null;
      if (taint && callee !== "?.exec") this.report("sql-injection", n, ctx, { taint });
    }
    const isRequest =
      callee === "global.fetch" ||
      ((mod === "http" || mod === "https") && (member === "get" || member === "request")) ||
      mod === "axios.default" ||
      (mod && mod.startsWith("axios"));
    if (isRequest) {
      const taint = this.taintOf(first, ctx);
      if (taint && !taint.startsWith("process.env")) this.report("ssrf", n, ctx, { taint });
    }
  }

  checkSecret(name, valueNode, node, ctx) {
    if (!valueNode || !isStaticString(valueNode)) return;
    const value = staticValue(valueNode);
    const line = this.lines[node.loc.start.line - 1] ?? "";
    const evidence = line.trim().replace(value, redact(value));
    if (looksLikeSecretValue(value)) {
      this.report("hardcoded-secret", node, ctx, {
        confidence: "high",
        evidence,
        detail: "Matches a known credential format.",
      });
    } else if (plausibleNamedSecret(name, value)) {
      this.report("hardcoded-secret", node, ctx, {
        confidence: "medium",
        evidence,
        detail: `Assigned to \`${name}\`.`,
      });
    }
  }

  // ---- pass 2: the walk ----------------------------------------------------
  functionName(n, parent) {
    if (n.id?.name) return n.id.name;
    if (parent?.type === "VariableDeclarator" && parent.id.type === "Identifier") return parent.id.name;
    if (
      (parent?.type === "Property" ||
        parent?.type === "MethodDefinition" ||
        parent?.type === "PropertyDefinition") &&
      keyName(parent.key)
    )
      return keyName(parent.key);
    if (parent?.type === "AssignmentExpression" && parent.left.type === "MemberExpression")
      return propName(parent.left);
    // app.get("/path", (req, res) => …) → "GET /path handler"
    if (parent?.type === "CallExpression" && parent.callee.type === "MemberExpression") {
      const verb = propName(parent.callee);
      const route = parent.arguments[0];
      if (HTTP_VERBS.has(verb) && isStaticString(route))
        return `${verb.toUpperCase()} ${staticValue(route)} handler`;
    }
    return `(anonymous@${n.loc.start.line})`;
  }

  walk(n, ctx, parent) {
    if (FUNCTION_TYPES.has(n.type)) {
      const name = this.functionName(n, parent);
      const params = n.params.map((p) =>
        p.type === "Identifier"
          ? p.name
          : p.type === "AssignmentPattern" && p.left.type === "Identifier"
            ? p.left.name
            : "…",
      );
      const fctx = new FunctionCtx(name, n.loc.start.line, ctx, params);
      fctx.endLine = n.loc.end.line;
      this.functions.push(fctx);
      for (const p of n.params) this.walk(p, fctx, n);
      this.walk(n.body, fctx, n);
      return;
    }

    switch (n.type) {
      case "VariableDeclarator": {
        const name = n.id.type === "Identifier" ? n.id.name : null;
        this.declNames.push(name);
        if (n.init) this.walk(n.init, ctx, n);
        this.declNames.pop();
        this.bindPattern(n.id, n.init ? this.taintOf(n.init, ctx) : null, ctx);
        if (name) this.checkSecret(name, n.init, n, ctx);
        else if (n.init) this.walk(n.id, ctx, n);
        return;
      }
      case "AssignmentExpression": {
        const target = n.left.type === "Identifier" ? n.left.name : propName(n.left);
        this.declNames.push(target);
        this.walk(n.right, ctx, n);
        this.declNames.pop();
        if (n.left.type === "MemberExpression") this.walk(n.left, ctx, n);
        if (n.left.type === "Identifier" || n.left.type.endsWith("Pattern")) {
          const label = this.taintOf(n.right, ctx);
          if (n.operator === "=") this.bindPattern(n.left, label, ctx);
          else if (label) this.bindPattern(n.left, label, ctx);
        }
        if (n.left.type === "MemberExpression" && /^(innerHTML|outerHTML)$/.test(propName(n.left) ?? "")) {
          if (!isStaticString(n.right)) {
            const taint = this.taintOf(n.right, ctx);
            this.report("dom-xss", n, ctx, { taint, severity: taint ? "high" : undefined });
          }
        }
        if (target) this.checkSecret(target, n.right, n, ctx);
        return;
      }
      case "Property":
      case "PropertyDefinition":
        if (!n.computed && n.value && !FUNCTION_TYPES.has(n.value.type))
          this.checkSecret(keyName(n.key), n.value, n, ctx);
        break;
      case "CallExpression":
      case "NewExpression":
        this.checkCall(n, ctx);
        break;
      case "ImportExpression":
        if (!isStaticString(n.source))
          this.report("dynamic-require", n, ctx, { taint: this.taintOf(n.source, ctx) });
        break;
      case "MemberExpression": {
        const src = sourceOf(n);
        if (src === "process.env") ctx.addCapability("reads environment variables", "process.env");
        else if (src === "process.argv") ctx.addCapability("reads command-line arguments", "process.argv");
        else if (src) ctx.addCapability("handles HTTP request input", src.split(".").slice(0, 2).join("."));
        break;
      }
      case "Literal":
        if (
          typeof n.value === "string" &&
          looksLikeSecretValue(n.value) &&
          !["VariableDeclarator", "AssignmentExpression", "Property", "PropertyDefinition"].includes(
            parent?.type,
          )
        ) {
          const line = this.lines[n.loc.start.line - 1] ?? "";
          this.report("hardcoded-secret", n, ctx, {
            confidence: "high",
            evidence: line.trim().replace(n.value, redact(n.value)),
            detail: "Matches a known credential format.",
          });
        }
        break;
    }
    for (const c of childNodes(n)) this.walk(c, ctx, n);
  }

  run() {
    this.collectBindings();
    const top = new FunctionCtx("(top level)", 1, null);
    this.top = top;
    this.walk(this.ast, top, null);
    // De-duplicate findings at the same line + rule (e.g. nested sinks).
    const seen = new Set();
    this.findings = this.findings.filter((f) => {
      const k = `${f.rule}|${f.where}`;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
    return this;
  }
}

const describeFn = (f, exported) => ({
  name: f.name,
  line: f.line,
  endLine: f.endLine ?? f.line,
  params: f.params,
  exported: exported.has(f.name),
  capabilities: Object.fromEntries([...f.capabilities].map(([k, v]) => [k, [...v]])),
  calls: f.calls,
});

// Fallback for files acorn can't parse (TypeScript, Flow, non-JS text): only
// line-level checks that don't need syntax — known credential formats and
// literal weak-hash names. Clearly labelled as a lower-confidence engine.
function regexFallback(file, text) {
  const findings = [];
  text.split("\n").forEach((line, i) => {
    const secret = SECRET_PATTERNS.map((re) => line.match(re)).find(Boolean);
    if (secret) {
      findings.push({
        rule: "hardcoded-secret",
        ...RULES["hardcoded-secret"],
        where: `${file}:${i + 1}`,
        evidence: line.trim().replace(secret[0], redact(secret[0])).slice(0, 160),
        engine: "trinetra-regex",
        confidence: "medium",
      });
    }
    if (/createHash\s*\(\s*["'](md5|sha1)["']/i.test(line)) {
      findings.push({
        rule: "weak-hash",
        ...RULES["weak-hash"],
        where: `${file}:${i + 1}`,
        evidence: line.trim().slice(0, 160),
        engine: "trinetra-regex",
        confidence: "medium",
      });
    }
  });
  return findings;
}

/**
 * Analyze one JavaScript file.
 * @returns {{file, parsed, error?, imports, exports, functions, topLevel, findings}}
 */
export function analyzeJs(text, file = "<input>") {
  let ast;
  try {
    ast = parseJs(text);
  } catch (err) {
    return {
      file,
      parsed: false,
      error: err.message,
      imports: [],
      exports: [],
      functions: [],
      topLevel: { capabilities: {}, calls: [] },
      findings: regexFallback(file, text),
    };
  }
  const a = new JsAnalyzer(file, text, ast).run();
  return {
    file,
    parsed: true,
    imports: a.imports,
    exports: [...a.exported].filter(Boolean).sort(),
    functions: a.functions.map((f) => describeFn(f, a.exported)),
    topLevel: describeFn(a.top, a.exported),
    findings: a.findings,
  };
}

export const JS_RULES = RULES;
