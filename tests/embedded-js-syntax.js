#!/usr/bin/env node
/**
 * Build-time guard: catch the regex-backslash class of bug in renderPage()'s
 * embedded JS before deploy.
 *
 * Run:   node tests/embedded-js-syntax.js
 * Exit:  0 on PASS, 1 on FAIL.
 *
 * The class of bug:
 *   renderPage() returns the entire HTML+JS as a JavaScript template literal.
 *   Inside template literals, \X where X is not a recognized escape character
 *   (n, t, r, b, f, v, 0, ', ", \, x, u) is silently stripped to X. Regex
 *   literals containing \. \/ \d \w \s \b … in source therefore arrive in the
 *   browser with the backslashes eaten.
 *
 *   Some of those mangled regexes still parse — the bug shows up as wrong
 *   matching (e.g. \d+ becomes d+ which only matches the literal letter d).
 *   Some don't: /^(https?:)?\/\//i becomes /^(https?:)?//i, the // is lexed
 *   as a single-line comment, the enclosing if-statement loses its closing )
 *   and the parser SyntaxErrors on the next non-whitespace token.
 *
 *   This test catches the second case (script-completely-fails-to-execute)
 *   by extracting the post-interpolation embedded JS and parsing it with
 *   `new Function`. It does NOT catch the first case (regex compiles but
 *   matches the wrong thing); a behavioural-regex test would, but that is
 *   out of scope for this guard.
 *
 *   The fix is to double-escape backslashes in the source: \\d, \\., \\/\\/
 *   become \d, \., \/\/ after template-literal processing, which is what the
 *   regex actually wants.
 */
"use strict";

const fs = require("fs");
const path = require("path");

const SRC_PATH = path.join(__dirname, "..", "src", "index.ts");
const src = fs.readFileSync(SRC_PATH, "utf8");

// Find the renderPage HTML template literal. The pattern is conservative:
// `const html = ` followed by an optional tag (e.g. String.raw — see PR #5)
// then a backtick-delimited literal that contains `<!DOCTYPE html>` and
// ends in `</html>`. We capture the tag too so eval() applies the same
// escape-processing rules the Worker runtime applies at request time.
const TEMPLATE_RE = /const\s+html\s*=\s*((?:String\.raw\s*)?`<!DOCTYPE html>[\s\S]*?<\/html>`)\s*;/;
const m = TEMPLATE_RE.exec(src);
if (!m) {
  console.error("FAIL: could not locate renderPage's HTML template literal in", SRC_PATH);
  process.exit(1);
}
const templateLiteralSrc = m[1]; // tag (optional) + surrounding backticks

// Evaluate the template literal as JavaScript so escape processing matches
// what the Worker runtime does at request time. The literal contains no
// ${...} interpolations (verified by a backtick count check on renderPage),
// so this is a pure string-extraction operation.
let html;
try {
  // Indirect eval keeps strict-mode happy and does not capture the local scope.
  html = (0, eval)(templateLiteralSrc);
} catch (e) {
  console.error("FAIL: template literal evaluation threw:", e && e.message ? e.message : String(e));
  process.exit(1);
}

if (typeof html !== "string") {
  console.error("FAIL: template literal eval did not return a string");
  process.exit(1);
}

// Extract the <script>…</script> contents. The renderer has exactly one
// inline script block (verified by a backtick count check on renderPage).
const SCRIPT_RE = /<script>([\s\S]*?)<\/script>/;
const sm = SCRIPT_RE.exec(html);
if (!sm) {
  console.error("FAIL: no <script> block found in rendered HTML");
  process.exit(1);
}
const embeddedJs = sm[1];

// Parse the post-interpolation embedded JS as a function body. Function()
// throws SyntaxError on parse failure; that is exactly the runtime symptom
// this test guards against.
let parseOk = true;
let parseErr = null;
try {
  // eslint-disable-next-line no-new-func
  new Function(embeddedJs);
} catch (e) {
  if (e && e.name === "SyntaxError") {
    parseOk = false;
    parseErr = e;
  } else {
    // Function() can also throw on referencing undefined identifiers during
    // hoisting in some engines, but that wouldn't surface here — Function()
    // only parses, it doesn't execute. Treat anything non-SyntaxError as a
    // test bug, not a renderer bug.
    console.error("FAIL: unexpected error during parse:", e && e.message ? e.message : String(e));
    process.exit(1);
  }
}

if (!parseOk) {
  console.error("FAIL: embedded JS has a SyntaxError (script block would not execute in browser)");
  console.error("       " + (parseErr && parseErr.message ? parseErr.message : String(parseErr)));
  console.error("       Most likely cause: a regex literal in the embedded JS uses an");
  console.error("       unescaped backslash (\\d, \\., \\/, \\w, \\s, \\b, \\B, ...). Inside");
  console.error("       the template literal those backslashes are silently stripped before");
  console.error("       the script reaches the browser. Double-escape them in source:");
  console.error("       \\d -> \\\\d, \\. -> \\\\., \\/ -> \\\\/, etc.");
  process.exit(1);
}

console.log("PASS: embedded JS parses cleanly (" + embeddedJs.length + " chars)");
process.exit(0);
