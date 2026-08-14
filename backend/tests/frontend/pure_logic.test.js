// Tests for pure (no-DOM) JS logic embedded in app/static/index.html:
// riskClass() and hasActiveFilters(). Both take a plain value in and
// return a plain value out with no document/DOM access, so rather than
// needing a full browser/DOM environment to test them, this extracts
// just those two functions' source out of the HTML file via regex and
// evals each in isolation. Everything else in index.html's <script>
// block DOES touch the DOM (document.getElementById, fetch, etc.) and
// isn't covered here — this project has no headless browser available
// in its environment (the same limitation already noted in the
// README's original "Browser UI" section: visual/DOM behavior needs a
// human to actually open the page and look).
//
// Run with: node tests/frontend/pure_logic.test.js
const assert = require('node:assert');
const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');

const htmlPath = path.join(__dirname, '..', '..', 'app', 'static', 'index.html');
const html = fs.readFileSync(htmlPath, 'utf-8');

const riskClassMatch = html.match(/function riskClass\(score\)\{[\s\S]*?\n\}/);
if (!riskClassMatch) {
  throw new Error('Could not find riskClass() in index.html — did its signature change?');
}
// eslint-disable-next-line no-eval
eval(riskClassMatch[0]);

const hasActiveFiltersMatch = html.match(/function hasActiveFilters\(filters\)\{[\s\S]*?\n\}/);
if (!hasActiveFiltersMatch) {
  throw new Error('Could not find hasActiveFilters() in index.html — did its signature change?');
}
// eslint-disable-next-line no-eval
eval(hasActiveFiltersMatch[0]);

test('score of 0 is risk-low', () => {
  assert.strictEqual(riskClass(0), 'risk-low');
});

test('score just below the medium threshold (19) is risk-low', () => {
  assert.strictEqual(riskClass(19), 'risk-low');
});

test('score at the medium threshold (20) is risk-medium', () => {
  assert.strictEqual(riskClass(20), 'risk-medium');
});

test('score just below the high threshold (59) is risk-medium', () => {
  assert.strictEqual(riskClass(59), 'risk-medium');
});

test('score at the high threshold (60) is risk-high', () => {
  assert.strictEqual(riskClass(60), 'risk-high');
});

test('max score (100, the backend cap) is risk-high', () => {
  assert.strictEqual(riskClass(100), 'risk-high');
});

test('hasActiveFilters: empty object is false', () => {
  assert.strictEqual(hasActiveFilters({}), false);
});

test('hasActiveFilters: object with severity_filter is true', () => {
  assert.strictEqual(hasActiveFilters({ severity_filter: ['high'] }), true);
});

test('hasActiveFilters: object with search is true', () => {
  assert.strictEqual(hasActiveFilters({ search: 'password' }), true);
});
