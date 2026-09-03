# Malicious fixtures

These files are intentionally crafted to represent compromised or
otherwise unsafe project configuration. They should all be treated
as real and serious threats to your system.

These files are malware - preserved for compromise simulation. 
They are **not intended to be executed, imported, or loaded as configuration**.

Never move these files into an application's source tree or use them as live configuration.

When adding a new fixture:

- Keep it self-contained.
- Do not include real credentials, tokens, or personal data.
- Prefer inert payloads that exercise the scanner's detection logic.
- Add or update a test demonstrating what the scanner is expected
  to detect.

## Don't make test fixture executable

This is a small but worthwhile precaution to run on fixture files:

```bash
$ chmod -x tests/fixtures/malicious/quarantined-tailwind.config.js
```

And make sure the test runner reads it as data rather than importing it.

For example, this:

```javascript
const fixture = readFileSync(
  join(fixturesDir, 'malicious', 'quarantined-tailwind.config.js'),
  'utf8',
)
```

is preferable to:

```javascript
import fixture from './fixtures/malicious/quarantined-tailwind.config.js'
```

The latter creates an unnecessary opportunity for the fixture to be evaluated by the JavaScript runtime.
