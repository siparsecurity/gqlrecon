# Testing Notes

## Local test target: DVGA

DVGA (Damn Vulnerable GraphQL Application) is used as the local legal test
target for validating Stage 1 schema discovery.

Repo: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application

### Known issue: Python 3.14 incompatibility

DVGA's pinned dependencies (gevent, greenlet, Flask 2.2.2, Werkzeug 2.2.2)
were built for Python 3.10/3.11 and fail to compile or run on Python 3.14,
which Kali currently ships by default.

Fix in progress: install Python 3.11 via pyenv and run DVGA's virtual
environment on that version instead of system Python.

### Setup steps used

1. Clone DVGA into ~/projects/Damn-Vulnerable-GraphQL-Application
2. Create venv: python3 -m venv dvga-env
3. Strip websocket/gevent dependencies not needed for core GraphQL testing
   (see requirements_fixed.txt in the DVGA folder)
4. Patch app.py with a pkgutil.get_loader compatibility shim (temporary,
   only needed until running under Python 3.11)
5. Install Python 3.11.16 via pyenv, rebuild venv against it

### Status

Resolved. Python 3.11.16 installed via pyenv, DVGA venv rebuilt against it,
original unmodified requirements.txt installed successfully (gevent and
greenlet compiled cleanly).

### Stage 1 validation result

Command:

    python3 stage1_discovery.py --url http://localhost:5013/graphql

Result: introspection enabled, schema successfully parsed.

- 12 queries discovered
- 7 mutations discovered
- 29 total types discovered
- Field arguments correctly extracted, including sensitive looking fields
  such as systemDiagnostics(username, password, cmd)

Stage 1 is confirmed working against a real GraphQL target.

## Stage 2 validation: Batching and Alias Abuse

Command:

    python3 stage2_batching.py --url http://localhost:5013/graphql --schema ../output/stage1_dvga_test.json

Result against DVGA (fresh server instance):

- Batching: SUPPORTED, 10 of 10 queries processed in a single HTTP request
- Alias abuse: SUPPORTED, 20 of 20 aliased fields resolved in a single query

Note: an earlier test run against a stale/hung DVGA process produced
misleading timeouts on both tests. Restarting DVGA cleanly resolved this.
Stage 2 was also improved to distinguish a genuine timeout (possible
resource exhaustion signal) from simple lack of support, and now defaults
to __typename as the alias probe field since it is always safe and
lightweight regardless of what Stage 1 picked as the general probe field.

Stage 2 is confirmed working against a real GraphQL target.

## Stage 3 validation: Depth and Complexity Fuzzing

Command:

    python3 stage3_depth.py --url http://localhost:5013/graphql

Result against DVGA:

- Self referencing cycle found: pastes -> owner -> paste -> owner -> ...
- Depth 5: accepted, 0.05s
- Depth 10: accepted, 0.22s
- Depth 20: accepted, 6.78s
- Depth 35: TIMEOUT after 10s

DVGA enforces no depth or complexity limit. Response time grows sharply
with nesting depth, confirming a genuine resource exhaustion risk.

Note: an earlier run reported a false "depth limit enforced" result caused
by a bug in query construction (field ordering flipped depending on odd or
even depth, which produced an invalid query at depth 10, not a real
rejection). Fixed by building the field sequence outer to inner before
nesting, so the outermost field is always consistent regardless of depth.
Stage 3 now also distinguishes genuine depth/complexity rejections from
unrelated schema errors.

Stage 3 is confirmed working and produced a real, meaningful finding
against a live GraphQL target.
