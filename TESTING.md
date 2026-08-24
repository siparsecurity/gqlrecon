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
