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

In progress. Python 3.11 build via pyenv underway.
