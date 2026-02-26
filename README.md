# Key Pass

A CustomTkinter-based, user-isolated password vault application.

## Features

- User registration and login
- Separate hash key per user
- User-scoped password listing
- Encrypted password storage in the database
- Argon2id password hashing
- CPU-bound delay on login attempts (anti-spam)
- Exponential lockout after failed login attempts
- Auto sign-out on inactivity

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Run

```bash
python app.py
```

## Database Location

- Running from source: `database.db` is created in the project folder.
- Running from packaged `.exe`: `database.db` is created at:
  `%LOCALAPPDATA%\KeyPass\database.db`

## Security Notes

- If the hash key is lost, encrypted passwords cannot be recovered.
- The hash key is not stored in plaintext in the database.
- Password entries are protected with a user-specific encryption key.
- Login password hashes use Argon2id.
- Failed login attempts trigger temporary account lockout.

## Test

```bash
python -m unittest tests.test_core -v
```
