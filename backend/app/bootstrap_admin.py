"""Interactive CLI for creating the first INVEST administrator."""

import argparse
import getpass
import sys

from sqlalchemy.exc import SQLAlchemyError

from app.db import SessionLocal
from app.security.bootstrap import create_bootstrap_admin


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create the first INVEST administrator."
    )
    parser.add_argument("email", help="Administrator email address")
    args = parser.parse_args()

    password = getpass.getpass("New administrator password: ")
    confirmation = getpass.getpass("Confirm password: ")

    if password != confirmation:
        print("Error: passwords do not match.", file=sys.stderr)
        return 1

    try:
        with SessionLocal.begin() as db:
            user = create_bootstrap_admin(db, args.email, password)
            email = user.email
    except ValueError as exc:
        print(f"Bootstrap refused: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"Bootstrap refused: {exc}", file=sys.stderr)
        return 1
    except SQLAlchemyError:
        print(
            "Bootstrap failed: database error. No account was created.",
            file=sys.stderr,
        )
        return 1

    print(f"Administrator created successfully: {email}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
