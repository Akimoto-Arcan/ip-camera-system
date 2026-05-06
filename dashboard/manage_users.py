#!/usr/bin/env python3
"""
CLI tool for managing the file-based user database (config/users.yml).

Usage:
  python3 manage_users.py list
  python3 manage_users.py add <username> --role <role> --password <password>
  python3 manage_users.py reset-password <username> --password <newpassword>
  python3 manage_users.py delete <username>
  python3 manage_users.py set-role <username> --role <newrole>
"""

import argparse
import os
import sys
from pathlib import Path

import bcrypt
import yaml

USERS_PATH = Path(os.environ.get("USERS_PATH", "/config/users.yml"))


def _load() -> dict:
    if not USERS_PATH.exists():
        return {"users": []}
    with open(USERS_PATH) as f:
        return yaml.safe_load(f) or {"users": []}


def _save(data: dict) -> None:
    tmp = USERS_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    tmp.replace(USERS_PATH)


def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def cmd_list(args):
    data = _load()
    users = data.get("users", [])
    if not users:
        print("No users configured.")
        return
    print(f"{'Username':<20} {'Role':<15} {'Approved'}")
    print("-" * 50)
    for u in users:
        print(f"{u['username']:<20} {u.get('role', '—'):<15} {u.get('approved', False)}")


def cmd_add(args):
    data = _load()
    users = data.setdefault("users", [])
    for u in users:
        if u["username"] == args.username:
            print(f"Error: user '{args.username}' already exists.")
            sys.exit(1)
    users.append({
        "username": args.username,
        "password": _hash_pw(args.password),
        "role": args.role,
        "approved": True,
    })
    _save(data)
    print(f"Added user '{args.username}' with role '{args.role}'.")


def cmd_reset_password(args):
    data = _load()
    for u in data.get("users", []):
        if u["username"] == args.username:
            u["password"] = _hash_pw(args.password)
            _save(data)
            print(f"Password reset for '{args.username}'.")
            return
    print(f"Error: user '{args.username}' not found.")
    sys.exit(1)


def cmd_delete(args):
    data = _load()
    before = len(data.get("users", []))
    data["users"] = [u for u in data.get("users", []) if u["username"] != args.username]
    if len(data["users"]) == before:
        print(f"Error: user '{args.username}' not found.")
        sys.exit(1)
    _save(data)
    print(f"Deleted user '{args.username}'.")


def cmd_set_role(args):
    data = _load()
    for u in data.get("users", []):
        if u["username"] == args.username:
            u["role"] = args.role
            _save(data)
            print(f"Role for '{args.username}' set to '{args.role}'.")
            return
    print(f"Error: user '{args.username}' not found.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Manage camera dashboard users")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("list", help="List all users")

    p_add = sub.add_parser("add", help="Add a new user")
    p_add.add_argument("username")
    p_add.add_argument("--role", default="Operator", help="Role: SuperAdmin, Supervisor, Operator, etc.")
    p_add.add_argument("--password", required=True)

    p_reset = sub.add_parser("reset-password", help="Reset user password")
    p_reset.add_argument("username")
    p_reset.add_argument("--password", required=True)

    p_del = sub.add_parser("delete", help="Delete a user")
    p_del.add_argument("username")

    p_role = sub.add_parser("set-role", help="Change user role")
    p_role.add_argument("username")
    p_role.add_argument("--role", required=True)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    cmds = {
        "list": cmd_list,
        "add": cmd_add,
        "reset-password": cmd_reset_password,
        "delete": cmd_delete,
        "set-role": cmd_set_role,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
