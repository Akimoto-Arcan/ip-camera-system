#!/usr/bin/env python3
"""
CLI tool for managing users and roles in config/users.yml.

Usage:
  python3 manage_users.py list
  python3 manage_users.py add <username> --role <role> --password <password>
  python3 manage_users.py reset-password <username> --password <newpassword>
  python3 manage_users.py delete <username>
  python3 manage_users.py set-role <username> --role <newrole>
  python3 manage_users.py roles                          # list roles
  python3 manage_users.py add-role <name> --level <level> # add a role
  python3 manage_users.py remove-role <name>              # remove a role
  python3 manage_users.py rename-role <old> --name <new>  # rename a role
"""

import argparse
import os
import sys
from pathlib import Path

import bcrypt
import yaml

USERS_PATH = Path(os.environ.get("USERS_PATH", "/config/users.yml"))

VALID_LEVELS = ("admin", "manager", "viewer")


def _load() -> dict:
    if not USERS_PATH.exists():
        return {"roles": [], "users": []}
    with open(USERS_PATH) as f:
        data = yaml.safe_load(f) or {}
    data.setdefault("roles", [])
    data.setdefault("users", [])
    return data


def _save(data: dict) -> None:
    tmp = USERS_PATH.with_suffix(".tmp")
    with open(tmp, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
    tmp.replace(USERS_PATH)


def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def _role_names(data: dict) -> set:
    return {r["name"] for r in data.get("roles", [])}


# ── User commands ──────────────────────────────────────────────────────────────

def cmd_list(args):
    data = _load()
    users = data.get("users", [])
    if not users:
        print("No users configured.")
        return
    print(f"{'Username':<20} {'Role':<20} {'Approved'}")
    print("-" * 55)
    for u in users:
        print(f"{u['username']:<20} {u.get('role', '-'):<20} {u.get('approved', False)}")


def cmd_add(args):
    data = _load()
    users = data.setdefault("users", [])
    for u in users:
        if u["username"] == args.username:
            print(f"Error: user '{args.username}' already exists.")
            sys.exit(1)
    known = _role_names(data)
    if known and args.role not in known:
        print(f"Warning: role '{args.role}' is not defined in the roles section.")
        print(f"  Known roles: {', '.join(sorted(known))}")
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
    known = _role_names(data)
    if known and args.role not in known:
        print(f"Warning: role '{args.role}' is not defined in the roles section.")
    for u in data.get("users", []):
        if u["username"] == args.username:
            u["role"] = args.role
            _save(data)
            print(f"Role for '{args.username}' set to '{args.role}'.")
            return
    print(f"Error: user '{args.username}' not found.")
    sys.exit(1)


# ── Role commands ──────────────────────────────────────────────────────────────

def cmd_roles(args):
    data = _load()
    roles = data.get("roles", [])
    if not roles:
        print("No roles defined.")
        return
    print(f"{'Role Name':<25} {'Level'}")
    print("-" * 40)
    for r in roles:
        print(f"{r['name']:<25} {r.get('level', 'viewer')}")


def cmd_add_role(args):
    if args.level not in VALID_LEVELS:
        print(f"Error: level must be one of: {', '.join(VALID_LEVELS)}")
        sys.exit(1)
    data = _load()
    roles = data.setdefault("roles", [])
    for r in roles:
        if r["name"] == args.name:
            print(f"Error: role '{args.name}' already exists.")
            sys.exit(1)
    roles.append({"name": args.name, "level": args.level})
    _save(data)
    print(f"Added role '{args.name}' with level '{args.level}'.")


def cmd_remove_role(args):
    data = _load()
    roles = data.get("roles", [])
    # Check if any users still use this role
    users_with_role = [u["username"] for u in data.get("users", []) if u.get("role") == args.name]
    if users_with_role:
        print(f"Error: cannot remove role '{args.name}' — still assigned to: {', '.join(users_with_role)}")
        print("  Reassign these users first with: set-role <username> --role <newrole>")
        sys.exit(1)
    before = len(roles)
    data["roles"] = [r for r in roles if r["name"] != args.name]
    if len(data["roles"]) == before:
        print(f"Error: role '{args.name}' not found.")
        sys.exit(1)
    _save(data)
    print(f"Removed role '{args.name}'.")


def cmd_rename_role(args):
    data = _load()
    found = False
    for r in data.get("roles", []):
        if r["name"] == args.old_name:
            r["name"] = args.name
            found = True
            break
    if not found:
        print(f"Error: role '{args.old_name}' not found.")
        sys.exit(1)
    # Update users who had the old role name
    count = 0
    for u in data.get("users", []):
        if u.get("role") == args.old_name:
            u["role"] = args.name
            count += 1
    _save(data)
    print(f"Renamed role '{args.old_name}' → '{args.name}'. Updated {count} user(s).")


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Manage camera dashboard users and roles")
    sub = parser.add_subparsers(dest="command")

    # User commands
    sub.add_parser("list", help="List all users")

    p_add = sub.add_parser("add", help="Add a new user")
    p_add.add_argument("username")
    p_add.add_argument("--role", default="Operator", help="Role name")
    p_add.add_argument("--password", required=True)

    p_reset = sub.add_parser("reset-password", help="Reset user password")
    p_reset.add_argument("username")
    p_reset.add_argument("--password", required=True)

    p_del = sub.add_parser("delete", help="Delete a user")
    p_del.add_argument("username")

    p_role = sub.add_parser("set-role", help="Change user role")
    p_role.add_argument("username")
    p_role.add_argument("--role", required=True)

    # Role commands
    sub.add_parser("roles", help="List all defined roles")

    p_ar = sub.add_parser("add-role", help="Add a new role")
    p_ar.add_argument("name", help="Role name (e.g. 'Security Guard')")
    p_ar.add_argument("--level", required=True, choices=VALID_LEVELS,
                       help="Permission level: admin, manager, or viewer")

    p_rr = sub.add_parser("remove-role", help="Remove a role (must have no users)")
    p_rr.add_argument("name")

    p_rn = sub.add_parser("rename-role", help="Rename a role (updates all users)")
    p_rn.add_argument("old_name")
    p_rn.add_argument("--name", required=True, help="New role name")

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
        "roles": cmd_roles,
        "add-role": cmd_add_role,
        "remove-role": cmd_remove_role,
        "rename-role": cmd_rename_role,
    }
    cmds[args.command](args)


if __name__ == "__main__":
    main()
