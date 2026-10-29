#!/usr/bin/env python3
"""Django's command for the conformance app: manage.py migrate (as the tables' owner: DATABASE_URL names who)."""

import os
import sys

if __name__ == "__main__":
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "conformance.settings")
    from django.core.management import execute_from_command_line

    execute_from_command_line(sys.argv)
