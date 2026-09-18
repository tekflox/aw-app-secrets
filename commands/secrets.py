"""``aw-workspace-cli secrets`` — this app's own CLI command.

Auto-discovered by aw-workspace-cli from this app's installed directory
(``<apps_root>/secrets/commands/``, since this file lives at ``commands/`` in
this repo's root — see aw-workspace's ``src/cli/discovery.py``, which loads
every ``<apps_root>/<slug>/commands/*.py`` exposing ``COMMAND``/
``DESCRIPTION``/``run``).

Everything real lives in ``secrets_app.cli``. This file only puts the app's
package dir on ``sys.path``: Tier-1 apps load under a synthetic
``aw_apps.<id>`` namespace inside the *workspace* process, so ``secrets_app``
is not importable as a plain top-level package from the separate
``aw-workspace-cli`` process without it.

Kept trivial on purpose — discovery imports every one of these files on EVERY
``aw-workspace-cli`` invocation, so anything that fails here prints a warning
in front of unrelated commands workspace-wide.
"""
from __future__ import annotations

import os
import sys

COMMAND = "secrets"
DESCRIPTION = "read, write and list the workspace's shared secrets"

APP_DIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def run(args: list[str]) -> int:
    if APP_DIR not in sys.path:
        sys.path.insert(0, APP_DIR)
    from secrets_app.cli import main

    return main(list(args or []))
