"""check_public_surface.py: the file manager uses only rowstile's public surface (what that is, and how it is
checked: ../public_surface.py, which the messenger runs too).

    python3 examples/filemanager/check_public_surface.py      # exit 1 and a list of places otherwise
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from public_surface import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(HERE))
