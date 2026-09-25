import sys

if sys.version_info < (3, 9):  # before importing the CLI, whose modules need 3.9 syntax
    sys.stderr.write("cloudseed needs Python 3.9 or newer (this is %s at %s).\n" % (sys.version.split()[0], sys.executable))
    sys.exit(1)

from .cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
