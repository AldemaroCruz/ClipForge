"""Explicit first administrator. Password input is terminal-only and never echoed."""
import argparse
import getpass
from pathlib import Path
import sys
import warnings

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.auth import bootstrap_admin
from app.auth_db import AuthConfigurationError, AuthDatabaseError


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--username", required=True)
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("Usa una terminal interactiva; no se acepta contraseña por argumentos, archivos o stdin redirigido.", file=sys.stderr)
        return 1
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            password = getpass.getpass("Contraseña inicial (12–128 caracteres): ")
            confirmation = getpass.getpass("Confirma la contraseña: ")
        if password != confirmation:
            print("Las contraseñas no coinciden.", file=sys.stderr)
            return 1
        user = bootstrap_admin(args.username, password)
    except (AuthConfigurationError, AuthDatabaseError):
        print("No se pudo crear el administrador. Verifica la base candidata y ejecuta su migración.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (getpass.GetPassWarning, EOFError, KeyboardInterrupt):
        print("Entrada segura cancelada; no se creó una cuenta.", file=sys.stderr)
        return 1
    print("Administrador inicial creado: " + user.username + ". Inicia sesión en la candidata local.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
