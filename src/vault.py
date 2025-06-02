#!/usr/bin/env python3
import configparser
import getpass
import os
import plistlib
import random
import sqlite3
import string
import subprocess
import sys
import time
import webbrowser
from cli import Logger, parser


def confirm_prompt(message, cancel_message="Operation canceled.", default=False):
    suffix = " [Y/n]?" if default else " [y/N]?"

    def ask():
        try:
            response = input(f"{message}{suffix}").lower().strip()
        except (EOFError, KeyboardInterrupt):
            print()
            if cancel_message:
                Logger.warning(cancel_message)
            return False
        if not default and (response == "" or response.startswith("n")):
            if cancel_message:
                Logger.warning(cancel_message)
            return False
        elif default and (response == "" or response.startswith("y")):
            return True
        elif response in ["y", "yes", "n", "no"]:
            return response.startswith("y")
        else:
            Logger.error("Invalid answer. Please enter y, yes, n, or no")
            return ask()

    return ask()


def copy_to_clipboard(text, description="Text"):
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
        Logger.success(f"{description} copied to clipboard")
        return True
    except subprocess.CalledProcessError:
        Logger.error(f"Failed to copy {description.lower()} to clipboard")
        return False


class VaultConfig:
    def __init__(self, config_path):
        self.config_path = config_path
        self._config = None
        self._load_config()

    def _load_config(self):
        self._config = configparser.ConfigParser()

        if not os.path.isfile(self.config_path):
            self._create_default_config()
        else:
            self._config.read(self.config_path)

    def _create_default_config(self):
        cmd_path = os.path.dirname(os.path.realpath(__file__))

        self._config["vault"] = {
            "session_timeout": "900 # 15 mins in seconds",
            "session_path": os.path.abspath(f"{cmd_path}/.vault_session"),
            "img_path": os.path.abspath(f"{cmd_path}/vault.dmg"),
            "mount_path": "/Volumes/vault",
            "db_path": "/Volumes/vault/vault.db",
        }
        self._config["genpass"] = {"length": "16", "digits": "4", "symbols": "4"}

        self.save()
        Logger.success(f"Created default config file at {self.config_path}")

    @property
    def db_path(self):
        return self.get("vault", "db_path")

    @property
    def img_path(self):
        return self.get("vault", "img_path")

    @property
    def mount_path(self):
        return self.get("vault", "mount_path")

    @property
    def session_path(self):
        return self.get("vault", "session_path")

    @property
    def session_timeout(self):
        return int(self.get("vault", "session_timeout"))

    def has_option(self, section, key):
        return self._config.has_option(section, key)

    def items(self, section):
        return self._config.items(section)

    def sections(self):
        return self._config.sections()

    def get(self, section, key):
        raw = self._config.get(section, key)
        return raw.split("#")[0].split(";")[0].strip()

    def set(self, section, key, value):
        self._config.set(section, key, value)

    def save(self):
        with open(self.config_path, "w") as f:
            self._config.write(f)


class Vault:
    cmd_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.abspath(f"{cmd_path}/vault.cfg")
    cfg = VaultConfig(config_path)

    @staticmethod
    def _get_image_device():
        return plistlib.loads(
            subprocess.check_output(
                [
                    "hdiutil",
                    "attach",
                    "-plist",
                    "-mountpoint",
                    Vault.cfg.mount_path,
                    Vault.cfg.img_path,
                ]
            )
        )["system-entities"][0].get("dev-entry")

    @staticmethod
    def _update_session():
        with open(Vault.cfg.session_path, "w") as f:
            f.write(str(time.time()))

    @staticmethod
    def _ensure_session_valid():
        is_valid = False
        session_exists = os.path.isfile(Vault.cfg.session_path)

        if session_exists:
            try:
                with open(Vault.cfg.session_path, "r") as f:
                    last_activity = float(f.read().strip())
                is_valid = (time.time() - last_activity) < Vault.cfg.session_timeout
            except (ValueError, IOError):
                pass

        if is_valid:
            Vault._update_session()
        else:
            if session_exists:
                os.remove(Vault.cfg.session_path)
            Vault.lock()
            raise PermissionError(
                "Session expired. Vault has been locked. Run 'vault unlock' to unlock it."
            )

    @staticmethod
    def _get_validated_connection():
        Vault._ensure_session_valid()
        conn = sqlite3.connect(Vault.cfg.db_path)
        return conn

    @staticmethod
    def init(args):
        img_exists = os.path.isfile(Vault.cfg.img_path)

        if not img_exists:
            subprocess.call(
                [
                    "hdiutil",
                    "create",
                    "-type",
                    "UDIF",
                    "-fs",
                    "Journaled HFS+",
                    "-size",
                    "100m",
                    "-volname",
                    "vault",
                    "-encryption",
                    "AES-256",
                    "-agentpass",
                    "-attach",
                    Vault.cfg.img_path,
                ]
            )
        else:
            raise ValueError("vault has already been initiated.")

        conn = sqlite3.connect(Vault.cfg.db_path)
        c = conn.cursor()

        c.execute("CREATE TABLE vaults(name text)")
        c.execute("INSERT INTO vaults VALUES ('_main')")
        c.execute(
            """CREATE TABLE logins(
            name text,
            username text,
            password text,
            email text,
            url text,
            notes text,
            vault text)"""
        )

        if args.vaults:
            for vault in args.vaults:
                c.execute("INSERT INTO vaults VALUES (?)", (vault,))

        conn.commit()
        conn.close()
        Vault._update_session()
        Logger.success("Vault initialized successfully.")

    @staticmethod
    def new(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":
            t = (args.name,)
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if vault_exists:
                conn.close()
                raise ValueError(f"Vault '{args.name}' already exists.")

            c.execute("INSERT INTO vaults VALUES (?)", t)
            conn.commit()
            conn.close()
            Logger.success(f"Created new vault '{args.name}'.")
            return

        action = ["Saved new"]

        t = (args.dest_vault,)
        vault_exists = c.execute("SELECT name FROM vaults WHERE name = ?", t).fetchone()

        if not vault_exists:
            if not confirm_prompt(
                f"Vault '{args.dest_vault}' does not exist. Do you want to create it",
                default=True,
            ):
                return

            c.execute("INSERT INTO vaults VALUES (?)", t)
            conn.commit()
            Logger.success(f"Created new vault '{args.dest_vault}'.")

        t = (args.name, args.dest_vault)
        login_exists = c.execute(
            "SELECT name, vault FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if login_exists:
            if not args.force and not confirm_prompt(
                f"Overwrite existing login '{args.name}' in vault '{args.dest_vault}'"
            ):
                return
            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            action[0] = "Overwrote"

        questions_length = 4
        question_index = [0]

        def increment_question():
            question_index[0] += 1
            return question_index[0]

        login = [args.name]

        if args.username:
            login.append(args.username)
            questions_length -= 1
        else:
            login.append(
                input(f"[{increment_question()}/{questions_length}] Username: ")
            )

        if args.genpass:
            login.append(Vault.genpass())
            questions_length -= 1
        elif args.password:
            login.append(args.password)
            questions_length -= 1
        else:
            login.append(
                getpass.getpass(
                    f"[{increment_question()}/{questions_length}] Password: "
                )
            )

        if args.email:
            login.append(args.email)
            questions_length -= 1
        else:
            login.append(input(f"[{increment_question()}/{questions_length}] Email: "))

        if args.url:
            login.append(args.url)
            questions_length -= 1
        else:
            login.append(input(f"[{increment_question()}/{questions_length}] URL: "))

        login.extend(
            [
                args.notes,
                args.dest_vault,
            ]
        )

        c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(login))
        Logger.success(f"{action[0]} login '{args.name}' in vault '{args.dest_vault}'")
        if args.genpass:
            if not copy_to_clipboard(login[2], "Password"):
                if confirm_prompt(
                    "Display generated password?",
                    cancel_message=None,
                ):
                    Logger.info(f"Password: {login[2]}")

        conn.commit()
        conn.close()

    @staticmethod
    def list(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.src_vault:

            t = (args.src_vault,)
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError(f"Vault '{args.src_vault}' does not exist.")

            for login in c.execute(
                "SELECT name FROM logins WHERE vault = ? ORDER BY LOWER(name)", t
            ):
                Logger.info(login[0])
            return

        vaults = c.execute("SELECT name FROM vaults ORDER BY LOWER(name)").fetchall()

        for vault in vaults:
            login_count = len(
                c.execute(
                    "SELECT name FROM logins WHERE vault = ?", tuple([vault[0]])
                ).fetchall()
            )
            Logger.info(f"{Logger.bold(vault[0])} ({login_count})")

        conn.close()

    @staticmethod
    def peek(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError(f"Vault '{args.src_vault}' does not exist.")

        login = c.execute(
            "SELECT * FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()
        columns = c.execute("PRAGMA table_info(logins)").fetchall()
        conn.close()

        if not login:
            conn.close()
            raise ValueError(
                f"Login '{args.name}' does not exist in vault '{args.src_vault}'."
            )

        # Display all fields except password
        for i, col in enumerate(login):
            field_name = columns[i][1]
            if field_name != "password":
                Logger.info(f"{Logger.bold(field_name)}: {col}")

    @staticmethod
    def open(args):
        Vault.peek(args)

        conn = Vault._get_validated_connection()
        c = conn.cursor()
        password = c.execute(
            "SELECT password FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()[0]
        conn.close()

        if not copy_to_clipboard(password, "Password"):
            if confirm_prompt("Display password?", cancel_message=None):
                Logger.info(f"{Logger.bold('Password')}: {password}")

    @staticmethod
    def edit(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError(f"Vault '{args.src_vault}' does not exist.")

        login = c.execute(
            "SELECT * FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()

        if not login:
            conn.close()
            raise ValueError(
                f"Login '{args.name}' does not exist in vault '{args.src_vault}'."
            )

        edited_login = [args.name]

        if args.username or args.password or args.email or args.url or args.notes:
            edited_login.extend(
                [
                    args.username or login[1],
                    args.password or login[2],
                    args.email or login[3],
                    args.url or login[4],
                    args.notes or login[5],
                ]
            )

        else:

            edited_login.extend(
                [
                    input(f"[1/4] Username [{login[1]}]: ") or login[1],
                    getpass.getpass("[2/4] Password [*****]: ") or login[2],
                    input(f"[3/4] Email [{login[3]}]: ") or login[3],
                    input(f"[4/4] URL [{login[4]}]: ") or login[4],
                    login[5],
                ]
            )

        edited_login.append(login[6])

        c.execute("DELETE FROM logins WHERE name = ?", (args.name,))
        c.execute(
            "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(edited_login)
        )

        Logger.success(f"Edited login '{args.name}' in vault '{args.src_vault}'")

        conn.commit()
        conn.close()

    @staticmethod
    def delete(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":

            t = (args.name,)
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError(f"Vault '{args.name}' does not exist.")

            c.execute("DELETE FROM vaults WHERE name = ?", t)
            conn.commit()
            conn.close()
            Logger.success(f"Deleted vault '{args.name}'.")
            return

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError(f"Vault '{args.src_vault}' does not exist.")

        t = (args.name, args.src_vault)
        login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if not login_exists:
            conn.close()
            raise ValueError(
                f"Login '{args.name}' does not exist in vault '{args.src_vault}'."
            )

        c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
        conn.commit()
        conn.close()
        Logger.success(f"Deleted login '{args.name}' in vault '{args.src_vault}'.")

    @staticmethod
    def rename(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":

            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", (args.old_name,)
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError(f"Vault '{args.old_name}' does not exists.")

            t = (args.new_name,)
            new_vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if new_vault_exists:
                if not args.force and not confirm_prompt(
                    f"Overwrite existing vault '{args.new_name}'",
                ):
                    return
                c.execute("DELETE FROM vaults WHERE name = ?", t)
                c.execute("DELETE FROM logins WHERE vault = ?", t)
                Logger.success(f"Deleted vault '{args.new_name}'.")

            t = (args.new_name, args.old_name)
            c.execute("UPDATE vaults SET name = ? WHERE name = ?", t)
            c.execute("UPDATE logins SET vault = ? WHERE vault = ?", t)
            conn.commit()
            conn.close()
            Logger.success(f"Renamed vault '{args.old_name}' to '{args.new_name}'.")
            return

        else:
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError(f"Vault '{args.src_vault}' does not exist.")

            t = (args.new_name, args.src_vault)
            new_login_exists = c.execute(
                "SELECT name FROM logins WHERE name = ? AND vault = ?", t
            ).fetchone()

            if new_login_exists:
                if not args.force and not confirm_prompt(
                    f"Overwrite existing login '{args.new_name}'",
                ):
                    return
                c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
                Logger.success(
                    f"Deleted login '{args.new_name}' in vault '{args.src_vault}'."
                )

            c.execute(
                "UPDATE logins SET name = ? WHERE name = ? AND vault = ?",
                (args.new_name, args.old_name, args.src_vault),
            )

            conn.commit()
            conn.close()
            Logger.success(
                f"Renamed login '{args.old_name}' to '{args.new_name}' in vault '{args.src_vault}'."
            )

    @staticmethod
    def move(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        src_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
        ).fetchone()

        if not src_exists:
            conn.close()
            raise ValueError(f"Source vault '{args.src_vault}' does not exist.")

        dest_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.dest_vault,)
        ).fetchone()

        if not dest_exists:
            conn.close()
            raise ValueError(f"Destination vault '{args.dest_vault}' does not exist.")

        login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()

        if not login_exists:
            conn.close()
            raise ValueError(f"Login '{args.name}' does not exist.")

        t = (args.name, args.dest_vault)
        dest_login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if dest_login_exists:
            if not args.force and not confirm_prompt(
                f"Overwrite existing login '{args.name}' in vault '{args.dest_vault}'",
            ):
                return
            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            Logger.success(f"Deleted login '{args.name}' in vault '{args.dest_vault}'")

        c.execute(
            "UPDATE logins SET vault = ? WHERE name = ? AND vault = ?",
            (args.dest_vault, args.name, args.src_vault),
        )
        conn.commit()
        conn.close()
        Logger.success(
            f"Moved login '{args.name}' from vault '{args.src_vault}' to vault '{args.dest_vault}'."
        )

    @staticmethod
    def genpass(args=None):

        letters = string.ascii_letters
        digits = string.digits
        symbols = string.punctuation

        if args:
            length = args.length or Vault.cfg.get("genpass", "length")
            digits_count = args.digits or Vault.cfg.get("genpass", "digits")
            symbols_count = args.symbols or Vault.cfg.get("genpass", "symbols")
            length = int(length)
            digits_count = int(digits_count)
            symbols_count = int(symbols_count)
        else:
            length = int(Vault.cfg.get("genpass", "length"))
            digits_count = int(Vault.cfg.get("genpass", "digits"))
            symbols_count = int(Vault.cfg.get("genpass", "symbols"))

        letters_count = length - digits_count - symbols_count

        if letters_count < 0:
            symbols_count -= digits_count + symbols_count - length
            letters_count = 0

        # create a string with random letters, digits, and symbols
        password = (
            "".join(random.sample(letters, min(letters_count, len(letters))))
            + "".join(random.sample(digits, min(digits_count, len(digits))))
            + "".join(random.sample(symbols, min(symbols_count, len(symbols))))
        )

        # randomly mix the characters to form the password
        password = "".join(random.sample(password, len(password)))

        if not args:
            return password

        if args.login:
            conn = Vault._get_validated_connection()
            c = conn.cursor()

            login_exists = c.execute(
                "SELECT name FROM logins WHERE name = ? AND vault = ?",
                (args.login, args.vault),
            ).fetchone()

            if login_exists:
                if not args.force and not confirm_prompt(
                    f"Edit password for existing login '{args.login}' in vault '{args.vault}'"
                ):
                    return

                c.execute(
                    "UPDATE logins SET password = ? WHERE name = ? AND vault = ?",
                    (password, args.login, args.vault),
                )
                Logger.success(
                    f"Edited password for login '{args.login}' in vault '{args.vault}'"
                )
                conn.commit()
                conn.close()

            else:
                login = (
                    args.login,
                    input("[1/3] Username: "),
                    password,
                    input("[2/3] Email: "),
                    input("[3/3] URL: "),
                    "",
                    args.vault,
                )
                c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", login)
                Logger.success(
                    f"Saved new login '{args.login}' in vault '{args.vault}'"
                )
                conn.commit()
                conn.close()

        if not copy_to_clipboard(password, "Generated password"):
            if confirm_prompt("Print password to console?", cancel_message=None):
                Logger.info(f"{Logger.bold('Password')}: {password}")
            else:
                return

    @staticmethod
    def login(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        src_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", (args.src_vault,)
        ).fetchone()

        if not src_exists:
            conn.close()
            raise ValueError(f"Source vault '{args.src_vault}' does not exist.")

        login = c.execute(
            "SELECT username, password, url FROM logins WHERE name = ? AND vault = ?",
            (args.login_name, args.src_vault),
        ).fetchone()

        if not login:
            conn.close()
            raise ValueError(
                f"Login '{args.login_name}' does not exist in vault '{args.src_vault}'."
            )

        conn.close()

        Logger.info(f"{Logger.bold('Username')}: {login[0]}")
        if not copy_to_clipboard(login[1], "Password"):
            if confirm_prompt("Display password?", cancel_message=None):
                Logger.info(f"{Logger.bold('Password')}: {login[1]}")

        # Open URL in browser
        if login[2]:  # Only if URL exists
            url = login[2]
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"
            webbrowser.open(url)

    @staticmethod
    def config(args):
        if args.list:
            for section in Vault.cfg.sections():
                Logger.info(section, bold=True)
                for key, value in Vault.cfg.items(section):
                    if section == "vault":
                        Logger.info(f"  {Logger.bold(key)} = {value}")
                    else:
                        Logger.info(f"  {Logger.bold(f'{(section)}.{key}')} = {value}")
            return

        if args.option_string is None:
            raise ValueError("No option specified. Use -l to list all options.")

        # turn 'section.key' to ['section', 'key']
        option_list = args.option_string.split(".")

        # If there was no section provided, set the section to 'vault'
        if len(option_list) == 1:
            option_list = ["vault"] + option_list

        (section, key) = option_list

        if not Vault.cfg.has_option(section, key):
            raise ValueError(f"Invalid config option: '{section}.{key}'")

        if args.get or args.value is None:
            value = Vault.cfg.get(section, key)
            Logger.info(value)
            return

        Vault.cfg.set(section, key, args.value)
        Logger.success(f"Set {section}.{key} to {args.value}")
        Vault.cfg.save()

    @staticmethod
    def lock(_=None):
        unlocked = os.path.ismount(Vault.cfg.mount_path)
        if not unlocked:
            Logger.success("Vaults are already locked.")
            return

        subprocess.call(["diskutil", "unmount", Vault.cfg.mount_path])

        device = Vault._get_image_device()
        if not device:
            Logger.warning("No device nodes found for the vault image.")
            return
        subprocess.call(["hdiutil", "detach", device])

        if os.path.isfile(Vault.cfg.session_path):
            os.remove(Vault.cfg.session_path)

        Logger.success("Locked vaults.")

    @staticmethod
    def unlock(_=None):
        unlocked = os.path.ismount(Vault.cfg.mount_path)
        if unlocked:
            Logger.success("Vaults are already unlocked.")
        else:
            unlock = subprocess.call(
                [
                    "hdiutil",
                    "attach",
                    "-mountpoint",
                    Vault.cfg.mount_path,
                    Vault.cfg.img_path,
                ]
            )
            if unlock == 0:
                Logger.success("Unlocked vaults.")
        Vault._update_session()


args = parser.parse_args()
unlocked = os.path.ismount(Vault.cfg.mount_path)
dmgExists = unlocked or os.path.isfile(Vault.cfg.img_path)

if not hasattr(Vault, args.command):
    parser.error(f"Missing command handler for '{args.command}' command.")

if not dmgExists and args.command != "init":
    Logger.error("Vault image does not exist. Run 'vault init' to create it.")
    sys.exit(1)

try:
    if not unlocked and args.command != "unlock" and dmgExists:
        confirm_unlock = confirm_prompt(
            "Vaults are locked. Do you want to unlock them?", cancel_message=None
        )
        if confirm_unlock:
            Vault.unlock()
        else:
            raise PermissionError(
                "Vaults are locked. Run 'vault unlock' to unlock them."
            )

    fn = getattr(Vault, args.command)
    fn(args)
except PermissionError as e:
    Logger.error(e)
    sys.exit(1)
except KeyboardInterrupt:
    Logger.info("Operation cancelled")
    sys.exit(130)
except (ValueError, IOError) as e:
    Logger.error(e)
    sys.exit(1)
except Exception as e:
    Logger.error(f"An unexpected error occurred: {e}")
    sys.exit(1)
