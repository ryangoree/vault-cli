#!/usr/bin/env python3
#
# Command line utility to generate and manage passwords
#
# help:
#   vault -h
#
# To do:
#   - Rewrite consistent helps

from cli import parser
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


def confirm_prompt(message, cancel_message="Operation canceled.", default_no=True):
    suffix = " [y/N]?" if default_no else " [Y/n]?"

    def ask():
        response = input(message + suffix).lower().strip()
        if default_no and (response == "" or response.startswith("n")):
            print(cancel_message)
            return False
        elif not default_no and (response == "" or response.startswith("y")):
            return True
        elif response in ["y", "yes", "n", "no"]:
            return response.startswith("y")
        else:
            print("Invalid answer. Please enter y, yes, n, or no")
            return ask()

    return ask()


def copy_to_clipboard(text, description="Text"):
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
        print(f"{description} copied to clipboard")
        return True
    except subprocess.CalledProcessError:
        print(f"Failed to copy {description.lower()} to clipboard")
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
            "session_timeout": "900",  # 15 mins in seconds
            "session_path": os.path.abspath(cmd_path + "/.vault_session"),
            "img_path": os.path.abspath(cmd_path + "/vault.dmg"),
            "mount_path": "/Volumes/vault",
            "db_path": "/Volumes/vault/vault.db",
        }
        self._config["genpass"] = {"length": "16", "digits": "4", "symbols": "4"}

        self.save()
        print("Created default config file at %s" % self.config_path)

    @property
    def db_path(self):
        return self._config.get("vault", "db_path")

    @property
    def img_path(self):
        return self._config.get("vault", "img_path")

    @property
    def mount_path(self):
        return self._config.get("vault", "mount_path")

    @property
    def session_path(self):
        return self._config.get("vault", "session_path")

    @property
    def session_timeout(self):
        return self._config.getint("vault", "session_timeout")

    def has_option(self, section, key):
        return self._config.has_option(section, key)

    def items(self, section):
        return self._config.items(section)

    def sections(self):
        return self._config.sections()

    def get(self, section, key):
        return self._config.get(section, key)

    def set(self, section, key, value):
        self._config.set(section, key, value)

    def save(self):
        with open(self.config_path, "w") as f:
            self._config.write(f)


class Vault:
    cmd_path = os.path.dirname(os.path.realpath(__file__))
    config_path = os.path.abspath(cmd_path + "/vault.cfg")
    user_config = VaultConfig(config_path)

    @staticmethod
    def _get_image_device():
        return plistlib.loads(
            subprocess.check_output(
                [
                    "hdiutil",
                    "attach",
                    "-plist",
                    "-mountpoint",
                    Vault.user_config.mount_path,
                    Vault.user_config.img_path,
                ]
            )
        )["system-entities"][0].get("dev-entry")

    @staticmethod
    def _update_session():
        with open(Vault.user_config.session_path, "w") as f:
            f.write(str(time.time()))

    @staticmethod
    def _ensure_session_valid():
        is_valid = False
        session_exists = os.path.isfile(Vault.user_config.session_path)

        if session_exists:
            try:
                with open(Vault.user_config.session_path, "r") as f:
                    last_activity = float(f.read().strip())
                is_valid = (
                    time.time() - last_activity
                ) < Vault.user_config.session_timeout
            except (ValueError, IOError):
                pass

        if is_valid:
            Vault._update_session()
        else:
            if session_exists:
                os.remove(Vault.user_config.session_path)
            print("Session expired. Vault has been locked.")
            Vault.lock(None)
            sys.exit(2)

    @staticmethod
    def _get_validated_connection():
        Vault._ensure_session_valid()
        conn = sqlite3.connect(Vault.user_config.db_path)
        return conn

    @staticmethod
    def init(args):
        img_exists = os.path.isfile(Vault.user_config.img_path)

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
                    Vault.user_config.img_path,
                ]
            )
        else:
            raise ValueError("vault has already been initiated.")

        conn = sqlite3.connect(Vault.user_config.db_path)
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
                c.execute("INSERT INTO vaults VALUES (?)", tuple([vault]))

        conn.commit()
        conn.close()
        Vault._update_session()

    @staticmethod
    def new(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":
            t = tuple([args.name])
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if vault_exists:
                conn.close()
                raise ValueError("Vault '%s' already exists." % args.name)

            c.execute("INSERT INTO vaults VALUES (?)", t)
            conn.commit()
            conn.close()
            print("Created new vault '%s'." % args.name)
            return

        action = ["Saved new"]

        t = tuple([args.dest_vault])
        vault_exists = c.execute("SELECT name FROM vaults WHERE name = ?", t).fetchone()

        if not vault_exists:
            if not confirm_prompt(
                "Vault '%s' does not exist. Do you want to create it" % args.dest_vault,
                "New login canceled.",
            ):
                return

            c.execute("INSERT INTO vaults VALUES (?)", t)
            conn.commit()
            print("Created new vault '%s'." % args.dest_vault)

        t = (args.name, args.dest_vault)
        login_exists = c.execute(
            "SELECT name, vault FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if login_exists and not args.force:
            if not confirm_prompt(
                "Overwrite existing login '%s' in vault '%s'"
                % (args.name, args.dest_vault),
                "New login canceled.",
            ):
                return

            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            action[0] = "Overwrote"

        elif login_exists and args.force:
            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            action[0] = "Overwrote"

        questions_length = 3 if args.genpass else 4
        question_index = [1]

        def increment_question():
            question_index[0] += 1
            return question_index[0]

        login = [args.name, input("[1/%i] Username: " % questions_length)]

        if args.genpass:
            login.append(Vault.genpass())
        else:
            login.append(
                getpass.getpass(
                    "[%i/%i] Password: " % (increment_question(), questions_length)
                )
            )

        login.extend(
            [
                input("[%i/%i] Email: " % (increment_question(), questions_length)),
                input("[%i/%i] URL: " % (increment_question(), questions_length)),
                args.notes,
                args.dest_vault,
            ]
        )

        c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(login))
        print("%s login '%s' in vault '%s'" % (action[0], args.name, args.dest_vault))
        if args.genpass:
            if not copy_to_clipboard(login[2], "Password"):
                if confirm_prompt(
                    "Copy failed. Display generated password?", cancel_message=""
                ):
                    print("Password: %s" % login[2])

        conn.commit()
        conn.close()

    @staticmethod
    def list(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.src_vault:

            t = tuple([args.src_vault])
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError("Vault '%s' does not exist." % args.src_vault)

            for login in c.execute(
                "SELECT name FROM logins WHERE vault = ? ORDER BY LOWER(name)", t
            ):
                print(login[0])
            return

        vaults = c.execute("SELECT name FROM vaults ORDER BY LOWER(name)").fetchall()

        for vault in vaults:
            login_count = len(
                c.execute(
                    "SELECT name FROM logins WHERE vault = ?", tuple([vault[0]])
                ).fetchall()
            )
            print("%s (%i)" % (vault[0], login_count))

    @staticmethod
    def open(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError("Vault '%s' does not exist." % args.src_vault)

        login = c.execute(
            "SELECT * FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()
        columns = c.execute("PRAGMA table_info(logins)").fetchall()

        if not login:
            conn.close()
            raise ValueError(
                "Login '%s' does not exist in vault '%s'." % (args.name, args.src_vault)
            )

        # Display all fields, but copy password to clipboard instead of showing
        password = ""
        for i, col in enumerate(login):
            field_name = columns[i][1]
            if field_name == "password":
                password = col
            else:
                print("%s: %s" % (field_name, col))

        if not copy_to_clipboard(password, "Password"):
            if confirm_prompt("Copy failed. Display password?", cancel_message=""):
                print("Password: %s" % password)

    @staticmethod
    def edit(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError("Vault '%s' does not exist." % args.src_vault)

        login = c.execute(
            "SELECT * FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()

        if not login:
            conn.close()
            raise ValueError(
                "Login '%s' does not exist in vault '%s'." % (args.name, args.src_vault)
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
                    input("[1/4] Username [%s]: " % login[1]) or login[1],
                    getpass.getpass("[2/4] Password [*****]: ") or login[2],
                    input("[3/4] Email [%s]: " % login[3]) or login[3],
                    input("[4/4] URL [%s]: " % login[4]) or login[4],
                    login[5],
                ]
            )

        edited_login.append(login[6])

        c.execute("DELETE FROM logins WHERE name = ?", tuple([args.name]))
        c.execute(
            "INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(edited_login)
        )

        print("Edited login '%s' in vault '%s'" % (args.name, args.src_vault))

        conn.commit()
        conn.close()

    @staticmethod
    def delete(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":

            t = tuple([args.name])
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError("Vault '%s' does not exist." % args.name)

            c.execute("DELETE FROM vaults WHERE name = ?", t)
            conn.commit()
            conn.close()
            print("Deleted vault '%s'." % args.name)
            return

        vault_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
        ).fetchone()

        if not vault_exists:
            conn.close()
            raise ValueError("Vault '%s' does not exist." % args.src_vault)

        t = (args.name, args.src_vault)
        login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if not login_exists:
            conn.close()
            print("Login '%s' does not exist in vault '%s'." % t)
            return

        c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
        conn.commit()
        conn.close()
        print("Deleted login '%s' in vault '%s'." % t)

    @staticmethod
    def rename(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        if args.mode == "vault":

            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", tuple([args.old_name])
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError("Vault '%s' does not exists." % args.old_name)

            t = tuple([args.new_name])
            new_vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", t
            ).fetchone()

            if new_vault_exists and not args.force:
                if not confirm_prompt(
                    "Overwrite existing vault '%s'" % args.new_name,
                    "Vault rename canceled.",
                ):
                    return

                c.execute("DELETE FROM vaults WHERE name = ?", t)
                c.execute("DELETE FROM logins WHERE vault = ?", t)
                print("Deleted vault '%s'." % args.new_name)

            elif new_vault_exists and args.force:
                c.execute("DELETE FROM vaults WHERE name = ?", t)
                c.execute("DELETE FROM logins WHERE vault = ?", t)
                print("Deleted vault '%s'." % args.new_name)

            t = (args.new_name, args.old_name)
            c.execute("UPDATE vaults SET name = ? WHERE name = ?", t)
            c.execute("UPDATE logins SET vault = ? WHERE vault = ?", t)
            conn.commit()
            conn.close()
            print("Renamed vault '%s' to '%s'." % (args.old_name, args.new_name))
            return

        else:
            vault_exists = c.execute(
                "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
            ).fetchone()

            if not vault_exists:
                conn.close()
                raise ValueError("Vault '%s' does not exist." % args.src_vault)

            t = (args.new_name, args.src_vault)
            new_login_exists = c.execute(
                "SELECT name FROM logins WHERE name = ? AND vault = ?", t
            ).fetchone()

            if new_login_exists and not args.force:
                if not confirm_prompt(
                    "Overwrite existing login '%s'" % args.new_name,
                    "Login rename canceled.",
                ):
                    return

                c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
                print("Deleted login '%s' in vault '%s'." % t)

            elif new_login_exists and args.force:
                c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
                print("Deleted login '%s' in vault '%s'." % t)

            c.execute(
                "UPDATE logins SET name = ? WHERE name = ? AND vault = ?",
                (args.new_name, args.old_name, args.src_vault),
            )

            conn.commit()
            conn.close()
            print(
                "Renamed login '%s' to '%s' in vault '%s'."
                % (args.old_name, args.new_name, args.src_vault)
            )

    @staticmethod
    def move(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        src_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
        ).fetchone()

        if not src_exists:
            conn.close()
            raise ValueError("Source vault '%s' does not exist." % args.src_vault)

        dest_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.dest_vault])
        ).fetchone()

        if not dest_exists:
            conn.close()
            raise ValueError("Destination vault '%s' does not exist." % args.dest_vault)

        login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?",
            (args.name, args.src_vault),
        ).fetchone()

        if not login_exists:
            conn.close()
            raise ValueError("Login '%s' does not exist." % args.name)

        t = (args.name, args.dest_vault)
        dest_login_exists = c.execute(
            "SELECT name FROM logins WHERE name = ? AND vault = ?", t
        ).fetchone()

        if dest_login_exists and not args.force:
            if not confirm_prompt(
                "Overwrite existing login '%s' in vault '%s'" % t, "Move canceled."
            ):
                return

            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            print("Deleted login '%s' in vault '%s'" % t)

        elif dest_login_exists and args.force:
            c.execute("DELETE FROM logins WHERE name = ? AND vault = ?", t)
            print("Deleted login '%s' in vault '%s'" % t)

        c.execute(
            "UPDATE logins SET vault = ? WHERE name = ? AND vault = ?",
            (args.dest_vault, args.name, args.src_vault),
        )
        conn.commit()
        conn.close()
        print(
            "Moved login '%s' from vault '%s' to vault '%s'."
            % (args.name, args.src_vault, args.dest_vault)
        )

    @staticmethod
    def genpass(args=None):

        letters = string.ascii_letters
        digits = string.digits
        symbols = string.punctuation

        if args:
            length = args.length or Vault.user_config.get("genpass", "length")
            digits_count = args.digits or Vault.user_config.get("genpass", "digits")
            symbols_count = args.symbols or Vault.user_config.get("genpass", "symbols")
            length = int(length)
            digits_count = int(digits_count)
            symbols_count = int(symbols_count)
        else:
            length = int(Vault.user_config.get("genpass", "length"))
            digits_count = int(Vault.user_config.get("genpass", "digits"))
            symbols_count = int(Vault.user_config.get("genpass", "symbols"))

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

            if login_exists and not args.force:
                if confirm_prompt(
                    "Edit password for existing login '%s' in vault '%s'"
                    % (args.login, args.vault),
                    "Save canceled.",
                ):
                    c.execute(
                        "UPDATE logins SET password = ? WHERE name = ? AND vault = ?",
                        (password, args.login, args.vault),
                    )
                    print(
                        "Edited password for login '%s' in vault '%s'"
                        % (args.login, args.vault)
                    )
                    conn.commit()
                    conn.close()
                else:
                    return

            elif login_exists and args.force:
                c.execute(
                    "UPDATE logins SET password = ? WHERE name = ? AND vault = ?",
                    (password, args.login, args.vault),
                )
                print(
                    "Edited password for login '%s' in vault '%s'"
                    % (args.login, args.vault)
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
                print("Saved new login '%s' in vault '%s'" % (args.login, args.vault))
                conn.commit()
                conn.close()

        if not copy_to_clipboard(password, "Generated password"):
            if confirm_prompt(
                "Copy failed. Print password to console?", cancel_message=""
            ):
                print("Password: " + password)
            else:
                return

        else:
            print("Password copied to clipboard.")

    @staticmethod
    def login(args):
        conn = Vault._get_validated_connection()
        c = conn.cursor()

        src_exists = c.execute(
            "SELECT name FROM vaults WHERE name = ?", tuple([args.src_vault])
        ).fetchone()

        if not src_exists:
            conn.close()
            raise ValueError("Source vault '%s' does not exist." % args.src_vault)

        t = (args.login_name, args.src_vault)
        login = c.execute(
            "SELECT username, password, url FROM logins WHERE name = ? AND vault = ?",
            t,
        ).fetchone()

        if not login:
            conn.close()
            raise ValueError("Login '%s' does not exist in vault '%s'." % t)

        conn.close()

        print("Username: " + login[0])
        if not copy_to_clipboard(login[1], "Password"):
            if confirm_prompt("Copy failed. Display password?", cancel_message=""):
                print("Password: " + login[1])

        # Open URL in browser
        if login[2]:  # Only if URL exists
            url = login[2]
            if not url.startswith(("http://", "https://")):
                url = "https://" + url
            webbrowser.open(url)

    @staticmethod
    def config(args):
        if args.list:
            for section_name in Vault.user_config.sections():
                print("%s" % section_name)
                for name, value in Vault.user_config.items(section_name):
                    print("     %s.%s = %s" % (section_name, name, value))
            return

        if args.option_string is None:
            raise ValueError("No option specified. Use -l to list all options.")

        # turn 'section.key' to ['section', 'key']
        option_list = args.option_string.split(".")

        # If there was no section provided, set the section to 'vault'
        if len(option_list) == 1:
            option_list = ["vault"] + option_list

        (section, option) = option_list

        if not Vault.user_config.has_option(section, option):
            raise ValueError("No %s.%s option found in configs." % (section, option))

        if args.get or args.value is None:
            value = Vault.user_config.get(section, option)
            print(value)
            return

        Vault.user_config.set(section, option, args.value)
        print("Set %s.%s to %s" % (section, option, args.value))
        Vault.user_config.save()

    @staticmethod
    def lock(_):
        unlocked = os.path.ismount(Vault.user_config.mount_path)
        if not unlocked:
            print("Vaults are already locked.")
            return

        subprocess.call(["diskutil", "unmount", Vault.user_config.mount_path])

        device = Vault._get_image_device()
        if not device:
            print("WARNING: No device nodes found for the vault image.")
            return
        subprocess.call(["hdiutil", "detach", device])

        if os.path.isfile(Vault.user_config.session_path):
            os.remove(Vault.user_config.session_path)

        print("Locked vaults.")

    @staticmethod
    def unlock(_):
        unlock = subprocess.call(
            [
                "hdiutil",
                "attach",
                "-mountpoint",
                Vault.user_config.mount_path,
                Vault.user_config.img_path,
            ]
        )
        print("Unlock: %s" % unlock)
        if unlock == 0:
            print("Unlocked vaults.")
            Vault._update_session()


args = parser.parse_args()
unlocked = os.path.ismount(Vault.user_config.mount_path)
dmgExists = os.path.isfile(Vault.user_config.img_path)

if not unlocked and args.command != "unlock" and dmgExists:
    print("Vaults are locked. To unlock them, run: vault unlock")
    sys.exit(2)

if args.command == None:
    print("\nNo command specified.\n")
    parser.print_help()
    sys.exit(2)

if not hasattr(Vault, args.command):
    print("\nUnknown command: %s\n" % args.command)
    parser.print_help()
    sys.exit(2)

try:
    fn = getattr(Vault, args.command)
    fn(args)
except (KeyboardInterrupt, SystemExit):
    print("\nOperation canceled.")
    sys.exit(0)
except (ValueError, IOError):
    print("\nError: %s\n" % sys.exc_info()[1])
    parser.print_help()
    sys.exit(2)
