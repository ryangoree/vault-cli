import argparse
import sys


class Logger:
    class Colors:
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        MAGENTA = "\033[35m"
        CYAN = "\033[36m"
        WHITE = "\033[37m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

    @staticmethod
    def info(msg):
        """Prints an informational message in blue."""
        print(f"{Logger.Colors.BLUE}ℹ︎{Logger.Colors.RESET} {msg}")

    @staticmethod
    def success(msg):
        """Prints a success message in green."""
        print(f"{Logger.Colors.GREEN}✓{Logger.Colors.RESET} {msg}")

    @staticmethod
    def warning(msg):
        """Prints a warning message in yellow."""
        print(f"{Logger.Colors.YELLOW}⚠︎{Logger.Colors.RESET} {msg}")

    @staticmethod
    def error(msg):
        """Prints an error message to stderr in red."""
        print(
            f"{Logger.Colors.RED}✖︎ Error:{Logger.Colors.RESET} {msg}", file=sys.stderr
        )


# Make the parser show the help msg when there's an error
class DefaultHelpParser(argparse.ArgumentParser):
    def error(self, message):
        print()
        Logger.error(f"{message}\n")
        self.print_help()
        sys.exit(2)


parser = DefaultHelpParser(
    prog="vault", description="Manage logins and generate passwords"
)

subparsers = parser.add_subparsers(
    dest="command", metavar="<command>", help="description:", required=True
)

# init
init_parser = subparsers.add_parser("init", help="Initiate Vault.")
init_parser.add_argument(
    "-v",
    "--vault",
    action="append",
    default=[],
    dest="vaults",
    metavar="<vault-name>",
    help="Init with the specified vault. Use multiple times to append more vaults.",
)

# new
new_parser = subparsers.add_parser("new", help="Create a new login or vault.")
new_parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    dest="force",
    help="Do not prompt for confirmation before overwriting an existing login/vault with the same name.",
)
new_parser.add_argument(
    "-g",
    "--genpass",
    action="store_true",
    dest="genpass",
    help="Generate a new password for the new login.",
)
new_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="dest_vault",
    default="_main",
    metavar="<vault-name>",
    help="Save new login in specified vault.",
)
new_parser.add_argument(
    "-v",
    "--vault",
    action="store_const",
    dest="mode",
    const="vault",
    default="login",
    help="Create a new vault instead of a login.",
)
new_parser.add_argument(
    "-n",
    "--with-notes",
    action="store",
    dest="notes",
    default="",
    metavar="<notes>",
    help="Add notes to the login.",
)
new_parser.add_argument(
    "name",
    action="store",
    metavar="<login-name>",
    help="Name the new login or vault.",
)

# list
list_parser = subparsers.add_parser("list", help="List all logins or vaults.")
list_parser.add_argument(
    "src_vault",
    action="store",
    metavar="<vault-name>",
    nargs="?",
    help="List logins in the specified vault.",
)

# open
open_parser = subparsers.add_parser("open", help="Open a login.")
open_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="src_vault",
    default="_main",
    metavar="<vault-name>",
    help="Open a login in the specified vault.",
)
open_parser.add_argument(
    "name",
    action="store",
    metavar="<login-name>",
    help="Name of the login to open.",
)

# edit
edit_parser = subparsers.add_parser("edit", help="Edit an existing login.")
edit_parser.add_argument(
    "-e",
    "--email",
    action="store",
    dest="email",
    metavar="<email>",
    nargs="?",
    help="Edit the email of a login specifically.",
)
edit_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="src_vault",
    default="_main",
    metavar="<vault-name>",
    help="Edit login in specified vault.",
)
edit_parser.add_argument(
    "-n",
    "--notes",
    action="store",
    dest="notes",
    metavar="<notes>",
    nargs="?",
    help="Edit the notes of a login specifically.",
)
edit_parser.add_argument(
    "-p",
    "--password",
    action="store",
    dest="password",
    metavar="<password>",
    nargs="?",
    help="Edit the password of a login specifically.",
)
edit_parser.add_argument(
    "-r",
    "--url",
    action="store",
    dest="url",
    metavar="<url>",
    nargs="?",
    help="Edit the URL of a login specifically.",
)
edit_parser.add_argument(
    "-u",
    "--username",
    action="store",
    dest="username",
    metavar="<username>",
    nargs="?",
    help="Edit the username of a login specifically.",
)
edit_parser.add_argument(
    "name",
    action="store",
    metavar="<login-name>",
    help="Name of the login to edit.",
)

# delete
delete_parser = subparsers.add_parser(
    "delete", help="Delete an existing login or vault."
)
delete_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="src_vault",
    default="_main",
    metavar="<vault-name>",
    help="Delete login is specified vault.",
)
delete_parser.add_argument(
    "-v",
    "--vault",
    action="store_const",
    dest="mode",
    const="vault",
    default="login",
    help="Delete a vault instead of a login.",
)
delete_parser.add_argument(
    "name",
    action="store",
    metavar="<login-name>",
    help="Name of the login or vault to delete.",
)

#  rename
rename_parser = subparsers.add_parser(
    "rename", help="Rename an existing login or vault."
)
rename_parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    dest="force",
    help="Do not prompt for confirmation before overwriting an existing login with the same name.",
)
rename_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="src_vault",
    default="_main",
    metavar="<vault-name>",
    help="Rename a login in the specified vault.",
)
rename_parser.add_argument(
    "-v",
    "--vault",
    action="store_const",
    dest="mode",
    const="vault",
    default="login",
    metavar="<vault-name>",
    help="Rename a vault instead of a login.",
)
rename_parser.add_argument(
    "old_name",
    action="store",
    metavar="<old-login-name>",
    help="The original name of the login to be renamed.",
)
rename_parser.add_argument(
    "new_name",
    action="store",
    metavar="<new-login-name>",
    help="The new name for the login file.",
)

# move
move_parser = subparsers.add_parser(
    "move", help="Move an existing login from vault to vault."
)
move_parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    dest="force",
    help="Do not prompt for confirmation before overwriting an existing login with the same name.",
)
move_parser.add_argument(
    "name",
    action="store",
    metavar="<login-name>",
    help="The name of the login to move.",
)
move_parser.add_argument(
    "src_vault",
    action="store",
    metavar="<source-vault-name>",
    help="The name of the vault that the login is currently in.",
)
move_parser.add_argument(
    "dest_vault",
    action="store",
    metavar="<destination-vault-name>",
    help="The name of the vault to move the login in to.",
)

# genpass
genpass_parser = subparsers.add_parser("genpass", help="Generate a new password.")
genpass_parser.add_argument(
    "-d",
    "--digits",
    action="store",
    dest="digits",
    metavar="<digits-count>",
    help="Generate a password with the specified number of digits.",
)
genpass_parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    dest="force",
    help="Do not prompt for confirmation before overwriting an existing login with the same name.",
)
genpass_parser.add_argument(
    "-l",
    "--save-as",
    action="store",
    dest="login",
    nargs="?",
    metavar="<login-name>",
    help="Save the generated password in a new login.",
)
genpass_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="vault",
    default="_main",
    nargs="?",
    metavar="<vault-name>",
    help="Save new login in specified vault.",
)
genpass_parser.add_argument(
    "-s",
    "--symbols",
    action="store",
    dest="symbols",
    metavar="<symbols-count>",
    help="Generate a password with the specified number of symbols.",
)
genpass_parser.add_argument(
    "length",
    action="store",
    nargs="?",
    metavar="<length>",
    help="Generate a password with the specified length.",
)

# login
login_parser = subparsers.add_parser("login", help="Open the URL of a login.")
login_parser.add_argument(
    "-i",
    "--in",
    action="store",
    dest="src_vault",
    default="_main",
    metavar="<vault-name>",
    help="The vault to look in for the the login.",
)
login_parser.add_argument(
    "login_name",
    action="store",
    metavar="<login-name>",
    help="The name of the login from which to open the URL.",
)

# config
config_parser = subparsers.add_parser("config", help="View/edit vault configurations.")
config_parser.add_argument(
    "-g",
    "--get",
    action="store_true",
    dest="get",
    help="Get the value of an option.",
)
config_parser.add_argument(
    "-l",
    "--list",
    action="store_true",
    dest="list",
    help="List all config options.",
)
config_parser.add_argument(
    "option_string",
    action="store",
    nargs="?",
    metavar="<option>",
    help="The option to edit/get.",
)
config_parser.add_argument(
    "value",
    action="store",
    nargs="?",
    metavar="<new-value>",
    help="The value to which the option will be set.",
)

# lock
lock_parser = subparsers.add_parser("lock", help="Lock the vault utility.")

# unlock
unlock_parser = subparsers.add_parser(
    "unlock", help="Unlock the vault utility with your master password."
)
