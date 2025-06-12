class Logger:
    # Formatting Syntax: ESC + CSI + SGR code + [; SGR code]* + m
    #   - ESC character = `\033` (octal) / `\x1b` (hex) / `\u001b` (unicode)
    #   - Control Sequence Introducer (CSI) = `[`
    #   - Select Graphic Rendition (SGR) codes = `31m`, `32m`, etc.

    class Format:
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        MAGENTA = "\033[35m"
        CYAN = "\033[36m"
        WHITE = "\033[37m"
        DEFAULT = "\033[39m"
        BOLD = "\033[1m"
        DIM = "\033[2m"
        ITALIC = "\033[3m"
        UNDERLINE = "\033[4m"
        STRIKETHROUGH = "\033[9m"
        RESET = "\033[0m"

    @staticmethod
    def red(text):
        """Formats text as red."""
        return f"{Logger.Format.RED}{text}{Logger.Format.RESET}"

    @staticmethod
    def green(text):
        """Formats text as green."""
        return f"{Logger.Format.GREEN}{text}{Logger.Format.RESET}"

    @staticmethod
    def yellow(text):
        """Formats text as yellow."""
        return f"{Logger.Format.YELLOW}{text}{Logger.Format.RESET}"

    @staticmethod
    def blue(text):
        """Formats text as blue."""
        return f"{Logger.Format.BLUE}{text}{Logger.Format.RESET}"

    @staticmethod
    def magenta(text):
        """Formats text as magenta."""
        return f"{Logger.Format.MAGENTA}{text}{Logger.Format.RESET}"

    @staticmethod
    def cyan(text):
        """Formats text as cyan."""
        return f"{Logger.Format.CYAN}{text}{Logger.Format.RESET}"

    @staticmethod
    def white(text):
        """Formats text as white."""
        return f"{Logger.Format.WHITE}{text}{Logger.Format.RESET}"

    @staticmethod
    def default(text):
        """Formats text as default."""
        return f"{Logger.Format.DEFAULT}{text}{Logger.Format.RESET}"

    @staticmethod
    def bold(text):
        """Formats text as bold."""
        return f"{Logger.Format.BOLD}{text}{Logger.Format.RESET}"

    @staticmethod
    def dim(text):
        """Formats text as dim."""
        return f"{Logger.Format.DIM}{text}{Logger.Format.RESET}"

    @staticmethod
    def italic(text):
        """Formats text as italic."""
        return f"{Logger.Format.ITALIC}{text}{Logger.Format.RESET}"

    @staticmethod
    def underline(text):
        """Formats text as underlined."""
        return f"{Logger.Format.UNDERLINE}{text}{Logger.Format.RESET}"

    @staticmethod
    def strikethrough(text):
        """Formats text as strikethrough."""
        return f"{Logger.Format.STRIKETHROUGH}{text}{Logger.Format.RESET}"

    @staticmethod
    def log(msg):
        """Prints a log message."""
        prefix = Logger.blue("✦ ")
        print(f"{prefix}{msg}")

    @staticmethod
    def info(msg):
        """Prints an informational message."""
        prefix = Logger.cyan("ℹ ")
        print(f"{prefix}{msg}")

    @staticmethod
    def success(msg):
        """Prints a success message."""
        prefix = Logger.green("✔︎ ")
        print(f"{prefix}{msg}")

    @staticmethod
    def warn(msg):
        """Prints a warning message."""
        prefix = Logger.yellow("⚠︎ ")
        print(f"{prefix}{msg}")

    @staticmethod
    def debug(msg):
        """Prints a debug message."""
        prefix = Logger.yellow("⚙︎ debug: ")
        print(f"{prefix}{msg}")

    @staticmethod
    def error(msg):
        """Prints an error message to stderr."""
        prefix = Logger.red("✖︎ error: ")
        print(f"{prefix}{msg}")

    @staticmethod
    def confirm(message, cancel_message="Operation canceled.", default=False):
        prefix = Logger.cyan("? ")
        suffix = " [Y/n]?" if default else " [y/N]?"
        cancel_prefix = Logger.red("✖︎ ")

        def ask():
            try:
                response = input(f"{prefix}{message}{suffix}").lower().strip()
            except (EOFError, KeyboardInterrupt):
                print()
                if cancel_message:
                    print(f"{cancel_prefix}{cancel_message}")
                return False

            if not default and (response == "" or response.startswith("n")):
                if cancel_message:
                    print(f"{cancel_prefix}{cancel_message}")
                return False
            if default and (response == "" or response.startswith("y")):
                return True
            if response in ["y", "yes", "n", "no"]:
                return response.startswith("y")

            Logger.error("Invalid answer. Please enter y, yes, n, or no")
            return ask()

        return ask()
