import subprocess

from logger import Logger


def copy_to_clipboard(text, description="Text"):
    try:
        subprocess.run(["pbcopy"], input=text.encode(), check=True)
        Logger.success(f"{description} copied to clipboard")
        return True
    except subprocess.CalledProcessError:
        Logger.error(f"Failed to copy {description.lower()} to clipboard")
        return False
