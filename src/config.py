import configparser
import os

from logger import Logger


class VaultConfig:
    def __init__(self, config_path):
        self.config_path = config_path
        self._config = configparser.ConfigParser()
        if not os.path.isfile(self.config_path):
            self._create_default_config()
        self._config.read(self.config_path)

    def _create_default_config(self):
        cmd_path = os.path.dirname(os.path.realpath(__file__))

        self._config["vault"] = {
            "session_timeout": "900 # 15 mins in seconds",
            "img_path": os.path.abspath(f"{cmd_path}/vault.dmg"),
            "mount_path": "/Volumes/vault",
            "db_path": "/Volumes/vault/vault.db",
        }
        self._config["genpass"] = {"length": "16", "digits": "4", "symbols": "4"}

        self.save()
        Logger.success(f"Created default config file at {self.config_path}")

    @property
    def session_timeout(self):
        return int(self.get("vault", "session_timeout"))

    @property
    def img_path(self):
        return self.get("vault", "img_path")

    @property
    def mount_path(self):
        return self.get("vault", "mount_path")

    @property
    def db_path(self):
        return self.get("vault", "db_path")

    @property
    def genpass_length(self):
        return int(self.get("genpass", "length"))

    @property
    def genpass_digits(self):
        return int(self.get("genpass", "digits"))

    @property
    def genpass_symbols(self):
        return int(self.get("genpass", "symbols"))

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
