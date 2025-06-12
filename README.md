# Vault CLI

A personal command-line password manager built in Python, designed for macOS.

> [!CAUTION]
> 
> **Use at Your Own Risk**: This is an old personal project (2018) that has
> been quickly updated for Python 3 compatibility and basic improvements. While
> the core security model is sound (using macOS encrypted disk images), the code
> has not been thoroughly tested. Please backup any important data and test
> thoroughly before relying on this tool for critical password management.
> Consider using established password managers like 1Password, Bitwarden, or
> similar for production use.

## Features

- Secure encrypted storage using macOS disk images
- Organized password vaults (categories)
- Password generation with clipboard integration
- Browser integration (opens login URLs)
- Session timeout for automatic locking
- Comprehensive CLI with 14 commands

## Quick Start

### 1. Initialize your vault

```sh
python vault.py init
```

This will create an encrypted disk image and prompt for your master password.

### 2. Create your first login

```sh
python vault.py new github
```

### 3. List your logins

```sh
python vault.py list
```

### 4. Open a login (shows details + copies password to clipboard)

```sh
python vault.py open github
```

### 5. Add an alias (Optional)

Add an alias to your shell’s startup file (e.g., `~/.zshrc`, `~/.bash_profile`,
or whichever file your shell uses).

```sh
alias vault="python ~/path/to/vault-cli/src/vault.py"
```

Then you can use `vault` instead of `python vault.py` for all commands.

## Available Commands

- `init` - Initialize vault with encrypted storage
- `new` - Create new login or vault
- `list` - List all vaults or logins in a vault
- `peek` - Display login details
- `open` - Display login details + copy password to clipboard
- `edit` - Edit existing login
- `delete` - Delete login or vault
- `rename` - Rename login or vault
- `move` - Move login between vaults
- `genpass` - Generate secure passwords
- `login` - Open login URL in browser, show username, and copy password
- `config` - View/edit configuration
- `lock`/`unlock` - Lock/unlock vault

## Usage Examples

```sh
# Generate and save a password
vault genpass --save-as stackoverflow

# Create login with generated password
vault new -g reddit

# Create a new vault for work logins
vault new -v work

# Add login to specific vault
vault new --in work slack

# Open URL, show username, and copy password to clipboard
vault login github

# Lock the vault when done
vault lock
```

## Configuration

The vault creates a config file (`vault.cfg`) with these settings:

```ini
[vault]
session_timeout = 900 # 15 minutes in seconds
img_path = /path/to/vault.dmg
mount_path = /Volumes/vault
db_path = /Volumes/vault/vault.db

[genpass]
length = 16
digits = 4
symbols = 4
```

Edit with: `vault config <option> <value>`. For example:

```sh
vault config genpass.length 20
```

## Security

- Uses macOS `hdiutil` for AES-256 encrypted disk images
- Master password required to mount/access data
- Credentials stored in SQLite database within encrypted volume
- Session timeout for automatic locking
- Clipboard integration minimizes password exposure

## Requirements

- macOS (uses hdiutil for disk image encryption)
- Python 3
- Standard library only (no external dependencies)

## Files

- `vault.py` - Main application
- `cli.py` - Argument parser
- `config.py` - Configuration helper
- `logger.py` - Custom logger
- `utils.py` - Utility functions
- `vault.cfg` - Configuration file (auto-generated)
- `vault.dmg` - Encrypted disk image (created on init)
- `vault.txt` - Original documentation with examples

---

*Originally built around 2018 as a learning project and personal tool. Recently
updated for Python 3 compatibility.*
