#!/usr/bin/python
#
# Command line utility to generate and manage passwords
#
# help:
#   vault -h
#
# To do:
#   - Rewrite consistent helps

from cli import parser
import sys
import os
import ConfigParser
import sqlite3
import subprocess
import string
import random
import webbrowser

class Vault:

    cmd_path = os.path.dirname(os.path.realpath(__file__))
    img_path = os.path.abspath(cmd_path + '/vault.dmg')
    mount_path = os.path.abspath('/Volumes/vault')
    db_path = os.path.abspath('/Volumes/vault/vault.db')
    config_path = os.path.abspath(cmd_path + '/vault.cfg')
    yes_no_answers = ['y', 'yes', 'n', 'no']


    @staticmethod
    def config(args, parser):

        # args = Namespace(
        #     command='config',
        #     get=False,
        #     list=False,
        #     option_string='test',
        #     value=None)

        config = ConfigParser.SafeConfigParser()
        config.read(Vault.config_path)

        if (args.list):
            for section_name in config.sections():
                print(section_name)
                if section_name == 'core':
                    for name, value in config.items(section_name):
                        print('     %s = %s' % (name, value))
                else:
                    for name, value in config.items(section_name):
                        print('     %s.%s = %s' % (section_name, name, value))
            sys.exit()

        if (args.option_string is None):
            parser.print_help()
            sys.exit()

        # turn 'section.key' to ['section', 'key']
        option_list = args.option_string.split('.')

        # If there was no section provided, set the section to 'core'
        if (len(option_list) == 1):
            option_list = ['core'] + option_list

        (section, option) = option_list

        if (not config.has_option(section, option)):
            print('No %s.%s option found in configs.' % (section, option))
            sys.exit(2)

        if (args.get or args.value is None):
            value = config.get(section, option)
            print(value)
            sys.exit()

        config.set(section, option, args.value)

        with open(Vault.config_path, 'wb') as config_file:
            config.write(config_file)


    @staticmethod
    def delete(args, parser):

        # args = Namespace(
        #     command='delete',
        #     mode='login',
        #     name='test',
        #     src_vault='_main')

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        if args.mode == 'vault':

            t = tuple([args.name])
            vault_exists = c.execute('SELECT name FROM vaults WHERE name LIKE ?', t).fetchone()
            
            if not vault_exists:
                conn.close()
                print("Vault '%s' does not exist." % args.name)
                sys.exit(2)

            c.execute('DELETE FROM vaults WHERE name LIKE ?', t)
            conn.commit()
            conn.close()
            print("Deleted vault '%s'." % args.name)
            sys.exit()

        vault_exists = c.execute('SELECT name FROM vaults WHERE name LIKE ?', tuple([args.src_vault])).fetchone()
            
        if not vault_exists:
            conn.close()
            print("Vault '%s' does not exist." % args.src_vault)
            sys.exit(2)

        t = (args.name, args.src_vault)
        login_exists = c.execute('SELECT name FROM logins WHERE name LIKE ? AND vault LIKE ?', t).fetchone()

        if not login_exists:
            conn.close()
            print("Login '%s' does not exist in vault '%s'." % t)

        c.execute('DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?', t)
        conn.commit()
        conn.close()
        print("Deleted login '%s' in vault '%s'." % t)


    @staticmethod
    def edit(args, parser):

        # args = Namespace(
        #     command='edit',
        #     email=None,
        #     name='test',
        #     notes=None,
        #     password=None,
        #     src_vault='_main',
        #     url=None,
        #     username=None)

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.src_vault])).fetchone()

        if not vault_exists:
            conn.close()
            print("Vault '%s' does not exist." % args.src_vault)
            sys.exit(2)

        login =  c.execute("SELECT * FROM logins WHERE name LIKE ? AND vault LIKE ?", (args.name, args.src_vault)).fetchone()

        if not login:
            conn.close()
            print("Login '%s' does not exist in vault '%s'." % (args.name, args.src_vault))
            sys.exit(2)

        edited_login = [args.name]

        if args.username or args.password or args.email or args.url or args.notes:
            edited_login.extend([
                args.username or login[1],
                args.password or login[2],
                args.email or login[3],
                args.url or login[4],
                args.notes or login[5],
            ])

        else:

            edited_login.extend([
                raw_input('[1/4] Username [%s]: ' % login[1]) or login[1],
                raw_input('[2/4] Password [%s]: ' % login[2]) or login[2],
                raw_input('[3/4] Email [%s]: ' % login[3]) or login[3],
                raw_input('[4/4] URL [%s]: ' % login[4]) or login[4],
                login[5],
            ])

        edited_login.append(login[6])

        c.execute('DELETE FROM logins WHERE name LIKE ?', tuple([args.name]))
        c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(edited_login))

        print("Edited login '%s' in vault '%s'" % (args.name, args.src_vault))

        conn.commit()
        conn.close()


    @staticmethod
    def genpass(args=None, parser=None):

        # args = Namespace(
        #     command='genpass',
        #     login=None,
        #     digits=None,
        #     length=None,
        #     force=False,
        #     symbols=None,
        #     vault='_main')

        config = ConfigParser.SafeConfigParser()
        config.read(Vault.config_path)

        letters = string.ascii_letters
        digits = string.digits
        symbols = string.punctuation

        if args:
            length = args.length or config.get('genpass', 'length')
            digits_count = args.digits or config.get('genpass', 'digits')
            symbols_count = args.symbols or config.get('genpass', 'symbols')
            length = int(length)
            digits_count = int(digits_count)
            symbols_count = int(symbols_count)
        else:
            length = int(config.get('genpass', 'length'))
            digits_count = int(config.get('genpass', 'digits'))
            symbols_count = int(config.get('genpass', 'symbols'))


        letters_count = length - digits_count - symbols_count

        if letters_count < 0:
            symbols_count -= digits_count + symbols_count - length
            letters_count = 0

        # create a string with 4 random letters, 4 random numbers, and 2 random punctuation
        password =  ''.join(random.sample(letters, letters_count)) + ''.join(random.sample(digits, digits_count)) + ''.join(random.sample(symbols, symbols_count))

        # randomly mix the characters to form the password
        password = ''.join(random.sample(password, length))

        if not args:
            return password

        if args.login:
            conn = sqlite3.connect(Vault.db_path)
            c = conn.cursor()

            login_exists = c.execute('SELECT name FROM logins WHERE name LIKE ? AND vault LIKE ?', (args.login, args.vault)).fetchone()

            if login_exists and not args.force:
                def overwrite_prompt():
                    overwrite = raw_input("Edit password for existing login '%s' in vault '%s' [y/N]?" % (args.login, args.vault)).lower()
                    if overwrite == 'n' or overwrite == 'no' or overwrite == '':
                        print('Save canceled.')
                        return
                    if overwrite not in Vault.yes_no_answers:
                        print('Invalid answer. Please enter y, yes, n, or no')
                        overwrite_prompt()
                    else:
                        c.execute('UPDATE logins SET password LIKE ? WHERE name LIKE ? AND vault LIKE ?', (password, args.login, args.vault))
                        print("Edited password for login '%s' in vault '%s'" % (args.login, args.vault))
                        conn.commit()
                        conn.close()

                overwrite_prompt()

            elif login_exists and args.force:
                c.execute('UPDATE logins SET password LIKE ? WHERE name LIKE ? AND vault LIKE ?', (password, args.login, args.vault))
                print("Edited password for login '%s' in vault '%s'" % (args.login, args.vault))
                conn.commit()
                conn.close()

            else:
                login = (
                    args.login,
                    raw_input('[1/3] Username: '),
                    password,
                    raw_input('[2/3] Email: '),
                    raw_input('[3/3] URL: '),
                    '',
                    args.vault
                )
                c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", login)
                print("Saved new login '%s' in vault '%s'" % (args.login, args.vault))
                conn.commit()
                conn.close()
        

        print('Password: ' + password)


    @staticmethod
    def init(args, parser):

        # args = Namespace(
        #     command='init',
        #     vaults=None)

        img_exists = os.path.isfile(Vault.img_path)

        if not img_exists:
            subprocess.call("hdiutil create -type UDIF -fs 'Journaled HFS+' -size 100m -volname 'vault' -encryption AES-256 -attach " + Vault.img_path, shell=True)

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='vaults' ")
        vaults_exist = c.fetchone()

        if (vaults_exist):
            print('vault has already been initiated.')
            sys.exit(2)

        c.execute("CREATE TABLE vaults(name text)")
        c.execute("INSERT INTO vaults VALUES ('_main')")
        c.execute('''CREATE TABLE logins(
            name text,
            username text,
            password text,
            email text,
            url text,
            notes text,
            vault text)''')

        if args.vaults:
            for vault in args.vaults:
                c.execute('''INSERT INTO vaults VALUES (?)''', tuple([vault]))

        conn.commit()
        conn.close()


    @staticmethod
    def list(args, parser):

        # args = Namespace(
        #     command='list',
        #     src_vault=None)

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        if args.src_vault:

            t = tuple([args.src_vault])
            vault_exists = c.execute('SELECT name FROM vaults WHERE name LIKE ?', t).fetchone()

            if not vault_exists:
                conn.close()
                print("Vault '%s' does not exist." % args.src_vault)
                sys.exit(2)

            for login in c.execute('SELECT name FROM logins WHERE vault LIKE ? ORDER BY LOWER(name)', t):
                print(login[0])
            sys.exit()

        vaults = c.execute('SELECT name FROM vaults ORDER BY LOWER(name)').fetchall()

        for vault in vaults:
            login_count = len(c.execute('SELECT name FROM logins WHERE vault LIKE ?', tuple([vault[0]])).fetchall())
            print('%s (%i)' % (vault[0], login_count))


    @staticmethod
    def lock(args, parser):

        unlocked = os.path.ismount(Vault.mount_path)
        if not unlocked:
            print('Vaults are already locked.')
        else:
            subprocess.call('umount ' + Vault.mount_path, shell=True)
            print('Locked vaults.')


    # needs work
    @staticmethod
    def login(args, parser):

        # args = Namespace(
        #     command='login',
        #     login_name='test',
        #     src_vault='_main')

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        src_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.src_vault])).fetchone()

        if not src_exists:
            conn.close()
            print("Source vault '%s' does not exist." % args.src_vault)
            sys.exit(2)

        t = (args.login_name, args.src_vault)
        login = c.execute('SELECT username, password, url FROM logins WHERE name LIKE ? AND vault LIKE ?', t).fetchone()

        if not login:
            conn.close()
            print("Login '%s' does not exist in vault '%s'." % t)
            sys.exit(2)

        conn.close()
        print('Username: ' + login[0])
        print('Password: ' + login[1])
        webbrowser.open(login[2])


    @staticmethod
    def move(args, parser):

        # args = Namespace(
        #     command='move',
        #     dest_vault='test',
        #     force=False,
        #     name='test',
        #     src_vault='test')

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        src_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.src_vault])).fetchone()

        if not src_exists:
            conn.close()
            print("Source vault '%s' does not exist." % args.src_vault)
            sys.exit(2)

        dest_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.dest_vault])).fetchone()

        if not dest_exists:
            conn.close()
            print("Destination vault '%s' does not exist." % args.dest_vault)
            sys.exit(2)

        login_exists = c.execute('SELECT name FROM logins WHERE name LIKE ? AND vault LIKE ?', (args.name, args.src_vault)).fetchone()
        
        if not login_exists:
            conn.close()
            print("Login '%s' does not exist." % args.name)
            sys.exit(2)

        t = (args.name, args.dest_vault)
        dest_login_exists = c.execute('SELECT name FROM logins WHERE name LIKE ? AND vault LIKE ?', t).fetchone()

        if dest_login_exists and not args.force:

            def overwrite_prompt():
                overwrite = raw_input("Overwrite existing login '%s' in vault '%s' [y/N]?" % t).lower()
                if overwrite == 'n' or overwrite == 'no' or overwrite == '':
                    print('Move canceled.')
                    sys.exit()
                if overwrite not in Vault.yes_no_answers:
                    print('Invalid answer. Please enter y, yes, n, or no')
                    overwrite_prompt()
                else:
                    c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
                    print("Deleted login '%s' in vault '%s'" % t)

            overwrite_prompt()

        elif dest_login_exists and args.force:
            c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
            print("Deleted login '%s' in vault '%s'" % t)

        c.execute("UPDATE logins SET vault LIKE ? WHERE name LIKE ? AND vault LIKE ?", (args.dest_vault, args.name, args.src_vault))
        conn.commit()
        conn.close()
        print("Moved login '%s' from vault '%s' to vault '%s'." % (args.name, args.src_vault, args.dest_vault))
        sys.exit()


    @staticmethod
    def new(args, parser):

        # args = Namespace(
        #     command='new',
        #     dest_vault='_main',
        #     force=False,
        #     genpass=False,
        #     mode='login',
        #     name='test',
        #     notes='')

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        if args.mode == 'vault':

            t = tuple([args.name])
            vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", t).fetchone()

            if vault_exists:
                conn.close()
                print("Vault '%s' already exists." % args.name)
                sys.exit(2)
        
            c.execute("INSERT INTO vaults VALUES (?)", t)
            conn.commit()
            conn.close()
            print("Created new vault '%s'." % args.name)
            sys.exit()

        action = ['Saved new']

        t = tuple([args.dest_vault])
        vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", t).fetchone()


        if not vault_exists:

            def create_prompt():
                create = raw_input('''Vault '%s' does not exist. Do you want to create it [y/N]?''' % args.dest_vault).lower()
                if create == 'n' or create == 'no' or create == '':
                    print('New login canceled.')
                    sys.exit()
                if create not in Vault.yes_no_answers:
                    print('Invalid answer. Please enter y, yes, n, or no')
                    create_prompt()
                else:
                    c.execute("INSERT INTO vaults VALUES (?)", t)
                    conn.commit()
                    print("Created new vault '%s'." % args.dest_vault)

            create_prompt()

        t = (args.name, args.dest_vault)
        login_exists = c.execute("SELECT name, vault FROM logins WHERE name LIKE ? AND vault LIKE ?", t).fetchone()

        if login_exists and not args.force:

            def overwrite_prompt():
                overwrite = raw_input("Overwrite existing login '%s' in vault '%s' [y/N]?" % (args.name, args.dest_vault)).lower()
                if overwrite == 'n' or overwrite == 'no' or overwrite == '':
                    print('New login canceled.')
                    sys.exit()
                if overwrite not in Vault.yes_no_answers:
                    print('Invalid answer. Please enter y, yes, n, or no')
                    overwrite_prompt()
                else:
                    c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
                    action[0] = 'Overwrote'

            overwrite_prompt()

        elif login_exists and args.force:
            c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
            action[0] = 'Overwrote'

        questions_length = 3 if args.genpass else 4
        question_index = [1]

        def increment_question():
            question_index[0] += 1
            return question_index[0]

        login = [
            args.name,
            raw_input('[1/%i] Username: ' % questions_length)
        ]

        if args.genpass:
            login.append(Vault.genpass())
        else:
            login.append(raw_input('[%i/%i] Password: ' % (increment_question(), questions_length)))

        login.extend([
            raw_input('[%i/%i] Email: ' % (increment_question(), questions_length)),
            raw_input('[%i/%i] URL: ' % (increment_question(), questions_length)),
            args.notes,
            args.dest_vault
        ])

        c.execute("INSERT INTO logins VALUES (?, ?, ?, ?, ?, ?, ?)", tuple(login))
        print("%s login '%s' in vault '%s'" % (action[0], args.name, args.dest_vault))
        if args.genpass:
            print('Password: ' + login[2])

        conn.commit()
        conn.close()


    @staticmethod
    def open(args, parser):

        # args = Namespace(
        #     command='open',
        #     name='test',
        #     src_vault='_main')


        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.src_vault])).fetchone()

        if not vault_exists:
            conn.close()
            print("Vault '%s' does not exist." % args.src_vault)
            sys.exit(2)

        login = c.execute("SELECT * FROM logins WHERE name LIKE ? AND vault LIKE ?", (args.name, args.src_vault)).fetchone()
        columns = c.execute('PRAGMA table_info(logins)').fetchall()

        if not login:
            conn.close()
            print("Login '%s' does not exist in vault '%s'." % (args.name, args.src_vault))
            sys.exit(2)

        for i, col in enumerate(login):
            print('%s: %s' % (columns[i][1], col))


    @staticmethod
    def rename(args, parser):

        # args = Namespace(command='rename',
        #     force=False,
        #     mode='login',
        #     new_name='test',
        #     old_name='test',
        #     src_vault='_main')

        conn = sqlite3.connect(Vault.db_path)
        c = conn.cursor()

        if args.mode == 'vault':

            vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.old_name])).fetchone()

            if not vault_exists:
                conn.close()
                print("Vault '%s' does not exists." % args.old_name)
                sys.exit(2)

            t = tuple([args.new_name])
            new_vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", t).fetchone()

            if new_vault_exists and not args.force:

                def overwrite_prompt():
                    overwrite = raw_input("Overwrite existing vault '%s' [y/N]?" % args.new_name).lower()
                    if overwrite == 'n' or overwrite == 'no' or overwrite == '':
                        print('Vault rename canceled.')
                        sys.exit()
                    if overwrite not in Vault.yes_no_answers:
                        print('Invalid answer. Please enter y, yes, n, or no')
                        overwrite_prompt()
                    else:
                        c.execute("DELETE FROM vaults WHERE name LIKE ?", t)
                        c.execute("DELETE FROM logins WHERE vault LIKE ?", t)
                        print("Deleted vault '%s'." % args.new_name)

                overwrite_prompt()

            elif new_vault_exists and args.force:
                c.execute("DELETE FROM vaults WHERE name LIKE ?", t)
                c.execute("DELETE FROM logins WHERE vault LIKE ?", t)
                print("Deleted vault '%s'." % args.new_name)
        
            t = (args.new_name, args.old_name)
            c.execute("UPDATE vaults SET name LIKE ? WHERE name LIKE ?", t)
            c.execute("UPDATE logins SET vault LIKE ? WHERE vault LIKE ?", t)
            conn.commit()
            conn.close()
            print("Renamed vault '%s' to '%s'." % (args.old_name, args.new_name))
            sys.exit()

        else:
            vault_exists = c.execute("SELECT name FROM vaults WHERE name LIKE ?", tuple([args.src_vault])).fetchone()

            if not vault_exists:
                conn.close()
                print("Vault '%s' does not exist." % args.src_vault)
                sys.exit(2)

            t = (args.new_name, args.src_vault)
            new_login_exists = c.execute("SELECT name FROM logins WHERE name LIKE ? AND vault LIKE ?", t).fetchone()

            if new_login_exists and not args.force:

                def overwrite_prompt():
                    overwrite = raw_input("Overwrite existing login '%s' [y/N]?" % args.new_name).lower()
                    if overwrite == 'n' or overwrite == 'no' or overwrite == '':
                        print('Login rename canceled.')
                        sys.exit()
                    if overwrite not in Vault.yes_no_answers:
                        print('Invalid answer. Please enter y, yes, n, or no')
                        overwrite_prompt()
                    else:
                        c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
                        print("Deleted login '%s' in vault '%s'." % t)

                overwrite_prompt()

            elif new_login_exists and args.force:
                c.execute("DELETE FROM logins WHERE name LIKE ? AND vault LIKE ?", t)
                print("Deleted login '%s' in vault '%s'." % t)

            c.execute("UPDATE logins SET name LIKE ? WHERE name LIKE ? AND vault LIKE ?", (args.new_name, args.old_name, args.src_vault))

            conn.commit()
            conn.close()
            print("Renamed login '%s' to '%s' in vault '%s'." % (args.old_name, args.new_name, args.src_vault))
            sys.exit()


    @staticmethod
    def unlock(args, parser):

        unlock = subprocess.call('hdiutil attach ' + Vault.img_path, shell=True)
        if unlock == 0:
            print('Unlocked vaults.')


args = parser.parse_args()
unlocked = os.path.ismount(Vault.mount_path)
dmgExists = os.path.isfile(Vault.img_path)
if not unlocked and args.command != 'unlock' and dmgExists:
    print('Vaults are locked. To unlock them, use vault unlock.')
    sys.exit(2)
fn = getattr(Vault, args.command)
fn(args, parser)