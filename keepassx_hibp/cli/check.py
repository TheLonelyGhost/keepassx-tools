import os
import sys

from .. import __version__

import click
from pykeepass import PyKeePass
from pwnedapi import Password


def current_entry(entry):
    if entry is not None:
        return '{path} ({username})'.format(path=entry.path, username=entry.username)


@click.command()
@click.argument('db_path')
@click.password_option('--password')
@click.version_option(version=__version__)
@click.help_option()
def main(db_path, password):
    click.echo('Decrypting database (this may take a while) ... ', nl=False)
    db = PyKeePass(os.path.expanduser(db_path), password=password)
    click.echo('Decrypted!')

    # Password hash => pwned counts (so we don't have to make numerous duplicate requests)
    pwds = {}
    failed = []

    click.echo('Checking for pwned passwords...')
    with click.progressbar(db.entries, show_percent=False, show_pos=True, show_eta=False, item_show_func=current_entry) as entries:
        for entry in entries:
            if not entry.password:
                continue

            pwd = Password(entry.password)

            if pwd.hashed_password not in pwds:
                pwd.is_pwned()  # Loads the cache for `pwd.pwned_count`
                pwds[pwd.hashed_password] = pwd.pwned_count

            pwned_count = pwds[pwd.hashed_password]

            if pwned_count == 0:
                continue

            failed.append(entry)

    failures = len(failed)

    for entry in failed:
        click.echo('{level}: {e}'.format(level=click.style('FAIL', fg='red'), e=current_entry(entry)))

    click.echo('Insecure passwords: {num} found'.format(
        num=click.style(
            str(failures), fg='bright_red' if failures > 0 else 'green')))

    if failures > 0:
        sys.exit(1)
