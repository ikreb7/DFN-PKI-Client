#!/usr/bin/env python

import click

from public_service import PublicServicePKI
from registration_service import RegistrationService
from utils import get_wsdl


@click.command()
@click.version_option()
def main():

    pass


if __name__ == '__main__':
    main()
