[![Latest Release](http://img.shields.io/github/release/SDM-TIB/ckanext-iam4nfdi.svg?logo=github)](https://github.com/SDM-TIB/ckanext-iam4nfdi/releases)
[![License: AGPL v3](https://img.shields.io/github/license/SDM-TIB/ckanext-datacomparison?color=blue)](LICENSE.md)

[![CKAN](https://img.shields.io/badge/ckan-2.10-orange.svg?style=flat-square)](https://github.com/ckan/ckan/tree/2.10) [![CKAN](https://img.shields.io/badge/ckan-2.9-orange.svg?style=flat-square)](https://github.com/ckan/ckan/tree/2.9)

# IAM4nfdi

`ckanext-iam4nfdi` is a CKAN extension allowing users to log in through the [IAM4nfdi](https://base4nfdi.de/projects/iam4nfdi) application [RegApp](https://www.nfdi-aai.de/community-aai-software/#regapp) using OpenID Connect.

> [!NOTE]
> The current version of this CKAN extension allows users to select their organizations themselves during the first login.

## Installation

As usual for CKAN extensions, you can install `ckanext-iam4nfdi` as follows:

```bash
git clone git@github.com:SDM-TIB/ckanext-iam4nfdi.git
pip install -e ./ckanext-iam4nfdi
pip install -r ./ckanext-iam4nfdi/requirements.txt
```

Then add `iam4nfdi` to the plugins in your `ckan.ini`.

## Configuration Options

`ckanext-iam4nfdi` requires a client ID and client secret to be set via environment variables.

- `CKANEXT__IAM4NFDI__CLIENT_ID`
- `CKANEXT__IAM4NFDI__CLIENT_SECRET`

## Changelog

If you are interested in what has changed, check out the [changelog](CHANGELOG.md).

## License

`ckanext-iam4nfdi` is licensed under AGPL-3.0, see the [license file](LICENSE).
