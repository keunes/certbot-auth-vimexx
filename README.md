# Vimexx DNS authenticator plugin for Certbot

This project is a [Certbot](https://certbot.eff.org/) DNS Authenticator plugin for the Dutch hosting provider Vimexx. It allows users to automatically manage DNS records for domain validation when obtaining SSL certificates.

## Installation

To install the plugin, you can use `pip`. Make sure you have Certbot installed first. Then run:

```bash
pip install certbot-dns-vimexx
```

## Usage

To use the Vimexx DNS Authenticator with Certbot, you can run the `certbot` command with the `--authenticator vimexx` argument:

```bash
certbot --authenticator dns-vimexx --dns-vimexx-credentials /path/to/vimexx.ini -d *.example.com -d example.com
```

This command will create a DNS TXT with the [ACME](https://datatracker.ietf.org/doc/html/rfc8555) challenge provided by Let's Encrypt, attempt to obtain a certificate for .

The plugin requires a configuration file (e.g., `vimexx.ini`) containing your general user credentials and [API client details](https://my.vimexx.nl/api) from Vimexx. Create this file with the following structure:

```ini
dns_vimexx_client_id = your_client_id
dns_vimexx_client_secret = your_client_secret
dns_vimexx_username = your_username
dns_vimexx_password = your_password
```

When running Certbot, specify the path to this configuration file using the `--dns-vimexx-credentials` argument.

For security reasons, make sure that
- the file is owned by the root user or the user running certbot: `chown root:root vimexx.ini`
- only the file owner can read and write the file: `chmod 600 vimexx.ini`

You can also add the argument `--dns-vimexx-propagation-seconds 60` to increase the waiting time for DNS propagation after the DNS record has been created.

After the challenge is completed (or has failed), the created DNS record is removed as well.

> [!NOTE]
> Due to limitations of the Vimexx API, current TTL values for existing DNS records are not returned. Also, the Vimexx API only seems to allow pushing a new set of records, not appending or removing single records. And providing a TTL is mandatory to save the DNS records. Therefore the plugin:
> * retrieves current records - without TTL
> * adds the ACME challenge record to the existing records and pushes it to Vimexx
> * pulls again the then-current records
> * removes the ACME challenge record that was added and pushes back all records - applying a TTL value of 86400 as it doesn't know the TTL value you had originally set
>
> **TL;DR:** When using this plugin all your DNS records will get a TTL of 24 hours.

## Support & contributing

If you encounter issues or have suggestions, please open an issue on the repository. Improvements and fixes are welcome via a pull request.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](./LICENSE) file for details.

## Related Plugins

If you need to use a different DNS service, check out the [Certbot DNS plugins](https://eff-certbot.readthedocs.io/en/latest/using.html#dns-plugins) for other providers.