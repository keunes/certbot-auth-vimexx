"""DNS Authenticator for Vimexx."""
import logging
from typing import Any, Optional, Protocol
from certbot import errors
from certbot.plugins import dns_common
from .vimexx_client import VimexxClient

logger = logging.getLogger(__name__)

logger.debug("New certbot run started with Vimexx authenticator")

# Define credential interface
class CredentialProtocol(Protocol):
    def conf(self, name: str) -> str: ...

class DNSVimexxAuthenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for Vimexx"""
    
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialProtocol] = None

    @classmethod
    def add_parser_arguments(cls, add):
        super().add_parser_arguments(add, default_propagation_seconds=30)
        add("credentials",
            help="Vimexx credentials INI file.")

    def more_info(self) -> str:
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'the WHMCS API for Vimexx.'

    def _setup_credentials(self) -> None:
        """Set up the credentials."""
        credentials_path = self.conf('credentials')
        logger.debug("Starting credentials setup")
        
        # Read raw file with interpolation disabled
        import configparser
        config = configparser.ConfigParser(interpolation=None)
        
        try:
            config.read(credentials_path)
        except configparser.MissingSectionHeaderError:
            logger.debug(f"No section header found in {credentials_path}, adding [default] section")
            with open(credentials_path, 'r') as f:
                config_string = '[default]\n' + f.read()
            config.read_string(config_string)
        
        # Create our own credentials object as certbot's credential interface doesn't handle passwords with special characters well
        class VimexxCredentials:
            def __init__(self, config):
                self.client_id = config['default']['dns_vimexx_client_id']
                self.client_secret = config['default']['dns_vimexx_client_secret']
                self.username = config['default']['dns_vimexx_username']
                self.password = config['default']['dns_vimexx_password']
            
            def conf(self, name):
                """Maintain compatibility with Certbot's credential interface"""
                return getattr(self, name.replace('-', '_'))
        
        self.credentials = VimexxCredentials(config)

    def _perform(self, domain: str, validation_name: str, validation: str) -> None:
        """
        Perform a DNS-01 challenge by creating a TXT record.
        """
        logger.debug(
            f"Starting new DNS challenge\n"
            f"Domain: {domain}\n"
            f"Validation name: {validation_name}\n"
            f"Validation value: {validation}"
        )
        
        self._get_vimexx_client().add_txt_record(
            domain, validation_name, validation)

    def _cleanup(self, domain: str, validation_name: str, validation: str) -> None:
        """
        Clean up the DNS challenge by removing the TXT record.
        """
        logger.info("Starting DNS challenge cleanup")

        self._get_vimexx_client().delete_txt_record(
            domain, validation_name, validation)

    def _get_vimexx_client(self) -> VimexxClient:
        """Get a new Vimexx client."""
        logger.debug("Creating Vimexx client")
        
        if self.credentials is None:
            raise errors.PluginError("Credentials not configured")
        
        # Get credentials
        client_id = self.credentials.conf('client-id')
        client_secret = self.credentials.conf('client-secret')
        username = self.credentials.conf('username')
        password = self.credentials.conf('password')
        
        # Validate credentials are present
        missing = []
        if not client_id: missing.append('client-id')
        if not client_secret: missing.append('client-secret')
        if not username: missing.append('username')
        if not password: missing.append('password')
        
        if missing:
            raise errors.PluginError(f"Missing required credentials: {', '.join(missing)}")
            
        # After validation, we can safely assert these are strings
        assert isinstance(client_id, str)
        assert isinstance(client_secret, str)
        assert isinstance(username, str)
        assert isinstance(password, str)
        
        return VimexxClient(
            client_id=client_id,
            client_secret=client_secret,
            username=username,
            password=password
        )