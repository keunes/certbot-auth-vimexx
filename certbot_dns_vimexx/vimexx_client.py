import requests
import logging
from typing import Dict, Optional, Any
from urllib.parse import quote, quote_plus
import tldextract
from certbot import errors

logger = logging.getLogger(__name__)

class VimexxClient:
    """Client for the Vimexx API."""

    DEFAULT_TTL = "86400"  # TTL for DNS records, because Vimexx API doesn't tell us the current values
                           #TODO: Make this configurable
    CHALLENGE_TTL = "60"
    WHMCS_VERSION = "8.6.1-release.1" # Valid WHMCS version number required for Vimexx API calls
    BASE_URL = "https://api.vimexx.nl"
    API_PATH = "/api/v1"

    def __init__(self, client_id: str, client_secret: str, username: str, password: str):
        """Initialize the Vimexx API client.
        
        Args:
            client_id: The OAuth2 client ID from Vimexx
            client_secret: The OAuth2 client secret from Vimexx
            username: Your Vimexx account username
            password: Your Vimexx account password
        """
        logger.debug(f"Initializing VimexxClient with username {username}")
        
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None

    def _extract_domain_parts(self, domain: str) -> tuple[str, str]:
        """Extract SLD and TLD using Public Suffix List.
        """
        extracted = tldextract.extract(domain.lstrip('*.'))
        
        if not extracted.domain or not extracted.suffix:
            raise errors.PluginError(f"Cannot parse domain: {domain}")
        
        return extracted.domain, extracted.suffix

    def authenticate(self) -> Dict[str, str]:
        """Authenticate with the Vimexx API using OAuth2."""

        logger.debug("Initiating authentication process")
        auth_url = f"{self.BASE_URL}/auth/token"
        headers_script = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        payload_script = '&'.join([
            'grant_type=password',
            f'client_id={quote(self.client_id)}',
            f'client_secret={quote(self.client_secret)}',
            f'username={quote(self.username)}',
            f'password={quote_plus(self.password)}',
            'scope=whmcs-access'
        ])

        import requests

        response = requests.request("POST", auth_url, headers=headers_script, data=payload_script)

        if response.status_code != 200:
            logger.error(f"Authentication failed with status code {response.status_code}")
            logger.debug(f"Response body: {response.text}")
            response.raise_for_status()
        
        logger.debug(f"Authentication successful with code {response.status_code}")
        try:
            token_data = response.json()
            logger.debug("Successfully parsed JSON response")
            
            if "access_token" not in token_data:
                logger.debug(f"No access token in response: {token_data}")
                raise errors.PluginError("No access token in response")
            
            self.access_token = token_data["access_token"]
            logger.debug("Successfully obtained access token")
            return token_data
            
        except ValueError as e:
            logger.error(f"Failed to parse response: {str(e)}")
            logger.debug(f"Raw response: {response.text}")
            raise errors.PluginError(f"Failed to parse authentication response: {str(e)}")

    def api_request(self, endpoint: str, method: str = 'GET', body: Optional[Dict] = None) -> Dict[str, Any]:
        """Make an authenticated API request."""
        logger.debug("Check if access token is set")
        if not self.access_token:
            logger.info("Access token not set, authenticating...")
            self.authenticate()
            logger.debug("Access token set successfully")

        logger.debug("=== Making API Request ===")
        headers = {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json"
        }
        logger.debug(f"Headers: {headers}")

        url = f"{self.BASE_URL}{self.API_PATH}{endpoint}"
        logger.debug(f"URL: {url}")

        data = {
            "body": body,
            "version": self.WHMCS_VERSION
        }
        logger.debug(f"Data: {data}")
        
        logger.debug(f"Method: {method}")

        response = requests.request(
            method=method.upper(),
            url=url,
            headers=headers,
            json=data if method.upper() in ["POST", "PUT", "PATCH"] else None,
            params=data if method.upper() == "GET" else None
        )
        
        logger.debug(
            f"Response Status: {response.status_code}"
            f"Response Headers: {dict(response.headers)}"
            f"Response Body: {response.text}")

        response.raise_for_status()
        return response.json()

    def add_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """Add a TXT record for DNS-01 challenge.
        
        Due to Vimexx API limitations, this retrieves all existing records,
        adds the challenge record, and pushes the complete set back.
        
        Args:
            domain: The domain name (e.g., 'example.com')
            record_name: Full record name (e.g., '_acme-challenge.example.com')
            record_content: The challenge token value
            
        Raises:
            PluginError: If DNS operation fails
        """
        
        logger.info(
            f"Adding TXT record for domain {domain}\n"
            f"- Name: {record_name}\n"
            f"- Content: {record_content}")
        
        sld, tld = self._extract_domain_parts(domain)
        
        # Get current records
        logger.debug("Fetching current DNS records...")
        response = self.api_request('/whmcs/domain/dns', 'POST', {"sld": sld, "tld": tld})
        current_records = response.get('data', {}).get('dns_records', [])
        logger.debug(f"Found {len(current_records)} existing records")
        
        # Ensure all existing records have TTL
        updated_records = []
        for record in current_records:
            record_copy = record.copy()
            if 'ttl' not in record_copy:
                record_copy['ttl'] = self.DEFAULT_TTL
            updated_records.append(record_copy)
        
        # Add new TXT record
        new_record = {
            "name": record_name,
            "type": "TXT",
            "content": record_content,
            "ttl": "60"
        }
        updated_records.append(new_record)
        logger.debug("New TXT record added")
        
        # Update records
        logging.debug(f"Updating DNS records (total: {len(updated_records)})...")
        try:
            self.api_request('/whmcs/domain/dns', 'PUT', {
                "sld": sld,
                "tld": tld,
                "dns_records": updated_records
            })
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to add DNS record: {e}")
            raise errors.PluginError(f"DNS record creation failed: {e}")
        except Exception as e:
            logger.error(f"Unexpected error adding DNS record: {e}")
            raise errors.PluginError(f"DNS operation failed: {e}")
        logging.info("TXT record added successfully")
        
    def delete_txt_record(self, domain: str, record_name: str, record_content: str) -> None:
        """Delete a TXT record from domain."""
        
        sld, tld = self._extract_domain_parts(domain)
        
        # Get current records
        logging.debug("Fetching current DNS records...")
        response = self.api_request('/whmcs/domain/dns', 'POST', {"sld": sld, "tld": tld})
        current_records = response.get('data', {}).get('dns_records', [])
        logging.debug(f"Found {len(current_records)} existing records")

        # Filter out the ACME challenge record
        logging.debug(f"Filtering for TXT records with name '{record_name}' and content '{record_content}'")
        updated_records = []
        for record in current_records:
            record_type = record.get('type')
            record_name_api = record.get('name', '').rstrip('.')
            record_content_api = record.get('content', '').strip('"')

            if (record_name_api == record_name and 
                record_type == 'TXT' and 
                record_content_api == record_content):
                logging.debug(f"Found matching record to remove")
                continue
                
            updated_records.append(record)
        logging.debug(f"Updated records count after filtering: {len(updated_records)}")
        
        # Update records with TTL
        for record in updated_records:
            record['ttl'] = '86400'

        # Update records
        self.api_request('/whmcs/domain/dns', 'PUT', {
            "sld": sld,
            "tld": tld,
            "dns_records": updated_records
        })
        
        logger.info("TXT record deleted successfully")