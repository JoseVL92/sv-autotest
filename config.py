import logging
import sys
from dataclasses import dataclass

# Logging config
logging_file = 'sv-test-scripts.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(module)s - %(message)s',
    handlers=[
        logging.FileHandler(logging_file),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("sv-test-scripts")


# Servers URL definition
@dataclass
class ServerData:
    portal_url: str
    api_url: str
    kc_url: str
    realm: str
    client_id: str


DOMAIN_TEMPLATE = "https://{}.secretsvault.net"

STAGES = {
    'dev': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('sv-dev'),
        api_url=DOMAIN_TEMPLATE.format('wapi-dev'),
        kc_url=DOMAIN_TEMPLATE.format('auth-dev'),
        realm='secret-vault',
        client_id='sv-web-portal'
    ),
    'test': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('sv-test'),
        api_url=DOMAIN_TEMPLATE.format('wapi-test'),
        kc_url=DOMAIN_TEMPLATE.format('auth-test'),
        realm='secret-vault',
        client_id='sv-web-portal'
    ),
    'prod': ServerData(
        portal_url=DOMAIN_TEMPLATE.format('app-pre'),
        api_url=DOMAIN_TEMPLATE.format('wapi-pre'),
        kc_url=DOMAIN_TEMPLATE.format('auth-pre'),
        realm='secrets-vault',
        client_id='sv-web-portal'
    )
}

default_environment = 'dev'
