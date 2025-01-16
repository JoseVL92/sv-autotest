#!/usr/bin/env python3

import argparse
import asyncio
import csv
import httpx
import os
import random
import string
from dataclasses import dataclass, asdict
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Tuple

from config import default_environment, logger, ServerData, STAGES
from sv_oidc_auth import OIDCAuth

load_dotenv()


# Default values from environment variables
DEFAULT_REALM = os.getenv('KEYCLOAK_REALM')
DEFAULT_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID')
DEFAULT_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET')


@dataclass
class AccessToken:
    access_token: str
    token_type: str
    expires_in: int
    issue_at: float

    def is_valid(self):
        now = datetime.now().timestamp()
        return now < self.issue_at + self.expires_in

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass
class KcUser:
    id: str
    username: str
    email: str


class KcAdmin:

    def __init__(self, client_id: str, client_secret: str, stage: str = default_environment):
        server_data: ServerData = STAGES.get(stage)
        if server_data is None:
            raise ValueError(f"Stage value '{stage}' is not valid")
        self.stage = stage
        self.base_url = server_data.kc_url
        self.api_url = server_data.api_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._client = httpx.AsyncClient()
        self._client.headers.update({"Content-Type": "application/json"})
        self._get_token()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self._client.aclose()

    async def get_users(self, realm: str, page: int = 0, page_size: int = 100):
        return await self._get(
            f"{self.base_url}/admin/realms/{realm}/users?first={page}&max={page_size}"
        )

    async def get_user(self, realm: str, user_id):
        return await self._get(f"{self.base_url}/admin/realms/{realm}/users/{user_id}")

    async def create_user(self, realm: str, username: str, email: str, password: str, set_free_license: bool) -> bool:
        try:
            response = await self._post(
                f"{self.base_url}/admin/realms/{realm}/users",
                json={
                    "username": username,
                    "email": email,
                    "emailVerified": True,
                    "enabled": True,
                    "credentials": [{
                        "type": "password",
                        "value": password,
                        "temporary": False
                    }]
                }
            )
            logger.info(f"User created successfully: {username}")

            if set_free_license:
                auth = OIDCAuth(self.stage)
                auth_info = await auth.kc_authenticate()
                if auth_info:
                    logger.info(f"=== {username}: Keycloak authentication successful! ===")
                    sv_token = await auth.sv_authenticate(auth_info.get('access_token'))
                    if sv_token:
                        logger.info(f"=== {username}: SV authentication successful! ===")
                        response = await self._client.post(
                            url=f"{self.api_url}/license/select_license",
                            json={
                                "license_id": "portal_lite",
                                "is_yearly": False,
                                "lang": ""
                            },
                            headers={
                                "Authorization": f"Bearer {sv_token}"
                            }
                        )
                        try:
                            response.raise_for_status()
                            logger.info(f"=== {username}: Free license assigned successfully! ===")
                        except httpx.HTTPError as e:
                            logger.error(f"Failed to assign free license to {username}: {str(e)}")
                    else:
                        logger.error(f"=== {username}: SV authentication failed! ===")
                else:
                    logger.error(f"=== {username}: Keycloak authentication failed! ===")

            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to create user {username}: {str(e)}")
            return False

    async def delete_user(self, realm: str, username: str) -> bool:
        try:
            # First, find the user
            users = await self.get_users(realm, page_size=1000)
            user = next((u for u in users if u["username"] == username), None)

            if not user:
                logger.warning(f"User not found: {username}")
                return False

            await self._delete(f"{self.base_url}/admin/realms/{realm}/users/{user['id']}")
            logger.info(f"User deleted successfully: {username}")
            return True
        except httpx.HTTPError as e:
            logger.error(f"Failed to delete user {username}: {str(e)}")
            return False

    def _get_token(self):
        response: httpx.Response = httpx.post(
            f"{self.base_url}/realms/master/protocol/openid-connect/token",
            data={
                "scope": "openid",
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        now = datetime.now().timestamp()
        json_data = response.json()

        token = AccessToken(
            access_token=json_data["access_token"],
            token_type=json_data["token_type"],
            expires_in=json_data["expires_in"],
            issue_at=now,
        )
        self._token = token
        self._client.headers.update(
            {"Authorization": f"{token.token_type} {token.access_token}"}
        )

    async def _get(self, url, as_json=True):
        if not self._token.is_valid():
            self._get_token()

        if as_json:
            result = await self._client.get(url)
            return result.json()

        return await self._client.get(url)

    async def _post(self, url, **kwargs):
        if not self._token.is_valid():
            self._get_token()
        return await self._client.post(url, **kwargs)

    async def _delete(self, url):
        if not self._token.is_valid():
            self._get_token()
        return await self._client.delete(url)


async def process_users(action: str, csv_file: str, realm: str,
                        client_id: str, client_secret: str, set_free_license: bool):
    async with KcAdmin(client_id, client_secret) as admin:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f, delimiter=';')
            users = list(reader)

        results = {
            "success": 0,
            "failed": 0,
            "total": len(users)
        }

        # Process users in parallel with a concurrency limit
        batch_size = 5
        for i in range(0, len(users), batch_size):
            batch = users[i:i + batch_size]
            tasks = []
            for username, password in batch:
                if action == "create":
                    email = f"{username}@example.com"  # Generate email based on username
                    task = admin.create_user(realm, username, email, password, set_free_license)
                else:
                    task = admin.delete_user(realm, username)
                tasks.append(task)

            results_batch = await asyncio.gather(*tasks)
            results["success"] += sum(1 for r in results_batch if r)
            results["failed"] += sum(1 for r in results_batch if not r)

            logger.info(f"Progress: {i + len(batch)}/{len(users)}")

        logger.info(f"Operation completed: {results}")


def generate_users(count: int, prefix: str = "user", password_length: int = 12) -> List[Tuple[str, str]]:
    users = []
    for i in range(1, count + 1):
        username = f"{prefix}{i}"
        password = ''.join(random.choices(
            string.ascii_letters + string.digits,
            k=password_length
        ))
        users.append((username, password))
    return users


def main():
    parser = argparse.ArgumentParser(description="Keycloak User Management CLI")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create users from CSV file")
    create_parser.add_argument("--csv", required=True, help="CSV file with username;password")
    create_parser.add_argument("--realm", default=DEFAULT_REALM, help=f"Keycloak realm")
    create_parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Client ID")
    create_parser.add_argument("--client-secret", default=DEFAULT_CLIENT_SECRET, help="Client Secret")
    create_parser.add_argument("--set-free-license", default=False, help="Automatically set free license")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete users from CSV file")
    delete_parser.add_argument("--csv", required=True, help="CSV file with username;password")
    delete_parser.add_argument("--realm", default=DEFAULT_REALM, help=f"Keycloak realm")
    delete_parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID, help=f"Client ID")
    delete_parser.add_argument("--client-secret", default=DEFAULT_CLIENT_SECRET, help="Client Secret")

    # Generate command
    generate_parser = subparsers.add_parser("generate", help="Generate CSV file with random users")
    generate_parser.add_argument("--count", type=int, required=True, help="Number of users to generate")
    generate_parser.add_argument("--output", required=True, help="Output CSV file")
    generate_parser.add_argument("--prefix", default="user_", help="Username prefix")

    args = parser.parse_args()

    if args.command == "create":
        if not (args.realm and args.client_id and args.client_secret):
            logger.error("Please specify all required params via CLI or environment variable")
            parser.print_help()
            return

        asyncio.run(process_users(
            args.command,
            args.csv,
            args.realm,
            args.client_id,
            args.client_secret,
            args.set_free_license
        ))
    elif args.command == "delete":
        if not (args.realm and args.client_id and args.client_secret):
            logger.error("Please specify all required params via CLI or environment variable")
            parser.print_help()
            return

        asyncio.run(process_users(
            args.command,
            args.csv,
            args.realm,
            args.client_id,
            args.client_secret
        ))
    elif args.command == "generate":
        users = generate_users(args.count, args.prefix)
        with open(args.output, 'w', newline='') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerows(users)
        logger.info(f"Generated {args.count} users in {args.output}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
