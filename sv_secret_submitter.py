from dataclasses import dataclass
import os
from pathlib import Path
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from selenium.common.exceptions import TimeoutException
from webdriver_manager.chrome import ChromeDriverManager
from dotenv import load_dotenv
from typing import Optional

from config import default_environment, logger, ServerData, STAGES

load_dotenv()


@dataclass
class SecretSubmission:
    name: str
    type: str
    tag: str
    text: str
    keepic_path: str


class SecretVaultSubmitter:
    def __init__(self, stage: str = default_environment, headless: bool = False):
        server_data: ServerData = STAGES.get(stage)
        if server_data is None:
            raise ValueError(f"Stage value '{stage}' is not valid")
        self.base_url = server_data.portal_url
        self.auth_url = server_data.kc_url
        self.options = Options()
        if headless:
            self.options.add_argument("--headless")
            self.options.add_argument("--no-sandbox")
            self.options.add_argument("--disable-dev-shm-usage")
        self.driver = None
        self.wait = None

    def __enter__(self):
        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=self.options)
        self.wait = WebDriverWait(self.driver, 60)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.driver:
            self.driver.quit()

    def _wait_for_element(self, by: By, value: str) -> Optional[webdriver.Remote]:
        try:
            return self.wait.until(
                EC.presence_of_element_located((by, value))
            )
        except TimeoutException:
            logger.error(f"Timeout waiting for element: {value}")
            return None

    def authenticate(self, username: str = None, password: str = None) -> bool:
        """Handle Keycloak authentication flow."""
        try:
            # Navigate to main application (will redirect to auth)
            self.driver.get(self.base_url)

            # Disable tour using JavaScript
            script = "localStorage.setItem('onboarding', true);"
            self.driver.execute_script(script)

            # Wait for redirect to Keycloak login page
            login_form = self._wait_for_element(By.ID, 'kc-form-login')
            if not login_form:
                return False

            # Get credentials from environment variables if not passed as arguments
            username = username or os.getenv('SV_USERNAME')
            password = password or os.getenv('SV_PASSWORD')

            if not username or not password:
                logger.error("Credentials not found")
                return False

            # Find and fill username field
            username_input = self._wait_for_element(By.ID, 'username')
            if not username_input:
                return False
            username_input.send_keys(username)

            # Find and fill password field
            password_input = self._wait_for_element(By.ID, 'password')
            if not password_input:
                return False
            password_input.send_keys(password)

            # Submit the form
            login_form.submit()

            # Wait for successful authentication and redirect
            # Wait for any element that confirms we're logged in
            success = self._wait_for_element(
                By.CSS_SELECTOR,
                '.tour-home-section'
            )

            if not success:
                logger.error("Failed to verify successful login")
                return False

            logger.info("Successfully authenticated")
            return True

        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            return False

    def submit_secret(self, secret: SecretSubmission) -> bool:
        """Submit a new secret through the web interface."""
        try:
            # Navigate to add secret page
            self.driver.get(f"{self.base_url}/add-secret")

            # Wait for form to load
            form = self._wait_for_element(By.XPATH, '//*[@id="root"]//form')
            if not form:
                return False

            # Fill in form fields
            name_input = self._wait_for_element(By.ID, "input")
            secret_input = self._wait_for_element(By.ID, "textarea")
            keepic_input = self._wait_for_element(By.ID, 'fileInput')
            if not all([name_input, secret_input, keepic_input]):
                logger.error("Failed to find all form elements")
                return False

            # Fill in the form
            name_input.send_keys(secret.name)
            secret_input.send_keys(secret.text)

            # Upload keepic file
            keepic_path = Path(secret.keepic_path)
            if not keepic_path.exists():
                logger.error(f"Keepic file not found: {secret.keepic_path}")
                return False

            keepic_input.send_keys(str(keepic_path.absolute()))

            # Submit the form
            submit_button = self._wait_for_element(
                By.XPATH,
                '/html/body/div[1]/div/div[2]/div/div[2]/div[2]/div/div[2]/div[2]/div[2]/div[3]/button'
            )
            if not submit_button:
                return False
            submit_button.click()
            # self.driver.execute_script("arguments[0].click();", submit_button)

            # Wait for success message or indicator
            success = self._wait_for_element(
                By.CSS_SELECTOR,
                'div.self-end'  # 'Finalize' button
            )
            #
            if not success:
                logger.error("Failed to verify successful secret submission")
                return False

            logger.info(f"Successfully submitted secret: {secret.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to submit secret: {str(e)}")
            return False


def main(stage):
    # Example secret submission
    secret = SecretSubmission(
        name="Test Secret",
        type="text",
        tag="password",
        text="This is a test secret",
        keepic_path="./keepic.jpg"
    )

    with SecretVaultSubmitter(stage=stage, headless=False) as submitter:
        # Authenticate first
        if not submitter.authenticate():
            logger.error("Authentication failed")
            return

        # Submit the secret
        if submitter.submit_secret(secret):
            logger.info("Secret submitted successfully")
        else:
            logger.error("Failed to submit secret")


if __name__ == "__main__":
    stage = 'prod'
    main(stage)
