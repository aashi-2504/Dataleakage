import os
import asyncio
import logging
from datetime import datetime
from spidering import spider_targets, run_custom_checks
from data_leakage import test_data_leakage  # Importing the data leakage module
from reports import generate_html_report, generate_csv_report, generate_json_report, display_reports_folder

# Setup logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler("app.log"),  # Changed log file name
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def is_valid_url(url):
    """Validate the provided URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)

def create_reports_folder():
    """Create a folder for the reports based on the current timestamp."""
    folder_name = datetime.now().strftime("%d%b%y%H%M%S")  # Format: ddMonyyhhmmss
    reports_dir = os.path.join("reports", folder_name)
    os.makedirs(reports_dir, exist_ok=True)
    return reports_dir

async def main():
    """
    Main function to run custom checks asynchronously for user-provided targets.
    """
    try:
        # Input and validation for target
        target = input("Enter the URL or IP for scanning: ").strip()
        if not is_valid_url(target):
            logger.error("Invalid URL. Please enter a valid target.")
            return

        # Authorization setup
        auth = None
        auth_required = input("Does the target require authorization (yes/no)? ").strip().lower()
        if auth_required == 'yes':
            auth_type = input("Enter authorization type (bearer/basic): ").strip().lower()
            if auth_type == 'bearer':
                token = input("Enter the Bearer token: ").strip()
                if not token:
                    logger.error("Bearer token cannot be empty.")
                    return
                auth = {"type": "bearer", "token": token}
            elif auth_type == 'basic':
                username = input("Enter the username: ").strip()
                password = input("Enter the password: ").strip()
                if not username or not password:
                    logger.error("Username and password cannot be empty for Basic auth.")
                    return
                auth = {"type": "basic", "username": username, "password": password}
            else:
                logger.error("Invalid authorization type. Please enter 'bearer' or 'basic'.")
                return

        # Spidering: Discover endpoints
        logger.info("Starting spidering to discover endpoints...")
        discovered_endpoints = await spider_targets(target)
        if not discovered_endpoints:
            logger.error("No endpoints discovered during spidering.")
            return

        logger.info(f"Spidering completed. {len(discovered_endpoints)} endpoints discovered.")
        logger.debug(f"Discovered endpoints: {discovered_endpoints}")

        # Save discovered endpoints to a file
        reports_dir = create_reports_folder()  # Create reports folder with timestamp
        endpoints_file = os.path.join(reports_dir, "discovered_endpoints.txt")
        with open(endpoints_file, 'w') as f:
            f.write("\n".join(discovered_endpoints))
        logger.info(f"Discovered endpoints saved to {endpoints_file}.")

        # Prepare target information
        target_info = {"target": target, "auth": auth}

        # Run custom checks
        logger.info(f"Starting the security scanning process for target: {target}")
        await run_custom_checks(target_info, discovered_endpoints)

        # Data leakage checks
        logger.info("Running data leakage checks on model outputs...")
        example_response = "This is a test response with an email john.doe@example.com."
        leakage_detected = await test_data_leakage(example_response)
        if leakage_detected:
            logger.error("Data leakage detected in the model output.")
        else:
            logger.info("No data leakage detected.")

        # Generate reports after scanning and checks are done
        logger.info("Generating reports...")
        generate_html_report(target, discovered_endpoints, leakage_detected, reports_dir)
        generate_csv_report(target, discovered_endpoints, leakage_detected, reports_dir)
        generate_json_report(target, discovered_endpoints, leakage_detected, reports_dir)

        # Display the reports folder contents
        display_reports_folder(reports_dir)

    except asyncio.CancelledError:
        logger.warning("Scanning process was cancelled.")
    except KeyboardInterrupt:
        logger.info("Scanning interrupted by user.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.error(f"Fatal error: {e}")
