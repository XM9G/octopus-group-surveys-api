import os
import requests
import json
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from collections import defaultdict


class OctopusAPI:
    def __init__(self, json_file: str):
        self.json_file = json_file

        with open(self.json_file, 'r') as f:
            self.credentials = json.load(f)

        # Phone and password are guaranteed to be present
        phone_val = self.credentials['phone']
        self.phone = phone_val if phone_val[0] == '4' else phone_val[1:]
        self.password = self.credentials['password']

        # Handle optional credentials safely
        optional_keys = ['authorization', 'firebase_api_key', 'refresh_token']
        file_updated = False

        for key in optional_keys:
            if key in self.credentials and self.credentials[key] is not None:
                setattr(self, key, self.credentials[key])
            else:
                setattr(self, key, None)
                self.credentials[key] = ""
                file_updated = True

        # Save back to the file only if missing keys were added/updated
        if file_updated:
            with open(self.json_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)

        self.api_base = 'https://my.octopusgroup.com.au/api'

    def regenerate_authorization_token(self):
        """Exchange the refresh token for an authorization token."""
        url = "https://securetoken.googleapis.com/v1/token"

        params = {
            "key": self.firebase_api_key
        }

        data = {
            "grant_type": "refresh_token",
            "refresh_token": self.refresh_token
        }

        response = requests.post(url, params=params, data=data)

        if response.status_code != 200:
            return None

        return 'Bearer ' + response.json().get("id_token")


    def get_authorization(self):
        """Get a valid authorization token, using saved credentials or Selenium."""

        # Step A: Try saved refresh token
        auth_token = None
        if self.refresh_token and self.firebase_api_key:
            print("Found saved refresh token and Firebase API key. Generating authorization token via API...")
            auth_token = self.regenerate_authorization_token()

            if not auth_token:
                print("Saved refresh token expired or invalid. Falling back to Selenium login...")

        if auth_token:
            self.authorization = auth_token
            self.credentials['authorization'] = auth_token
            with open(self.json_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)

            return auth_token

        # Step B: Fall back to Selenium login
        print("Launching headless browser to capture fresh credentials...")

        options = webdriver.ChromeOptions()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(options=options)

        try:
            wait = WebDriverWait(driver, 10)

            driver.get("https://my.octopusgroup.com.au/login")

            driver.execute_script("""
                window.__capturedRefreshToken = null;
                window.__capturedApiKey = null;

                function checkUrlForKey(url) {
                    if (typeof url === 'string' && url.includes('identitytoolkit.googleapis.com')) {
                        const match = url.match(/[?&]key=([^&]+)/);
                        if (match) {
                            window.__capturedApiKey = match[1];
                        }
                    }
                }

                const originalFetch = window.fetch;
                window.fetch = async function(...args) {
                    checkUrlForKey(args[0]);

                    const response = await originalFetch.apply(this, args);

                    try {
                        const clone = response.clone();
                        const json = await clone.json();

                        if (json && json.refreshToken) {
                            window.__capturedRefreshToken = json.refreshToken;
                        }
                    } catch(e) {}

                    return response;
                };

                const originalOpen = XMLHttpRequest.prototype.open;
                XMLHttpRequest.prototype.open = function(method, url) {
                    checkUrlForKey(url);

                    this.addEventListener('load', function() {
                        try {
                            const json = JSON.parse(this.responseText);

                            if (json && json.refreshToken) {
                                window.__capturedRefreshToken = json.refreshToken;
                            }
                        } catch(e) {}
                    });

                    return originalOpen.apply(this, arguments);
                };
            """)

            phone_input = wait.until(
                EC.presence_of_element_located((By.ID, "phone"))
            )
            phone_input.clear()
            phone_input.send_keys(self.phone)

            password_input = driver.find_element(
                By.CSS_SELECTOR,
                "input[formcontrolname='password']"
            )
            password_input.clear()
            password_input.send_keys(self.password)

            login_button = wait.until(
                EC.element_to_be_clickable(
                    (By.CSS_SELECTOR, "button.signInBubble")
                )
            )
            login_button.click()

            print("Waiting for login authentication...")
            time.sleep(4)

            refresh_token = driver.execute_script(
                "return window.__capturedRefreshToken;"
            )
            api_key = driver.execute_script(
                "return window.__capturedApiKey;"
            )

        except Exception as e:
            print(f"Selenium automation error: {e}")
            return None

        finally:
            driver.quit()

        # Step C: Check that credentials were captured
        if not refresh_token or not api_key:
            print("Failed to capture refresh token and API key during Selenium login.")
            return None

        # Step D: Save fresh credentials
        self.refresh_token = refresh_token
        self.firebase_api_key = api_key
        self.credentials['refresh_token'] = refresh_token
        self.credentials['firebase_api_key'] = api_key

        with open(self.json_file, 'w') as f:
            json.dump(self.credentials, f, indent=4)

        print("Saved new refresh token and Firebase API key successfully!")

        # Step E: Generate final authorization token
        auth_token = self.regenerate_authorization_token()

        if auth_token:
            self.authorization = auth_token
            self.credentials['authorization'] = auth_token
            with open(self.json_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)

        return auth_token


    def get_request(self, api_endpoint: str, headers: dict = None, _attempt: int = 0):
        if not self.authorization:
            self.get_authorization()

        if headers is None:
            headers = {}
        headers['Authorization'] = self.authorization

        try:
            response = requests.get(url=self.api_base+api_endpoint, headers=headers)

            if response.status_code == 401:
                print("Received 401 Unauthorized. Token may have expired. Generating a new one...")

                if _attempt == 2:
                    print('Failed to authorize after 2 attempts')
                    return None
                
                self.get_authorization()
                return self.get_request(api_endpoint=api_endpoint, headers=headers, _attempt=_attempt+1)

            elif response.status_code == 200:
                try:
                    return response.json()
                except ValueError:  # Catches JSONDecodeError, blank responses, and bad syntax
                    return True
                
            else:
                print(f"Failed with status code: {response.status_code}")
                print(response.text)
                return None
            
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
    
    def post_request(self, api_endpoint: str, headers: dict = None, payload: dict = None, _attempt: int = 0):
        if not self.authorization:
            self.get_authorization()
            
        if headers is None:
            headers = {}
        headers['Authorization'] = self.authorization
        
        try:
            response = requests.post(url=self.api_base + api_endpoint, headers=headers, json=payload)

            if response.status_code == 401:
                print("Received 401 Unauthorized. Token may have expired. Generating a new one...")

                if _attempt >= 2:
                    print('Failed to authorize after maximum attempts')
                    return None
                
                self.get_authorization()
                return self.post_request(api_endpoint=api_endpoint, headers=headers, payload=payload, _attempt=_attempt + 1)

            elif response.status_code in (200, 201):
                try:
                    return response.json()
                except ValueError:  # Catches JSONDecodeError, blank responses, etc.
                    return True
                
            else:
                print(f"Failed with status code: {response.status_code}")
                print(response.text)
                return None
            
        except Exception as e:
            print(f"An error occurred: {e}")
            return None

class Octopus:
    def __init__(self, json_file: str):
        self.json_file = json_file
        self.octopusapi = OctopusAPI(json_file)

        self.api_member_details = "/Member/Details"
        self.api_open_surveys = "/Survey/OpenSurveys"
        self.api_get_redemptions = "/Redeem/GetRedemptions"
        self.api_redeem_setup_approval = '/Redeem/SetupApproval'
        self.api_redeem_check_for_approval = '/Redeem/CheckForApproval'
        self.api_redeem_cash = '/Redeem/RedeemCash'
        self.api_get_surveys = '/SurveyHistory/GetHistories'
        self.api_get_incentives = '/Incentive/GetIncentives'

    def _get_member_details(self):
        return self.octopusapi.get_request(self.api_member_details)

    def _get_open_surveys(self):
        return self.octopusapi.get_request(self.api_open_surveys)

    def _get_all_surveys(self):
        return self.octopusapi.post_request(
            self.api_get_surveys,
            payload={
                "PageNumber": 0,
                "PageSize": 1000
            }
        )

    def _get_incentive_history(self):
        return self.octopusapi.post_request(
            self.api_get_incentives,
            payload={
                "PageNumber": 0,
                "PageSize": 1000
            }
        )

    def _get_redemptions(self):
        return self.octopusapi.post_request(
            self.api_get_redemptions,
            payload={
                "PageNumber": 0,
                "PageSize": 1000
            }
        )

    # --- end of api requests ---
    
    def get_balance(self):
        return self._get_member_details()['points']

    def get_total_redeemed(self):
        redemptions = self._get_redemptions()

        total_redeemed = sum([r['amount'] for r in redemptions])
        return total_redeemed

    def get_total_earned(self):
        return self.get_total_redeemed() + self.get_balance()

    def get_open_surveys(self):
        open_surveys = self._get_open_surveys()

        survey_count = len(open_surveys)
        total_earnings = sum([s['incentive'] for s in open_surveys])
        total_time = sum([s['length'] for s in open_surveys])

        return {
            'number': survey_count,
            'total_earnings': total_earnings,
            'total_time': total_time
        }

    def survey_stats(self):
        surveys = self._get_all_surveys()

        filtered_counts = defaultdict(int)

        for item in surveys:
            status: str = item['status']
            
            if status in {'Paused', 'Duplicate', 'Fresh', 'Active'}:
                continue
                
            if status.startswith('Complete'):
                filtered_counts['Complete'] += 1
            elif status.startswith('ScreenerFail'):
                filtered_counts['ScreenerFail'] += 1
            else:
                filtered_counts[status] += 1

        active = self.get_open_surveys()['number']
        filtered_counts['Active'] = active

        return dict(filtered_counts)



if __name__ == '__main__':

    o = Octopus('login.json')

    open_surveys = o.get_open_surveys()
    balance = o.get_balance()
    total_redeemed = o.get_total_redeemed()
    total_earned = o.get_total_earned()
    survey_stats = o.survey_stats()

    print('===== Open Surveys =====')
    print(f'You have {open_surveys['number']} open survey{'' if open_surveys['number'] == 1 else 's'}.')
    print(f'Possible Earnings: ${open_surveys['total_earnings']:.2f}')
    print(f'Total Time: {open_surveys['total_time']} minute{'' if open_surveys['total_time'] == 1 else 's'}')

    print('\n===== Balance =====')
    print(f'Current Balance: ${balance:.2f}')
    print(f'Total Redeemed: ${total_redeemed:.2f}')
    print(f'Time Required: ${total_earned:.2f}')

    print('\n===== Survey Stats =====')
    if 'Complete' in survey_stats:
        print(f"Complete: {survey_stats['Complete']}")
    if 'ScreenerFail' in survey_stats:
        print(f"Screened Out: {survey_stats['ScreenerFail']}")
    if 'QA' in survey_stats:
        print(f"QA Flagged: {survey_stats['QA']}")
    if 'QuotaFail' in survey_stats:
        print(f"Quota Exceeded: {survey_stats['QuotaFail']}")
    if 'Active' in survey_stats:
        print(f"Active: {survey_stats['Active']}")
