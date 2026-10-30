import requests
import json
from bs4 import BeautifulSoup
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

        if not self.firebase_api_key:
            api_key = self.regenerate_firebase_api_key()

            self.firebase_api_key = api_key
            self.credentials['firebase_api_key'] = api_key
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

        return response.json().get("id_token")

    def regenerate_firebase_api_key(self):
        # get the login page html and parse for main js file name
        
        r = requests.get('https://my.octopusgroup.com.au/login')
        soup = BeautifulSoup(r.text, 'html.parser')
        scripts = soup.find_all("script")
        for script in scripts:
            if script.get('src'):
                if script['src'].startswith('main.'):
                    main_js = script['src']
                    break

        main_js_url = 'https://my.octopusgroup.com.au/' + main_js

        # get the firebase api key from the main js file

        r = requests.get(main_js_url)
        js_text = r.text
        api_key = js_text.split('apiKey:"')[1].split('"')[0].strip()

        return api_key
        


    def get_authorization(self):
        """Get a valid authorization token, using saved credentials or Selenium."""

        # Step A: Try saved refresh token
        auth_token = None
        if self.refresh_token and self.firebase_api_key:
            print("Found saved refresh token and Firebase API key. Generating authorization token via API...")
            auth_token = self.regenerate_authorization_token()

        if auth_token:
            self.authorization = auth_token
            self.credentials['authorization'] = auth_token
            with open(self.json_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)

            return auth_token
        
        print("Saved refresh token expired, invalid, or missing. Falling back to API login...")

        # Step B: Use login API endpoint, and also get a new refresh token


        # log in and get the authorization token
        auth_token_request = self.post_request(
            '/Auth/Login',
            payload={
                'phoneNumber':'+61'+self.phone, 
                'password':self.password
            },
            require_auth=False
        )

        if not auth_token_request:
            print("Failed to log in with given credentials. Check that you have entered the right phone number and password.")
            exit()

        auth_token = auth_token_request['token']

        # use the authorization token and the firebase api key to get refresh token

        refresh_token_request = self.post_request(
            f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={self.firebase_api_key}',
            payload={
                "token": auth_token,
                "returnSecureToken": True
            },
            base='',
            require_auth=False
        )

        if not refresh_token_request:
            api_key = self.regenerate_firebase_api_key()

            self.firebase_api_key = api_key
            self.credentials['firebase_api_key'] = api_key
            with open(self.json_file, 'w') as f:
                json.dump(self.credentials, f, indent=4)

            refresh_token_request = self.post_request(
                f'https://identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key={self.firebase_api_key}',
                payload={
                    "token": auth_token,
                    "returnSecureToken": True
                },
                base='',
                require_auth=False
            )

        if not refresh_token_request:
            print("Failed to generate refresh token. The Firebase API key may be incorrect.")
            return None
        else:
            refresh_token = refresh_token_request['refreshToken']

        # 1. Update self.refresh_token first so the next function can see it
        self.refresh_token = refresh_token
        self.credentials['refresh_token'] = refresh_token

        # 2. Now generate the Firebase ID token using the new refresh token
        auth_token = self.regenerate_authorization_token()
        if not auth_token:
            print("Failed to generate Firebase ID token.")
            return None
        
        # 3. Save everything else
        self.authorization = auth_token
        self.credentials['authorization'] = auth_token

        print("Saved new refresh token and Firebase API key successfully!")

        with open(self.json_file, 'w', encoding='utf-8') as f:
            json.dump(self.credentials, f, indent=4)

        return auth_token


    def get_request(self, api_endpoint: str, headers: dict = None, _attempt: int = 0, base: str = None, require_auth: bool = True):
        
        if headers is None:
            headers = {}

        if require_auth:
            if not self.authorization:
                self.get_authorization()

            headers['Authorization'] = 'Bearer '+self.authorization

        try:
            if base is None:
                base = self.api_base
                
            response = requests.get(url=base+api_endpoint, headers=headers)

            if response.status_code == 401:
                print("Received 401 Unauthorized. Token may have expired. Generating a new one...")

                if _attempt == 2:
                    print('Failed to authorize after 2 attempts')
                    return None
                
                self.get_authorization()
                return self.get_request(api_endpoint=api_endpoint, headers=headers, _attempt=_attempt+1, base=base)

            elif response.status_code == 200:
                try:
                    return response.json()
                except ValueError:  # Catches JSONDecodeError, blank responses, and bad syntax
                    return True
                
            else:
                print(f"Failed with status code: {response.status_code}")
                if response.status_code != "404":
                    print(response.text)
                return None
            
        except Exception as e:
            print(f"An error occurred: {e}")
            return None
    
    def post_request(self, api_endpoint: str, headers: dict = None, payload: dict = None, _attempt: int = 0, base: str = None, require_auth: bool = True):

        if headers is None:
            headers = {}

        if require_auth:
            if not self.authorization:
                self.get_authorization()

            headers['Authorization'] = 'Bearer '+self.authorization
        
        try:
            if base is None:
                base = self.api_base
            
            response = requests.post(url=base + api_endpoint, headers=headers, json=payload)

            if response.status_code == 401:
                print("Received 401 Unauthorized. Token may have expired. Generating a new one...")

                if _attempt >= 2:
                    print('Failed to authorize after maximum attempts')
                    return None
                
                self.get_authorization()
                return self.post_request(api_endpoint=api_endpoint, headers=headers, payload=payload, _attempt=_attempt + 1, base=base)

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
    
    def get_redeemable_balance(self, balance: float = None):
        if balance is None:
            balance = self.get_balance()
        return 0 if balance < 20 else int(balance//5*5)

    def get_total_redeemed(self):
        redemptions = self._get_redemptions()

        total_redeemed = sum([r['amount'] for r in redemptions])
        return total_redeemed

    def get_total_earned(self, total_redeemed: float = None, balance: float = None):
        if total_redeemed is None:
            total_redeemed = self.get_total_redeemed()
        if balance is None:
            balance = self.get_balance()
        return total_redeemed + balance
    
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
    survey_stats = o.survey_stats()
    total_earned = o.get_total_earned(balance=balance, total_redeemed=total_redeemed)
    # balance and total_redeemed parameters are optional but used here given balance and total_redeemed are already known to save 2 redundant API calls
    redeemable_balance = o.get_redeemable_balance(balance=balance)
    # balance parameter is again optional but used here to save a redundant API call

    print('===== Open Surveys =====')
    print(f'You have {open_surveys['number']} open survey{'' if open_surveys['number'] == 1 else 's'}.')
    print(f'Possible Earnings: ${open_surveys['total_earnings']:.2f}')
    print(f'Total Time: {open_surveys['total_time']} minute{'' if open_surveys['total_time'] == 1 else 's'}')

    print('\n===== Balance =====')
    print(f'Current Balance: ${balance:.2f}')
    print(f'Redeemable Balance: ${redeemable_balance:.2f}')
    print(f'Total Redeemed: ${total_redeemed:.2f}')
    print(f'Total Earned: ${total_earned:.2f}')

    print('\n===== Survey Stats =====')
    if 'Complete' in survey_stats:
        print(f"Completed: {survey_stats['Complete']} ({survey_stats['Complete'] / (survey_stats['Complete'] + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)) * 100:.2f}%)")
    if 'ScreenerFail' in survey_stats:
        print(f"Screened Out: {survey_stats['ScreenerFail']} ({survey_stats['ScreenerFail'] / (survey_stats['Complete'] + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)) * 100:.2f}%)")
    if 'QA' in survey_stats:
        print(f"QA Flagged: {survey_stats['QA']} ({survey_stats['QA'] / (survey_stats['Complete'] + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)) * 100:.2f}%)")
    if 'QuotaFail' in survey_stats:
        print(f"Quota Exceeded: {survey_stats['QuotaFail']} ({survey_stats['QuotaFail'] / (survey_stats['Complete'] + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)) * 100:.2f}%)")
    if 'Active' in survey_stats:
        print(f"Active: {survey_stats['Active']} ({survey_stats['Active'] / (survey_stats['Complete'] + survey_stats.get('ScreenerFail', 0) + survey_stats.get('QA', 0) + survey_stats.get('QuotaFail', 0) + survey_stats.get('Active', 0)) * 100:.2f}%)")
