import base64
import functions_framework
import json
#this is to generate mock data. Not required in production code
from types import SimpleNamespace
#this will automatically fetch my credentials to connect to other google services
from google.auth import default
#this will attach oauth tokens
from google.auth.transport.requests import AuthorizedSession
from google.cloud import secretmanager
#to get the environment file
import os
from dotenv import load_dotenv
load_dotenv()

#this is to send post requests to cimpress api endpoint
import requests

### this function will get the id of the stored procedure and look for its name from transfer config lookup file
## some issue with this function so skipping this now
def get_transfer_display_name(name):
    try:
        parts = name.split("/")
        project_id = parts[1]
        location = parts[3]
        transfer_config_id = parts[5]
        print(transfer_config_id,project_id,location)

        credentials, _ = default()
        authed_session = AuthorizedSession(credentials)
        #bearer tokens will get automatically attached to this url
        url = f"https://bigquerydatatransfer.googleapis.com/v1/projects/{project_id}/locations/{location}/transferConfigs/{transfer_config_id}"

        

        response = authed_session.get(url)
        if response.status_code == 200:
            return response.json().get("displayName", None)
        else:
            print(f"Failed to fetch display name. Status: {response.status_code}, Body: {response.text}")
            return None
    except Exception as e:
        print(f"Error fetching display name: {e}")
        return None

#this function will connect to the national pens project on gcp which has the client secret to setup auth with email service
#projects/261374685312/secrets/email_template_cred_eca
def secret_fetcher(secret_name):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/261374685312/secrets/{secret_name}/versions/1"
    response = client.access_secret_version(name=name)
    # Decode the payload
    payload = response.payload.data.decode("UTF-8").strip()
    return payload

#once we have the secret we can use these values to access the email template app under https://api.cimpress.io/ using cimpress oauth tokens

def generate_token(client_id, client_secret):
    try:
        response = requests.post(
            'https://oauth.cimpress.io/v2/token',
            data={
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'audience': 'https://api.cimpress.io/'
            }
        )
        json_data = response.json()
        # print ('Response from cimpress endpoint:',json_data)-- > {'access_token': 'eyJhbGci....'expires_in': 86400, 'token_type': 'Bearer'}
        return f"Bearer {json_data['access_token']}" if 'access_token' in json_data else None
    except requests.exceptions.RequestException as err:
        print(f"Request Exception: {err}")
        return None

#this function will generate a token usong the generate token function and send a post request to puremail.trdlnk.cimpress.io/v1/send/{PUREMAIL_TEMPLATE_ID}
#with the email payload
def send_email_alert(message_body, cred):
    token = generate_token(cred['client_id'], cred['client_secret'])
    if not token:
        print("Cannot send email: Failed to generate access token.")
        return
    PUREMAIL_TEMPLATE_ID = os.getenv("PUREMAIL_TEMPLATE_ID")
    url = f"https://puremail.trdlnk.cimpress.io/v1/send/{PUREMAIL_TEMPLATE_ID}"
    headers = {
        "Authorization": token,
        "Content-Type": "application/json"
    }

    email_payload = {
        # "to": "kiran.r@cimpress.com",
        # "subject": subject,
        "item": message_body
    }

    try:
        response = requests.post(url, headers=headers, data=json.dumps(email_payload))
        print(f"Email sent. Status: {response.status_code}")
        print(f"Response: {response.text}")
    except Exception as e:
        print(f"Error sending email: {e}")

# Mock CloudEvent-- comment this whendeploying in cf
event = SimpleNamespace(
    data={
        "message": {
            "data": "#eyJkYXRhU291cmNlSWQiOiAic2NoZWR1bGVkX3F1ZXJ5IiwgImRlc3RpbmF0aW9uRGF0YXNldElkIjogIiIsICJlbWFpbFByZWZlcmVuY2VzIjoge30sICJlbmRUaW1lIjogIjIwMjUtMDctMTBUMDk6NDk6MTUuNDA4MzQ4WiIsICJlcnJvclN0YXR1cyI6IHsiY29kZSI6IDMsICJtZXNzYWdlIjogIlF1ZXJ5IGVycm9yOiBkaXZpc2lvbiBieSB6ZXJvOiAxIC8gMCBhdCBbNTozXTsgSm9iSUQ6IDI2MTM3NDY4NTMxMjpzY2hlZHVsZWRfcXVlcnlfNjhjMDkxOGYtMDAwMC0yNmVhLWFmZjUtNTgyNDI5YjdkNjI0In0sICJuYW1lIjogInByb2plY3RzLzI2MTM3NDY4NTMxMi9sb2NhdGlvbnMvdXMvdHJhbnNmZXJDb25maWdzLzY4N2IwZGZiLTAwMDAtMmQxZC1iYjk1LTAwMWExMTQ0OTg2NC9ydW5zLzY4YzA5MThmLTAwMDAtMjZlYS1hZmY1LTU4MjQyOWI3ZDYyNCIsICJub3RpZmljYXRpb25QdWJzdWJUb3BpYyI6ICJwcm9qZWN0cy9uYXRpb25hbHBlbi90b3BpY3Mvc2NoZWR1bGVyX3Rlc3RfcHNfQVAiLCAicGFyYW1zIjogeyJxdWVyeSI6ICJERUNMQVJFIERBVEVfVE9EQVkgREFURVRJTUU7XG5ERUNMQVJFIEVSUk9SX01TRyBTVFJJTkc7XG5CRUdJTlxuICBTRVQgREFURV9UT0RBWSA9IChTRUxFQ1QgQ1VSUkVOVF9EQVRFKCkpO1xuICBTRUxFQ1QgMS8wO1xuRVhDRVBUSU9OIFdIRU4gRVJST1IgVEhFTlxuICBTRVQgRVJST1JfTVNHID0gJ1lFUyc7XG4gIFJBSVNFO1xuRU5EXG5cblxuXG4ifSwgInJ1blRpbWUiOiAiMjAyNS0wNy0xMFQwOTo0ODowMFoiLCAic2NoZWR1bGUiOiAiZXZlcnkgNSBtaW51dGVzIiwgInNjaGVkdWxlVGltZSI6ICIyMDI1LTA3LTEwVDA5OjQ4OjAwWiIsICJzdGFydFRpbWUiOiAiMjAyNS0wNy0xMFQwOTo0ODowMC41MjkyMTVaIiwgInN0YXRlIjogIkZBSUxFRCIsICJ1cGRhdGVUaW1lIjogIjIwMjUtMDctMTBUMDk6NDk6MTUuNDA4NDA1WiIsICJ1c2VySWQiOiAiLTIxNzQ1MDMwNDYwMDIwNDQ0OTIifQ=="
        }
    }
)

# Triggered from a message on a Cloud Pub/Sub topic.
@functions_framework.cloud_event
# Your Cloud Function code
def main(event):

        # Fetch credentials
    client_secret_val = secret_fetcher('email_template_cred_eca')
    cred = {
        'client_id': 'l2F4Uo2JHNChz3iRCIlsXN0hUajWxcHW',
        'client_secret': client_secret_val
    }

    token = generate_token(cred['client_id'], cred['client_secret'])
    print("token: ",token)
    if not token:
        print("Cannot send email: Failed to generate access token.")

    #decode the pubsub message into utf-8(json) from bytes
    payload_bytes = base64.b64decode(event.data["message"]["data"])
    #convert json to python data dictionary
    payload = json.loads(payload_bytes.decode("utf-8"))

    # Extract the error message,time_of_error and name of procedure which gives the error
    error_message = payload.get("errorStatus", {}).get("message", "No error message found.")
    runtime_utc = payload.get("runTime", "No runTime found")
    
    payload_request_url = payload.get("name", "")
    #get the name of the procedure from the payload_name using the display name function
    proc_name = get_transfer_display_name(payload_request_url)


    # Prepare message body
    # subject = f"Scheduled Query Failed: {proc_name}"
    message_body = {
            "procedure_name": proc_name,
            "message": error_message,
            "timestamp": runtime_utc,
            "contacts":{
                "primary": "harendra.sahu@pens.com",
                "secondary": "abhranil.pal@pens.com"
            }
    }

    #send message
    send_email_alert(message_body, cred)



    #All logs
    print("Name of procedure: ",proc_name ,'\n')
    print("Error_msg: ",error_message,'\n')
    print("Time of exection: ",runtime_utc,'\n')
    print("client secret: ",client_secret_val,'\n')
    print("Proc_name: ",proc_name,'\n')
    print('Payload req url: ',payload_request_url,'\n' )
    print('Payload: ',payload,'\n')
    print('Payload bytes: ',payload_bytes,'\n')

#remove this when deploying
main(event)

