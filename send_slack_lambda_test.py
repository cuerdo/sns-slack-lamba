import requests
import boto3
import json
import logging
import os

from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError


# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
# ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
# SLACK_CHANNEL = os.environ['slackChannel']

# HOOK_URL = "https://" + boto3.client('kms').decrypt(
    # CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL)
    # )['Plaintext'].decode('utf-8')

# logger = logging.getLogger()
# logger.setLevel(logging.INFO)


def lambda_handler():
    # logger.info("Event: " + str(event))
    # message = json.dumps(event['Records'][0]['Sns']['Message'])
    # logger.info("Message: " + str(message))
    f = open('sns.json')
    data = json.load(f)

    alarm_name = json.dumps(data['Records'][0]['Sns']['Message']['AlarmName'])
    old_state = json.dumps(data['Records'][0]['Sns']['Message']['OldStateValue'])
    new_state = json.dumps(data['Records'][0]['Sns']['Message']['NewStateValue'])
    reason = json.dumps(data['Records'][0]['Sns']['Message']['NewStateReason'])
    account = json.dumps(data['Records'][0]['Sns']['Message']['AWSAccountId'])

    payload = {"text": " %s state is now %s: %s in Account %s" % (alarm_name, new_state, reason, account)}
    headers = {'Content-Type': "application/json"}
#    print(HOOK_URL)
    print(payload)
    # try:
        # req = requests.post(HOOK_URL,
            # json.dumps(payload), 
            # headers=headers)
    # except ValueError:
        # print("Couldn't send the message")
    # finally:
        # return {
            # 'statusCode': 200,
            # 'body': json.dumps('Code Run Succesfully')
        # }
if __name__ == '__main__':
    lambda_handler()
