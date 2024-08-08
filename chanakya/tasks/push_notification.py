import requests
import os
import logging

logger = logging.getLogger(__name__)

ONESIGNAL_AUTHORIZATION = os.getenv("ONESIGNAL_AUTHORIZATION")


class PushNotification:
    def __init__(self):
        self.headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": f"Basic {ONESIGNAL_AUTHORIZATION}"
        }
        self.app_id = os.getenv("ONESIGNAL_APP_ID")
        self.url = os.getenv("ONESIGNAL_URL")

    def send_notification(self, contents, headings=None, url=None, data=None):

        payload = {
            "app_id": self.app_id,
            "contents": {"en": contents},
            "included_segments": ["All"],
        }

        if headings:
            payload["headings"] = {"en": headings}
        if url:
            payload["url"] = url
        if data:
            payload["data"] = data

        response = requests.post(self.url, headers=self.headers, json=payload)
        return response.json()

    def send_notification_to_user(self, contents, user_player_id):
        try:
            logger.debug("Sending notification to user")
            logger.info(f"Sending notification to user {user_player_id}")
            payload = {
                "app_id": self.app_id,
                "contents": {"en": contents},
                "include_aliases": {
                    "external_id": [user_player_id]
                },
                "target_channel": "push"
            }

            response = requests.post(self.url, headers=self.headers, json=payload)
            logger.info(f"one signal response: {response.text}")
            return True
        except Exception as e:
            pass
    # email service
    # def send_notification_to_emai(self, contents, user):
    #     try:
    #         logger.debug("Sending notification to user")
    #         logger.info(f"Sending notification to user {user.emal}")
    #         email_body = f"""
    #                 <html>
    #                     <head>Welcome to Chanakya</head>
    #                     <body>
    #                         <h1>Welcome to Chanakya</h1>
    #                         <h4>Learn Answer Fast\'s Explore the World!</h4>
    #                         <hr/>
    #                         <p>Hi {user.first_name},</p>
    #                         <p>Thanks for subscribing to Chanakya!</p>
    #                         <p>{contents}</p>
    #                         <a href='https://aichanakya.in/'>Show me more about Chanakya</a>
    #                         <hr/>
    #                         <p><small>(c) 2024 NeuroBridge Tech All rights reserved.</small></p>
    #                         <p><small><a href='[unsubscribe_url]'>Unsubscribe</a></small></p>
    #                     </body>
    #                 </html>
    #                 """
    #         payload = {
    #             "app_id": self.app_id,
    #             "email_subject": "🚀 Welcome to Chanakya: The India AI Revolution 🇮🇳",
    #             "email_body": email_body,
    #             "include_aliases": {
    #                 "email": [user.emal]
    #             },
    #             "target_channel": "email"
    #         }
    #
    #         response = requests.post(self.url, headers=self.headers, json=payload)
    #         logger.info(f"one signal email response: {response.text}")
    #         return True
    #     except Exception as e:
    #         pass
