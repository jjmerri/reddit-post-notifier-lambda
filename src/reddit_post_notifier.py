#!/usr/bin/env python3.9

import configparser
import json
import logging
import smtplib
import sys
import time
from email.mime.text import MIMEText
from os import environ as env

sys.path.insert(0, 'src/vendor')
import boto3
import praw
from google.auth.transport.requests import AuthorizedSession
from google.oauth2 import service_account

# =============================================================================
# GLOBALS
# =============================================================================


# Reads the config file
config = configparser.ConfigParser()


def set_config():
    config.add_section("Reddit")
    config.add_section("Email")
    config.add_section("RedditPostNotifier")

    config.set("Reddit", "username", env['REDDIT_USERNAME'])
    config.set("Reddit", "password", env['REDDIT_PASSWORD'])
    config.set("Reddit", "client_id", env['REDDIT_CLIENT_ID'])
    config.set("Reddit", "client_secret", env['REDDIT_CLIENT_SECRET'])
    config.set("Email", "server", env['EMAIL_SERVER'])
    config.set("Email", "username", env['EMAIL_USERNAME'])
    config.set("Email", "password", env['EMAIL_PASSWORD'])
    config.set("RedditPostNotifier", "dev_email", env['APP_DEV_EMAIL'])
    config.set("RedditPostNotifier", "dev_user", env['APP_DEV_USERNAME'])
    config.set("RedditPostNotifier", "firebase_uri", env['APP_FIREBASE_URI'])
    config.set("RedditPostNotifier", "app_google_service_account", env['APP_GOOGLE_SERVICE_ACCOUNT'].replace('%', '%%'))
    config.set("RedditPostNotifier", "s3_bucket_name", env['APP_S3_BUCKET_NAME'])


set_config()

# Setup firebase connection/
scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/firebase.database"
]
credentials = service_account.Credentials.from_service_account_info(
    json.loads(config.get("RedditPostNotifier", "app_google_service_account")), scopes=scopes)
authed_session = AuthorizedSession(credentials)

bot_username = config.get("Reddit", "username")
bot_password = config.get("Reddit", "password")
client_id = config.get("Reddit", "client_id")
client_secret = config.get("Reddit", "client_secret")

# Reddit info
reddit = praw.Reddit(client_id=client_id,
                     client_secret=client_secret,
                     password=bot_password,
                     user_agent='reddit_post_notifier by /u/BoyAndHisBlob',
                     username=bot_username)

EMAIL_SERVER = config.get("Email", "server")
EMAIL_USERNAME = config.get("Email", "username")
EMAIL_PASSWORD = config.get("Email", "password")

DEV_EMAIL = config.get("RedditPostNotifier", "dev_email")
DEV_USER_NAME = config.get("RedditPostNotifier", "dev_user")
FIREBASE_URI = config.get("RedditPostNotifier", "firebase_uri")
S3_BUCKET_NAME = config.get("RedditPostNotifier", "s3_bucket_name")

LAST_SUBMISSION_FILE = "lastsubmission.txt"

MAX_EMAIL_RECIPIENTS = 50

pm_notification_subject = "New Post In {subreddit_name}"
pm_notification_body = "{permalink}"
last_submission_sec = {}

s3 = boto3.resource('s3')

# Setup firebase connection
scopes = [
    "https://www.googleapis.com/auth/userinfo.email",
    "https://www.googleapis.com/auth/firebase.database"
]

FORMAT = '%(asctime)-15s %(message)s'
logging.basicConfig(format=FORMAT)
logger = logging.getLogger('redditPostNotifier')
logger.setLevel(logging.INFO)


def get_sub_preferences(subreddit_name):
    response = authed_session.get(
        "{firebase_uri}/notification_preferences/subreddits/{subreddit_name}/user_preferences.json".format(
            firebase_uri=FIREBASE_URI,
            subreddit_name=subreddit_name
        ))

    if response is not None:
        return response.json()
    else:
        return None


def get_all_users_preferences():
    response = authed_session.get("{firebase_uri}/notification_preferences/users.json".format(
        firebase_uri=FIREBASE_URI
    ))

    if response is not None:
        return response.json()
    else:
        return None


def send_dev_pm(subject, body):
    """
    Sends Reddit PM to DEV_USER_NAME
    :param subject: subject of PM
    :param body: body of PM
    """
    reddit.redditor(DEV_USER_NAME).message(subject, body)


def send_notifications(submission):
    preferences = get_sub_preferences(submission.subreddit)
    emails = []
    if preferences:
        for user in preferences:
            if preferences[user]['emailNotification']:
                emails.append(get_user_email(user))
        if emails:
            for emailChunks in list(chunks(emails, MAX_EMAIL_RECIPIENTS)):
                send_email_notifications(submission.subreddit, submission.permalink, emailChunks)


def listen_for_posts(subreddit_name):
    subreddit = reddit.subreddit(subreddit_name)
    last_sent_submission_time = last_submission_sec.get(subreddit_name, 0)
    if last_sent_submission_time == 0:
        last_sent_submission_time = time.time()

    unsent_submissions = set()  # used to retry sending notifications if there was a failure
    submissions = list(subreddit.new(limit=10))
    submissions.sort(key=lambda x: x.created_utc)  # oldest first so can process in order of submission

    for submission in submissions:
        try:
            if last_sent_submission_time >= submission.created_utc:
                continue

            unsent_submissions.add(submission)

            sent_submissions = set()

            # if there are multiple items in the unsent_submissions this could cause items to get resent
            # if a failure occurred on any element other than the first because they never get removed
            for unsent_submission in unsent_submissions:
                send_notifications(unsent_submission)
                sent_submissions.add(unsent_submission)

            for sent_submission in sent_submissions:
                if last_sent_submission_time < sent_submission.created_utc:
                    last_sent_submission_time = sent_submission.created_utc
                    write_last_submission_time(subreddit_name, last_sent_submission_time)
                unsent_submissions.remove(sent_submission)

        except Exception as err:
            logger.exception("Unknown Exception sending notifications")
            try:
                send_email("Error sending notifications", "Error: {exception}".format(exception=str(err)),
                           [DEV_EMAIL])
                send_dev_pm("Unknown Exception sending notifications",
                            "Error: {exception}".format(exception=str(err)))
            except Exception as err:
                logger.exception("Unknown error sending dev pm or email")


def get_user_email(user):
    all_users_preferences = get_all_users_preferences()
    return all_users_preferences[user]['global_preferences']['email']


def load_last_submission_times():
    obj = s3.Object(S3_BUCKET_NAME, LAST_SUBMISSION_FILE)
    last_submissions = obj.get()['Body'].read().decode('utf-8')

    for last_submission in last_submissions.splitlines():
        values = last_submission.split(" ")
        if len(values) == 2:
            last_submission_sec[values[0]] = int(values[1])


def get_subscribed_subs():
    response = authed_session.get(
        "{firebase_uri}/supported_subreddits.json".format(
            firebase_uri=FIREBASE_URI
        ))

    if response is not None:
        return response.json()
    else:
        send_email("Could Not Load Supported Subreddits", "Try to restart it manually.", [DEV_EMAIL])
        return []


def write_last_submission_time(subreddit_name, time_sec):
    last_submission_sec[subreddit_name] = int(float(time_sec))
    last_submissions = ""
    for last_submission in last_submission_sec:
        last_submissions += last_submission + " " + str(
            last_submission_sec.get(last_submission, "10000")) + "\n"

    object = s3.Object(S3_BUCKET_NAME, LAST_SUBMISSION_FILE)
    object.put(Body=last_submissions)


def send_email_notifications(subreddit_name, permalink, email_addresses):
    subject = 'New Reddit Post Notification'
    footer = 'Manage your notification preferences at https://reddit-post-notifier.firebaseapp.com/home'
    body = 'New post in {subreddit_name}.\n\nhttps://www.reddit.com{permalink}\n\n{footer}'.format(
        subreddit_name=subreddit_name, permalink=permalink, footer=footer)

    send_email(subject, body, email_addresses)


def send_email(subject, body, email_addresses):
    sent_from = 'redditpostnotificationbot@gmail.com'

    msg = MIMEText(body.encode('utf-8'), 'plain', 'UTF-8')
    msg['Subject'] = subject

    server = smtplib.SMTP_SSL(EMAIL_SERVER, 465)
    server.ehlo()
    server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
    server.sendmail(sent_from, email_addresses, msg.as_string())
    server.close()


def chunks(l, n):
    """Yield successive n-sized chunks from l."""
    for i in range(0, len(l), n):
        yield l[i:i + n]


def execute(event, context):
    logger.info("start")

    load_last_submission_times()
    subscribed_subs = get_subscribed_subs()

    for subscribed_sub in subscribed_subs:
        logger.info(subscribed_sub)
        listen_for_posts(subscribed_sub)

    logger.info("end")


# for simpler local testing
if __name__ == '__main__':
    execute(None, None)
