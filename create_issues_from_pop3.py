"""
Script for connect to mailbox via POP3 and creating redmine issues bases on inbox messages
"""

import argparse
import email
import logging
import poplib
import re
from email.message import EmailMessage
from email.parser import BytesParser
from email.policy import EmailPolicy
from io import BytesIO
from poplib import POP3
from typing import List, Dict

from bs4 import BeautifulSoup
from redminelib import Redmine


class EmailClient:
    """
    Email client for POP3 server. Can retrieve and delete messages.
    """
    username: str
    password: str
    server: str
    port: str
    server_connection: POP3

    def __init__(self, server: str, username: str, password: str, port: str = '110') -> None:
        """
        :param string server: (required). Mail server address
        :param string username: (required). Username used for authentication.
        :param string password: (required). Password used for authentication
        :param string port: (optional). Mail server port
        """
        self.server = server
        self.port = port
        self.password = password
        self.username = username

    def __enter__(self) -> 'EmailClient':
        """
        Make a connection to the server when used as context manager
        :return EmailClient:
        """
        self.connect_pop3_server(server=self.server, username=self.username, password=self.password, port=self.port)
        return self

    def connect_pop3_server(self, server: str, username: str, password: str, port: str):
        """
        Connect to POP3 server
        :param server: (required). Mail server address
        :param username: (required). Username used for authentication.
        :param password: (required). Password used for authentication
        :param port: (optional). Mail server port
        :return:
        """
        self.server_connection = poplib.POP3(server, port)
        self.server_connection.user(username)
        self.server_connection.pass_(password)

    def disconnect(self):
        """
        Disconnect from the server if connected
        :return:
        """
        if self.server_connection is not None:
            self.server_connection.quit()

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Make sure we disconnect from mail server when used as context manager
        :param exc_type:
        :param exc_val:
        :param exc_tb:
        :return:
        """
        self.disconnect()

    def get_messages(self) -> List[Dict]:
        """
        Get all messages from mailbox
        :return List[Dict]: List of messages
        """
        messages = []
        for i in range(len(self.get_message_list())):
            message_index = i + 1  # message index starts at 1
            messages.append(self.get_message(message_index))
        return messages

    def get_message_list(self):
        """
        Get list of messages in the mailbox
        :return:
        """
        (resp_message, mail_list, octets) = self.server_connection.list()
        return mail_list

    def get_message(self, message_index: int) -> Dict:
        """
        Get specified message from server
        :param int message_index: (required)
        :return Dict: Message as dictionary
        """
        (resp_message, lines, octets) = self.server_connection.retr(message_index)
        msg_content = b'\n'.join(lines)
        msg = BytesParser(EmailMessage, policy=email.policy.default).parsebytes(
            msg_content)  # Create email.message.EmailMessage from message string
        headers = self.get_message_headers(msg)
        body = self.get_message_body(msg)
        attachments = self.get_attachments(msg)

        return {
            **headers,
            'body': body,
            'attachments': attachments,
        }

    def get_message_headers(self, msg: EmailMessage) -> Dict:
        """
        Decodes and parses message headers
        https://docs.python.org/3/library/email.message.html#email.message.EmailMessage

        :param EmailMessage msg: (required) Email message
        :return Dict: Message headers
        """
        email_regexp = r'(?:(.+?)\s<)?([\w.-]+@[\w.-]+)'
        from_name, from_email = re.findall(email_regexp, msg.get('From'))[0]

        # To field can contain multiple recipients separated by comma
        # we split it before decoding because it hard to separate decode_header() result
        raw_to = msg.get('To').split(',')
        recipients = []
        for recipient in raw_to:
            match = re.findall(email_regexp, recipient)
            if match:
                recipients.append({'name': match[0][0], 'email': match[0][1]})
        subject = msg.get('Subject')
        return {
            'sender': {
                'name': from_name,
                'email': from_email
            },
            'recipients': recipients,
            'subject': subject
        }

    def get_message_body(self, msg: EmailMessage) -> List[Dict]:
        body = msg.get_body()
        parsed_body = ''
        content_type = body.get_content_type()
        main_content_type = body.get_content_maintype()
        if main_content_type == 'text':
            parsed_body = self.parse_message_body(body)
        elif content_type == 'multipart/related':
            for part in body.iter_parts():
                if part.get_content_maintype() == 'text':
                    return self.parse_message_body(part)
        else:
            print(content_type)
        return parsed_body

    def parse_message_body(self, msg: EmailMessage):
        content_type = msg.get_content_type()
        if content_type == 'text/html':
            content = msg.get_payload(decode=True)
            # Convert html to plain text using BeautifulSoup module
            soup = BeautifulSoup(content, 'html.parser')
            # Remove style tags because soup.get_text() leaves traces of them
            for tag in soup.find_all('style'):
                tag.decompose()
            body = soup.get_text()
        elif content_type == 'text/plain':
            content = msg.get_payload(decode=True)
            charset = self.get_message_charset(msg)
            if not charset:
                return []
            body = content.decode(charset)
        else:
            raise Exception('Unknown text content type')
        return body

    def get_attachments(self, msg: EmailMessage):
        attachments = []
        for attachment in msg.iter_attachments():
            content = attachment.get_payload(decode=True)
            attachments.append(
                {'type': attachment.get_content_type(), 'filename': attachment.get_filename(), 'body': content})
        return attachments

    def get_message_charset(self, msg: EmailMessage) -> str:
        """
        Get the message charset
        :param EmailMessage msg:
        :return str:
        """
        charset = msg.get_charset()
        if charset is None:
            content_type = msg.get('Content-Type', '').lower()
            match = re.search(r'charset=\"([\w-]+)\"', content_type)
            if match:
                charset = match.group(1)
        return charset

    def delete_message(self, msg_index):
        """
        Delete message
        :param msg_index:
        :return:
        """
        self.server_connection.dele(msg_index)


if __name__ == '__main__':
    logging.basicConfig(filename='create_issues_from_pop3.log', filemode='a',
                        format='%(asctime)s - %(message)s',
                        level=logging.DEBUG)
    parser = argparse.ArgumentParser(
        description='Connect to mailbox via POP3 and create redmine issues bases on messages.')
    parser.add_argument('-server', default='localhost', help='server name (default: localhost)')
    parser.add_argument('-port', default=110, help='server port (default: 110)')
    parser.add_argument('-username', required=True, help='username (example: user@doman.test)')
    parser.add_argument('-password', required=True, help='password')
    parser.add_argument('-redmine_url', required=True, help='Redmine URL')
    parser.add_argument('-redmine_api_key', required=True, help='Redmine API key')
    parser.add_argument('-project_id', required=True, help='Redmine project ID')
    parser.add_argument('-user_id', required=True, help='User or group id to assign issue to')
    args = parser.parse_args()
    redmine = Redmine(args.redmine_url, key=args.redmine_api_key)
    with EmailClient(server=args.server, port=args.port, username=args.username, password=args.password) as client:
        message_list = client.get_message_list()
        for index in range(len(message_list)):
            message_index = index + 1  # message index starts at 1
            try:
                message = client.get_message(message_index)
                uploads = [{'path': BytesIO(attachment["body"]), 'filename': attachment["filename"]} for attachment in
                           message["attachments"]]
                # Find phone number in message body
                match = re.search(r'Тел.\s*((?:\d{3}-)?\d{2}-\d{2})', message['body'])
                phone = f' ({match.group(1)})' if match else ''
                issue = redmine.issue.create(
                    project_id=args.project_id,
                    subject=f'{message["sender"]["name"] or message["sender"]["email"]}: {message["subject"]}{phone}',
                    assigned_to_id=args.user_id,
                    description=message['body'],
                    custom_fields=[
                        {
                            'id': 1,
                            'value': '999  Прочее'
                        },
                        {
                            'id': 64,
                            'value': 'Не указано'
                        },
                        {
                            'id': 65,
                            'value': 'Приём и регистрация заявки(1ч.)'
                        }
                    ],
                    uploads=uploads
                )
                client.delete_message(message_index)
            except Exception as e:
                logging.exception(f'Exception "{e}" occurred')
