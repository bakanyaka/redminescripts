"""
Script for connect to mailbox via POP3 and creating redmine issues bases on inbox messages
"""

import argparse
import poplib
import re
from email.header import decode_header
from email.message import EmailMessage
from email.parser import Parser
from poplib import POP3
from typing import List, Dict

from bs4 import BeautifulSoup
from redminelib import Redmine
from io import BytesIO


class MessageContentTypeError(Exception):
    """Exception raised for errors in the message content type"""

    def __init__(self, message):
        self.message = message


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
        msg_content = b'\r\n'.join(lines).decode('utf-8')
        msg = Parser().parsestr(msg_content)  # Create email.message.EmailMessage from message string
        headers = self.parse_message_headers(msg)
        mail_body_parts = self.parse_message_body(msg)

        body = []
        attachments = []
        for part in mail_body_parts:
            if part['type'] == 'text':
                body.append(part['body'])
            elif part['type'] == 'file':
                attachments.append(part)

        return {
            **headers,
            'body': '\n'.join(body),
            'attachments': attachments,
        }

    def parse_message_headers(self, msg: EmailMessage) -> Dict:
        """
        Decodes and parses message headers
        https://docs.python.org/3/library/email.message.html#email.message.EmailMessage

        :param EmailMessage msg: (required) Email message
        :return Dict: Message headers
        """
        email_regexp = r'[\w\.-]+@[\w\.-]+'
        decoded_from = decode_header(msg.get('From'))  # Decode from base64. Returns a list of (string, charset) pairs.
        if len(decoded_from) == 1:
            # Only email address in from field
            match = re.findall(email_regexp, decoded_from[0][0])
            from_email = match[0] if match else ''
            from_name = ''
        elif len(decoded_from) == 2:
            # Both address and name in from field
            (from_name_raw, encoding) = decoded_from[0]
            from_name = from_name_raw if encoding is None else from_name_raw.decode(encoding)
            match = re.findall(email_regexp, decoded_from[1][0].decode())
            from_email = match[0] if match else ''
        else:
            raise Exception('Incorrect from header')

        decoded_to = decode_header(msg.get('To'))  # Decode from base64. Returns a list of (string, charset) pairs.
        if len(decoded_to) == 1:
            # Only email address in to field
            match = re.findall(email_regexp, decoded_to[0][0])
            to_email = match[0] if match else ''
            to_name = ''
        elif len(decoded_to) == 2:
            # Both address and name in to field
            (to_name_raw, encoding) = decoded_to[0]
            to_name = to_name_raw if encoding is None else to_name_raw.decode(encoding)
            match = re.findall(email_regexp, decoded_to[1][0].decode())
            to_email = match[0] if match else ''
        else:
            raise Exception('Incorrect to header')

        header_subject = msg.get('Subject')
        subject_raw, encoding = decode_header(header_subject)[0]  # Decode from base64
        subject = subject_raw if encoding is None else subject_raw.decode(encoding)
        return {
            'from_email': from_email,
            'from_name': from_name,
            'to_email': to_email,
            'to_name': to_name,
            'subject': subject
        }

    def parse_message_body(self, msg: EmailMessage) -> List[Dict]:
        """
        Decodes and parses all parts of message
        https://docs.python.org/3/library/email.message.html#email.message.EmailMessage
        :param EmailMessage msg: Email message
        :return List[Dict]:
        """
        content_type = msg.get_content_type()
        if content_type == 'multipart/report':
            raise MessageContentTypeError(message='Message is report')
        if msg.is_multipart():
            parts = []
            for part in msg.get_payload():
                parts += self.parse_message_body(part)
            return parts
        else:
            content = msg.get_payload(decode=True)
            if content_type == 'text/html':
                # Convert html to plain text using BeautifulSoup module
                soup = BeautifulSoup(content, 'html.parser')
                # Remove style tags because soup.get_text() leaves traces of them
                for tag in soup.find_all('style'):
                    tag.decompose()
                return [{'type': 'text', 'body': soup.get_text()}]
            elif content_type == 'text/plain':
                charset = self.get_message_charset(msg)
                if not charset:
                    return []
                return [{'type': 'text', 'body': content.decode(charset)}]
            elif content_type.startswith('image') or content_type.startswith('application'):
                return [{'type': 'file', 'filename': msg.get_filename(), 'body': content}]
            else:
                raise Exception(f'Unknown content type {content_type}')

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
                    subject=f'{message["from_name"] or message["from_email"]}: {message["subject"]}{phone}',
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

            except MessageContentTypeError:
                pass
            except Exception as e:
                print(e)
