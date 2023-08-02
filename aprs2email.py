import socket
import smtplib
import re
import time
import requests
from email.mime.text import MIMEText
from imapclient import IMAPClient
import email
from email.mime.multipart import MIMEMultipart
import threading

# APRS credentials
APRS_CALLSIGN = 'CALL'
APRS_PASSCODE = 'PASS'
APRS_SERVER = 'rotate.aprs2.net'
APRS_PORT = 14580

# Initialize the socket
aprs_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
aprs_socket_lock = threading.Lock()

# Email configuration
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
IMAP_SERVER = 'imap.gmail.com'
IMAP_PORT = 993
SENDER_EMAIL = 'EMAIL@gmail.com'
SENDER_PASSWORD = 'APP_PASSCODE'

# Alias dictionary
alias_email_map = {
    'mike': 'mike@gmail.com',
    'john': 'john@gmail.com',
    'larry': 'larry@yahoo.com',
    'kevin': 'kevin@gmail.com',

    # Add more aliases and their corresponding email addresses here
}

# Optimization parameters
CHECK_INTERVAL = 0  # Sleep interval between email checks (in seconds)

# Message counter for numbering APRS messages
message_counter = 1

def send_aprs_message(recipient_call, message_body):
    global message_counter
    spaces_after_recipient = ' ' * max(0, 9 - len(recipient_call))
    aprs_message = '{}>APRS::{}{}:{}{{{}\r'.format(APRS_CALLSIGN, recipient_call, spaces_after_recipient, message_body, message_counter)
    message_packet = aprs_message.encode()
    with aprs_socket_lock:  # Acquire lock before sending APRS message
        aprs_socket.sendall(message_packet)
    print(message_packet)
    print(aprs_message)
    print("Sent APRS message to {}: {}".format(recipient_call, message_body))
    print("Outgoing APRS packet: {}".format(aprs_message))  # Exclude the closing "}"
    message_counter += 1
        
def send_ack_message(sender, message_id):
    if message_id.isdigit():
        ack_message = 'ack{}'.format(message_id)
        sender_length = len(sender)
        spaces_after_sender = ' ' * max(0, 9 - sender_length)
        ack_packet_format = '{}>APRS::{}{}:{}\r\n'.format(APRS_CALLSIGN, sender, spaces_after_sender, ack_message)
        ack_packet = ack_packet_format.encode()
        aprs_socket.sendall(ack_packet)
        print("Sent ACK to {}: {}".format(sender, ack_message))
        print("Outgoing ACK packet: {}".format(ack_packet.decode()))

def get_email_body(email_message):
    if email_message.is_multipart():
        # If the email is multipart, extract the text content
        for part in email_message.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True).decode()
                return payload.strip()
    else:
        # If the email is plain text, return the body
        return email_message.get_payload().strip()

    return None



def check_emails():
    try:
        with IMAPClient(IMAP_SERVER, port=IMAP_PORT) as client:
            client.login(SENDER_EMAIL, SENDER_PASSWORD)
            client.select_folder('INBOX')
            messages = client.search(['UNSEEN'])
            if messages:
                print('Received', len(messages), 'new email(s)')

            for msgid, message_data in client.fetch(messages, ['RFC822']).items():
                raw_email = message_data[b'RFC822']
                email_message = email.message_from_bytes(raw_email)

                sender_match = re.search(r'<([^>]+)>', email_message['From'])
                if sender_match:
                    sender = sender_match.group(1)
                else:
                    sender = email_message['From']
                subject = email_message['Subject']
                email_body = get_email_body(email_message)

                aprs_in_subject = 'email' in subject.lower()

                print("\nReceived an email:")
                print("From:", sender)
                print("Subject:", subject)
                print("Body:", email_body)
                print("Contains email:", aprs_in_subject)

                if aprs_in_subject:
                    # Use regular expression to extract the APRS call and message
                    match = re.search(r'@([A-Z0-9-]+)\s+(.+)', email_body, re.IGNORECASE)
                    if match:
                        recipient_call = match.group(1)
                        message_body = match.group(2)
                        print("APRS Callsign-SSID found in email body:", recipient_call)
                        print("Message in email body:", message_body)

                        # Prepend sender's email to the message
                        message_body_with_sender = "@{} {}".format(sender, message_body)

                        send_aprs_message(recipient_call, message_body_with_sender)
                        print("Sent APRS message to {}: {}".format(recipient_call, message_body_with_sender))
                    else:
                        print("No valid APRS Callsign-SSID and message found in email body.")

                # Mark the email as read
                client.set_flags(msgid, [b'\\Seen'])

    except Exception as e:
        print('An error occurred:', e)


def receive_aprs_messages():
    # Connect to the APRS server
    aprs_socket.connect((APRS_SERVER, APRS_PORT))
    print("Connected to APRS server with callsign: {}".format(APRS_CALLSIGN))

    # Send login information with APRS callsign and passcode
    login_str = 'user {} pass {} vers APRS-Email-Bot 1.0\r\n'.format(APRS_CALLSIGN, APRS_PASSCODE)
    aprs_socket.sendall(login_str.encode())
    print("Sent login information.")

    buffer = ""
    try:
        while True:
            data = aprs_socket.recv(1024)
            if not data:
                break
            
            # Add received data to the buffer
            buffer += data.decode()

            # Split buffer into lines
            lines = buffer.split('\n')

            # Process each line
            for line in lines[:-1]:
                if line.startswith('#'):
                    continue

                # Process APRS message
                print("Received raw APRS packet: {}".format(line.strip()))
                parts = line.strip().split(':')
                if len(parts) >= 2:
                    from_callsign = parts[0].split('>')[0].strip()
                    message_text = ':'.join(parts[1:]).strip()

                    # Check if the message contains "{"
                    if "{" in message_text:
                        message_id = message_text.split('{')[1].strip('}')
                        
                        # Remove the first 11 characters from the message to exclude the "Callsign :" prefix
                        verbose_message = message_text[11:].split('{')[0].strip()

                        # Check if the message starts with "@" to handle both email and alias
                        if verbose_message.startswith('@'):
                            email_match = re.match(r'@([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,4})\s+(.+)', verbose_message)
                            if email_match:
                                recipient_email = email_match.group(1)
                                message_body = email_match.group(2)
                                send_email(from_callsign, message_body, recipient_email)
                            else:
                                alias = verbose_message[1:].split()[0]
                                recipient_email = alias_email_map.get(alias)
                                if recipient_email:
                                    message_body = verbose_message[len(alias)+2:]
                                    send_email(from_callsign, message_body, recipient_email)
                                else:
                                    print("Alias '{}' not found in the alias_email_map. Email not sent.".format(alias))

                            send_ack_message(from_callsign, message_id)

            # The last line might be an incomplete packet, so keep it in the buffer
            buffer = lines[-1]

    except Exception as e:
        print("Error receiving APRS messages: {}".format(e))

    finally:
        # Close the socket connection when done
        aprs_socket.close()


        
def send_email(subject, body, recipient_email):
    message = MIMEText(body)
    message['From'] = SENDER_EMAIL
    message['To'] = recipient_email
    message['Subject'] = subject

    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, recipient_email, message.as_string())
        server.quit()
        print('Email sent successfully!')
    except smtplib.SMTPException as e:
        print('Email could not be sent:', e)


def listen_emails():
    while True:
        check_emails()
        time.sleep(CHECK_INTERVAL)

def start_email_listener():
    email_thread = threading.Thread(target=listen_emails)
    email_thread.daemon = True
    email_thread.start()

    print('Email listener started.')
    
def start_aprs_receiver():
    aprs_thread = threading.Thread(target=receive_aprs_messages)
    aprs_thread.daemon = True
    aprs_thread.start()

    print('APRS receiver started.')


if __name__ == '__main__':
    print("APRS bot is running. Waiting for APRS messages...")
    start_email_listener()
    receive_aprs_messages()
    start_aprs_receiver()  # Start the APRS receiver thread
