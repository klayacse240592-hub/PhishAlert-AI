import imaplib
import email
import re
import os
from dotenv import load_dotenv
from analyzer import analyze_email, analyze_url

load_dotenv()

EMAIL_USER = os.getenv("GMAIL_USER")
EMAIL_PASS = os.getenv("GMAIL_APP_PASSWORD")


def extract_links(text):
    return re.findall(r'https?://\S+', text)


def scan_inbox(limit=10):
    results = []

    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(EMAIL_USER, EMAIL_PASS)
    mail.select("inbox")

    _, data = mail.search(None, "ALL")
    mail_ids = data[0].split()

    latest_ids = mail_ids[-limit:]

    for mail_id in reversed(latest_ids):
        _, msg_data = mail.fetch(mail_id, "(RFC822)")
        raw_email = msg_data[0][1]

        msg = email.message_from_bytes(raw_email)

        sender = msg.get("From", "")
        subject = msg.get("Subject", "")

        body = ""

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                if ctype == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        body += payload.decode(errors="ignore")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                body = payload.decode(errors="ignore")

        full_text = f"{sender}\n{subject}\n{body}"

        email_result = analyze_email(full_text)

        links = extract_links(body)
        link_results = []

        for link in links:
            link_results.append({
                "url": link,
                "analysis": analyze_url(link)
            })

        results.append({
            "from": sender,
            "subject": subject,
            "email_analysis": email_result,
            "links": link_results
        })

    mail.logout()
    return results