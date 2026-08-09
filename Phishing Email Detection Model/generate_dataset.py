"""
generate_dataset.py
--------------------
Generates a synthetic-but-realistic labeled dataset of phishing and
legitimate emails for training/testing the phishing detector.

In a real project you would replace this with a real-world dataset such as:
- Nazario Phishing Corpus
- SpamAssassin Public Corpus
- Kaggle "Phishing Email Detection" datasets
The rest of the pipeline (feature extraction, model, evaluation) is
dataset-agnostic and will work unchanged as long as you provide a CSV
with 'text' and 'label' columns (label in {"phishing", "safe"}).
"""

import random
import pandas as pd

random.seed(42)

# ------------------------------------------------------------------
# Building blocks for PHISHING emails
# ------------------------------------------------------------------
phishing_subjects = [
    "Urgent: Your Account Has Been Suspended",
    "Action Required: Verify Your Identity Now",
    "Your Password Will Expire Today",
    "Security Alert: Unusual Sign-in Activity Detected",
    "Final Notice: Payment Failed - Update Billing Info",
    "You Have Won a Prize! Claim Now",
    "Confirm Your Bank Account Details Immediately",
    "Your Package Could Not Be Delivered",
    "IRS Tax Refund Pending - Verify Now",
    "Your Mailbox Storage Is Full - Upgrade Now",
]

phishing_bodies = [
    "Dear Customer, we detected suspicious activity on your account. "
    "Click here immediately to verify your identity: {url} or your account "
    "will be permanently suspended within 24 hours. Failure to act now will "
    "result in loss of access. This is your final warning!!!",

    "Dear User, your password has expired. To avoid losing access to your "
    "account, please login and reset your password urgently at {url}. "
    "Act now, this link expires in 1 hour.",

    "Congratulations!!! You have been selected as the winner of a $1,000,000 "
    "prize. To claim your reward, verify your details at {url} within 48 "
    "hours or the prize will be forfeited.",

    "We were unable to process your last payment. Your account will be "
    "suspended unless you update your billing information immediately. "
    "Click {url} now to confirm your credit card details.",

    "Your bank account has been flagged for unusual login activity. "
    "Please confirm your identity by clicking {url} and entering your "
    "username, password and security code to restore access.",

    "This is an urgent notice from IRS Tax Services. You are eligible for "
    "a tax refund. Verify your social security number and bank details at "
    "{url} to receive your refund immediately.",

    "Your package delivery failed due to an incomplete address. Click {url} "
    "to reschedule delivery and confirm your payment details, or your "
    "package will be returned.",

    "ATTENTION: We noticed a login attempt from an unrecognized device. "
    "If this wasn't you, secure your account NOW by clicking {url} and "
    "verifying your login credentials immediately.",

    "Your mailbox has exceeded its storage limit and incoming mail will be "
    "rejected. Click {url} to upgrade your storage and avoid service "
    "interruption today.",

    "Dear valued customer, due to a security breach we require you to "
    "reconfirm your account information at {url}. This is mandatory and "
    "must be completed within 12 hours to avoid permanent suspension.",
]

phishing_urls = [
    "http://192.168.44.21/secure-login/verify",
    "http://bit.ly/3xAmpleLink",
    "http://paypal-security-update.com/login",
    "http://account-verify-now.info/confirm",
    "http://tinyurl.com/xyz123reset",
    "http://apple-id-locked.support/verify",
    "http://irs-tax-refund.net/claim",
    "http://secure-bank0famerica.com/login",
    "http://185.23.11.9/reset-password",
    "http://amaz0n-delivery-update.com/track",
]

phishing_signoffs = [
    "\n\nSecurity Team\nDo not reply to this automated message.",
    "\n\nCustomer Support\nThis message requires immediate action.",
    "\n\nAccount Services Department",
    "\n\nThank you,\nBilling Department",
]

# ------------------------------------------------------------------
# Building blocks for LEGITIMATE emails
# ------------------------------------------------------------------
safe_subjects = [
    "Meeting Rescheduled to 3 PM Tomorrow",
    "Your Monthly Newsletter is Here",
    "Project Update: Q3 Roadmap",
    "Lunch this Friday?",
    "Invoice #4521 Attached",
    "Notes from Today's Standup",
    "Welcome to the Team!",
    "Your Order Has Shipped",
    "Reminder: Dentist Appointment Next Week",
    "Weekly Team Digest",
]

safe_bodies = [
    "Hi team, just a quick note that our meeting tomorrow has been moved to "
    "3 PM in the main conference room. Please update your calendars "
    "accordingly. Let me know if this time doesn't work for you.",

    "Hello, here is our monthly newsletter with updates on new features, "
    "upcoming events, and community highlights. As always, feel free to "
    "reply with any feedback or questions.",

    "Hi all, sharing our Q3 roadmap for review. We've made good progress "
    "on the core features and plan to start user testing next month. "
    "Happy to discuss further in our next sync.",

    "Hey, are you free for lunch this Friday? I was thinking we could try "
    "the new place downtown around noon. Let me know if that works for you.",

    "Hello, please find attached invoice #4521 for services rendered in "
    "June. Payment is due within 30 days. Let us know if you have any "
    "questions about the charges.",

    "Hi everyone, quick recap from today's standup: backend work is on "
    "track, frontend is slightly behind due to a design change, and QA "
    "will begin testing next week.",

    "Welcome aboard! We're excited to have you join the team. Your laptop "
    "and accounts have been set up, and your manager will walk you through "
    "onboarding on your first day.",

    "Good news, your order #A29381 has shipped and is expected to arrive "
    "in 3-5 business days. You can track the shipment from your account "
    "order history page.",

    "This is a friendly reminder that you have a dentist appointment "
    "scheduled for next Tuesday at 10 AM. Please call the office if you "
    "need to reschedule.",

    "Hi team, here's this week's digest: three features shipped, two bugs "
    "closed, and planning for next sprint starts Monday. Great work "
    "everyone.",
]

safe_signoffs = [
    "\n\nBest,\nSarah",
    "\n\nThanks,\nThe Team",
    "\n\nCheers,\nMike",
    "\n\nBest regards,\nHR Department",
    "\n\nThank you,\nAccounting",
]

safe_urls = [
    "https://company-intranet.com/calendar",
    "https://mail.google.com/mail/u/0",
    "https://docs.company.com/roadmap-q3",
    "https://tracking.shipco.com/orders/A29381",
    "https://calendar.google.com/event?id=abc123",
]


def make_phishing_email():
    subject = random.choice(phishing_subjects)
    body_template = random.choice(phishing_bodies)
    url = random.choice(phishing_urls)
    body = body_template.format(url=url)
    body += random.choice(phishing_signoffs)
    # occasionally add a second suspicious url to add variety
    if random.random() < 0.3:
        body += f"\nAlternative link: {random.choice(phishing_urls)}"
    return f"Subject: {subject}\n\n{body}"


def make_safe_email():
    subject = random.choice(safe_subjects)
    body = random.choice(safe_bodies)
    if random.random() < 0.4:
        body += f"\n\nLink: {random.choice(safe_urls)}"
    body += random.choice(safe_signoffs)
    return f"Subject: {subject}\n\n{body}"


def generate_dataset(n_phishing=300, n_safe=300):
    rows = []
    for _ in range(n_phishing):
        rows.append({"text": make_phishing_email(), "label": "phishing"})
    for _ in range(n_safe):
        rows.append({"text": make_safe_email(), "label": "safe"})
    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # shuffle
    return df


if __name__ == "__main__":
    df = generate_dataset()
    df.to_csv("emails_dataset.csv", index=False)
    print(f"Generated dataset with {len(df)} emails")
    print(df["label"].value_counts())
