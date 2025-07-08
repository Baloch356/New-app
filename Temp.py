import requests
import time

API_BASE = "https://api.mail.tm"

def create_account():
    # Generate a random email and password
    domain_resp = requests.get(f"{API_BASE}/domains")
    domain = domain_resp.json()["hydra:member"][0]["domain"]
    username = f"user{int(time.time())}"
    email = f"{username}@{domain}"
    password = "Password123!"  # Simple password for testing

    # Create the account
    resp = requests.post(f"{API_BASE}/accounts", json={
        "address": email,
        "password": password
    })

    if resp.status_code != 201:
        print("Failed to create account:", resp.json())
        return None, None, None

    print(f"[+] Email created: {email}")
    return email, password, username


def get_token(email, password):
    resp = requests.post(f"{API_BASE}/token", json={
        "address": email,
        "password": password
    })
    if resp.status_code != 200:
        print("[-] Login failed:", resp.json())
        return None
    return resp.json()["token"]


def check_inbox(token):
    headers = {"Authorization": f"Bearer {token}"}
    print("[*] Checking inbox...")
    while True:
        resp = requests.get(f"{API_BASE}/messages", headers=headers)
        msgs = resp.json()["hydra:member"]
        if msgs:
            for msg in msgs:
                print("\n[+] New Message Received!")
                print(f"From   : {msg['from']['address']}")
                print(f"Subject: {msg['subject']}")
                print("ID     :", msg["id"])

                # Fetch full message
                msg_detail = requests.get(f"{API_BASE}/messages/{msg['id']}", headers=headers)
                content = msg_detail.json()["text"]
                print(f"Body:\n{content}")
                return
        else:
            print("[-] No messages yet. Waiting...")
        time.sleep(5)


def main():
    email, password, _ = create_account()
    if not email:
        return

    token = get_token(email, password)
    if not token:
        return

    print("[*] Email ready. Use this address to receive your OTP.")
    check_inbox(token)


if __name__ == "__main__":
    main()
