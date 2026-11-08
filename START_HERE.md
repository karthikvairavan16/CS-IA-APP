# IA Project setup and current behavior

For deployment on a public HTTPS URL with a persistent online SQLite database, follow [DEPLOY_ONLINE.md](DEPLOY_ONLINE.md). The steps below also document local development.

## 1. Run locally

Use Windows and Python 3.11 or newer. In a PowerShell terminal in this folder:

```powershell
python app.py
```

Open **http://localhost:8000**. Keep the terminal open. Press Ctrl+C to stop. The signup screen opens by default. Google signup becomes available after the following setup. Always use `localhost`, rather than switching between it and `127.0.0.1`, so your sign-in cookie and callback stay on the same hostname.

## 2. Create your Google Cloud project

1. Open [Google Cloud Console](https://console.cloud.google.com/). Sign in with the account you will use to own the project.
2. Use the project selector at the top to create a project, for example **IA Project IA**. Select it.
3. Open **APIs & Services → Library**, find **Gmail API**, and enable it.
4. Open **Google Auth Platform**. Complete its initial setup / branding: app name **IA Project**, support email, and developer contact email. Console menu names may vary.
5. Under **Audience**, choose **External** if using a personal Google account. Keep the application in **Testing**. Add the exact Gmail address you will connect as a **test user**. A school Workspace project can use Internal when the organization permits it; your administrator may restrict Gmail access.
6. Under **Data Access**, add these scopes:
   - `openid`
   - `https://www.googleapis.com/auth/userinfo.email`
   - `https://www.googleapis.com/auth/userinfo.profile`
   - `https://www.googleapis.com/auth/gmail.modify`
7. Under **Clients**, create an **OAuth client ID** with application type **Web application**. Name it **IA Project local**.
8. Add this **Authorized JavaScript origin**:
   `http://localhost:8000`
9. Add this exact **Authorized redirect URI**:
   `http://localhost:8000/auth/callback`
10. Save. Keep the client ID and client secret on your own machine. Do not paste the secret into chat, source code, Git, or your IA screenshots.

`gmail.modify` is needed for your requested Gmail labels and read/unread changes. It is broader than read-only access; the app implements reading, replies, label creation/application, stars, read status changes and moving messages to Trash. Google classifies Gmail modify as a restricted scope. Testing and public publication have different requirements; a public app can need restricted-scope verification and additional review. See [Google's Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes) and [restricted-scope verification](https://developers.google.com/identity/protocols/oauth2/production-readiness/restricted-scope-verification).

## 3. Save your OAuth client locally

In another PowerShell terminal in this folder, run:

```powershell
python app.py --configure
```

Paste the client ID when asked. Paste the client secret at the hidden prompt and press Enter; it will not be printed. The configuration is encrypted using the current Windows account and saved in `private_data/google.json`. You do not need to create this file yourself. Reload the app page after configuring. Restart the server after any code changes.

## 4. Connect your actual Gmail account

1. Open http://localhost:8000.
2. Leave **Sign up** selected and click **Sign up with Google**.
3. Select the Gmail account you added as a test user.
4. Review Google's consent screen and grant Gmail access if you want to proceed. If Google or your school blocks access, resolve the test-user or admin configuration; the app cannot bypass a blocked consent screen.
5. Google sends you back to IA Project. Choose a username and a **new app password of at least 12 characters**. This is not your Google password.
6. Open the dashboard. The first synchronization fetches up to 100 inbox emails and can take a minute or more. Later synchronizations use Gmail history to fetch changed messages.
7. Sign in later with Google or your IA Project username and app password. A successful Google sign-in allows changing a forgotten app password in Settings for ten minutes without the old app password. The verification is consumed when credentials are changed.

In Google's External/Testing mode, refresh tokens for Gmail commonly expire after seven days. Reconnect Google from Settings when prompted. Password changes, revoked access, and organizational policies can also require reconnecting. See [Google OAuth token expiration](https://developers.google.com/identity/protocols/oauth2#expiration) and [web-server OAuth](https://developers.google.com/identity/protocols/oauth2/web-server).


## Inbox and priority

The inbox opens with newest messages first. Use Sort to switch to Rule priority. The latest 100 Inbox messages are synchronized every 30 seconds while the page is open; browser timer throttling can delay background updates. Archived mail, Spam and messages beyond these 100 are not included. OTP emails that arrive in Inbox are included, summarized, and available through the OTP codes filter. Search also scans email bodies.

Priority is now strictly based on enabled custom rules. No keyword category or deadline automatically adds points. Each matching rule contributes its configured points once; negative scores have a floor of zero. Messages with no matching rules are Unprioritized. Notifications are generated only by rules with Notify enabled. Categories and summaries never change priority scores, including Ads.

Each email is summarized by extracting relevant sentences and assigned an app-only category: OTP & verification, Ads, Account & security, School & assessments, Meetings & events, Updates, or General. Select a category to filter the inbox. Categories use deterministic text patterns and can be imperfect. They do not create Gmail labels. OTP values are not separately stored or copied into notifications.

## Rules and labels

My rules supports subject text, body text, subject-or-body text, exact sender address, and exact sender domain. Matches ignore case. Choose positive or negative points, enable notifications, pause a rule, edit it, or delete it. A sender domain such as school.edu matches that exact domain. Subject/body matches are phrase containment.

The Gmail label dropdown and Load labels button show your account's custom labels. Create label creates a real Gmail label immediately. Saving an enabled label rule applies it to matching cached inbox messages at the next refresh. Label rules are optional. Pausing/deleting a rule does not undo previously applied Gmail labels.

## Reading and message actions

Open a card for its summary and score reasons. Read original email opens a focused text reader. Email HTML is never executed; tracking images and attachments are not downloaded. Open in Gmail is available for the full visual email and attachments.

Inside the reader:

- Reply loads the actual Reply-To address (or From address when absent), shows it, and opens a text composer. Nothing is sent until Send reply is clicked. Replies use the original Gmail thread ID and email reply headers.
- Gmail labels loads existing custom labels, then lets you apply or remove a selected label.
- Star / Unstar updates the message's actual Gmail star.
- Move to Trash asks for confirmation and moves the actual message to Gmail Trash. Restore it through Gmail if needed; the app does not permanently delete messages.

These actions use the already-requested gmail.modify permission. If Google reports insufficient permissions, reconnect your account from Settings and grant the configured scope. Sending failures are shown in the reader and the reply text remains available. If an interrupted send has an uncertain outcome, check Gmail Sent before sending again.

## Account controls

Click the top-right profile avatar for Settings or Sign out. The theme switch animates between black and white and respects reduced-motion preferences. Password fields have Show/Hide buttons. New passwords require 12?200 characters, uppercase and lowercase letters, a number and a symbol. Existing passwords still work for sign-in. Usernames accept 1?60 visible characters, including spaces and Unicode. Availability is checked as you type and rechecked on save.

## Local storage and limits

Run this Windows edition from a normal terminal. SQLite stores profiles, cached email text, rules, notifications and server-side sessions in private_data/staffroom.db. Email text is not encrypted. Google client credentials and tokens use Windows DPAPI; passwords use salted scrypt hashes. Keep private_data out of shared repositories. Disconnect revokes Google access and clears cached messages/notifications while preserving your profile/rules and Gmail data. Sign-out ends the session.

This is a local development server bound to localhost, not a public hosting stack. No external Python packages or MySQL installation are needed. All application code is in app.py and views.py; HTML, CSS and JavaScript are embedded inside views.py.

## Checks

Run python -m unittest -v for isolated automated checks using temporary databases and fake Google responses. The suite includes rule-only priority, OTP classification, OAuth, user isolation, labels, reply threading, stars, Trash and credential handling. Windows encryption may be unavailable inside an execution sandbox and must be checked in a normal Windows terminal. Tests do not connect to or modify an actual mailbox. Visual browser QA and live account actions have not been verified here.

## Message navigation and cleanup

View email in Notifications opens that exact message in the reader. If it is outside the current 100-message cache, it is fetched by its Gmail message ID using the connected account.

Manage mail offers a preview for exact sender email or a topic phrase using Gmail search. It searches received mailbox messages beyond the inbox cache, excluding Trash, Spam, Sent and Drafts. Review up to 500 matches per batch. Confirming moves only the previewed message IDs to Gmail Trash. More matches can be handled by previewing another batch. Preview tokens expire after 15 minutes and belong to your signed-in app account. Partial failures report progress; preview again to continue. Restore messages through Gmail if needed.

Blocked senders uses a persistent Gmail auto-Trash filter, not rejection of incoming SMTP delivery. Future matching messages go to Trash even with IA Project closed; existing messages are unchanged. Choose Enable Google permission for Gmail filters in Manage mail and reconnect to grant gmail.settings.basic. Add this scope under Google Auth Platform > Data Access if needed. The existing gmail.modify permission still handles mailbox operations. Show blocked senders lists filters created through this app; Unblock removes that filter without restoring previous Trash messages. Filters created by other tools are not managed here. Google filters persist after disconnecting IA Project; remove them in the app before disconnecting or in Gmail settings afterward.

## Algorithms and IA authorship

The app does not call an AI model. Custom-rule matching, weighted score aggregation, sorting, regular-expression category detection, deadline parsing and extractive sentence ranking are deterministic Python algorithms. Gmail supplies mailbox data and executes mail operations; Gmail search and filters are Google services. The app interface uses embedded HTML/CSS/JavaScript.

No implementation guarantees an IA grade. Use your assessment cohort's rubric with your teacher: establish a real client problem, measurable success criteria, explain your data model and algorithms, record your own design/development decisions, demonstrate edge-case tests and obtain client feedback for evaluation. This code was developed with AI assistance; acknowledge assistance and sources in the form your school requires, and do not present generated code as entirely your own independent work. Make sure you can explain and justify every submitted component.

## Sender panel and interface updates

The blocked-sender panel loads automatically when Manage mail opens. It verifies app-created sender filters against Gmail, shows simple sender auto-Trash filters created in Gmail, and provides address search and active/inactive/unverified states. Native Gmail Block sender entries are not exposed by the Gmail filters API; manage that separate list in Gmail settings. Missing filter permissions and network failures are shown in the panel; saved records remain visible. Inactive app records can be removed, then the sender can be blocked again. External Gmail filters link to Gmail settings for editing.

The reader includes Manage sender and read/unread controls. Manage sender pre-fills the blocking and cleanup address fields. Inbox filters have a Clear filters button; / focuses inbox search. Search focus survives background refresh. Reply text is saved only in this browser tab's session storage while you type and is restored when you reopen Reply for that same message. Sending successfully clears that saved draft. It is not a Gmail draft and is cleared on sign-out or when the browser tab session ends.

All visible branding is IA Project. Existing database and cookie identifiers are retained internally so existing accounts and rules continue to work. Google Cloud consent-screen branding is configured separately in your Cloud project.
