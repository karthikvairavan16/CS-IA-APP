# Put IA Project online: follow these steps in order

Use **Railway** for the Python website and a **persistent Railway volume** for its SQLite database. The volume is online storage that survives app restarts and redeploys. You do not need MySQL or a separate database service. The old Vercel link will still show 404; the new app link will be the Railway link.

You need your GitHub account, a Railway account, and access to the Google Cloud project you already used for local Google sign-in. Never put passwords, Google client secrets, or encryption keys in GitHub or a chat.

## Part A: Send the latest code to GitHub

1. Open **PowerShell** in `C:\Users\Student\Documents\IA.APP`, the folder containing `app.py`.
2. Paste this command and press Enter:

   ```powershell
   git add app.py START_HERE.md DEPLOY_ONLINE.md Dockerfile requirements.txt .dockerignore
   ```

3. Paste this command and press Enter:

   ```powershell
   git commit -m "Prepare IA Project for Railway"
   ```

4. Paste this command and press Enter:

   ```powershell
   git push origin main
   ```

5. Open your GitHub repository. Check that `Dockerfile` and `requirements.txt` are visible beside `app.py`. If Git says your branch is not `main`, run `git branch --show-current` and push the branch name it prints.

## Part B: Create the online Python service

6. Go to [railway.com](https://railway.com/), sign in, and connect GitHub when asked. Give Railway access to this repository.
7. In Railway, click **New Project** > **Deploy from GitHub repo**. Select the IA Project repository. If offered **Add Variables** or **Deploy Now**, choose **Deploy Now**. This first deployment may fail until you finish the settings below.
8. Click the new service box. Open **Settings** > **Networking** > **Generate Domain**. Copy its complete URL, for example `https://ia-project-production.up.railway.app`. Write this down as `YOUR_RAILWAY_URL`. Use your actual URL in every later step.
9. Return to the project canvas. Right-click an empty area and choose **New Volume** (or press `Ctrl+K` and search for **volume**). Connect the volume to your Python service. Set **Mount Path** to exactly `/data`, then save. Keep the service at one replica.

## Part C: Get Google sign-in credentials

10. Go to [Google Cloud Console](https://console.cloud.google.com/). At the top, select the **same project** you used for local Google sign-in. Open **Google Auth platform** > **Clients**.
11. If you can access an existing **Web application** client ID and secret, use them. Otherwise, click **Create Client**, select **Web application**, give it a name such as `IA Project Railway`, and create it in the same Google Cloud project. Copy the **Client ID** and **Client secret** into a private note. They will go into Railway, not GitHub.
12. Open that Web application client. Under **Authorized redirect URIs**, click **Add URI** and enter `YOUR_RAILWAY_URL/auth/callback`. Example: `https://ia-project-production.up.railway.app/auth/callback`. Under **Authorized JavaScript origins**, you can add `YOUR_RAILWAY_URL` without `/auth/callback`. Click **Save**. The URL must match your Railway domain exactly.
13. In **Google Auth platform** > **Audience**, find **Test users**. Add the exact Google email address you will use to sign in. Click **Save**. This prevents the Google `403 access_denied` error while the app is in Testing. Keep the Gmail API enabled in this Cloud project.

## Part D: Add Railway settings

14. Return to Railway. Click your Python service, then **Variables** > **New Variable**. Add these four variables one at a time:

   | Name | Value |
   | --- | --- |
   | `APP_ORIGIN` | Your complete Railway URL, with **no** trailing `/` |
   | `GOOGLE_CLIENT_ID` | The Client ID copied from Google Cloud |
   | `GOOGLE_CLIENT_SECRET` | The Client secret copied from Google Cloud |
   | `TOKEN_ENCRYPTION_KEY` | A new key generated in step 15 |

15. To generate the last value, paste this into PowerShell on your computer:

   ```powershell
   python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
   ```

   Copy the single line it prints into Railway's `TOKEN_ENCRYPTION_KEY` value. Keep a private copy of the exact key. Changing or losing it makes saved Google connections unreadable. **Do not** add `PORT` or `RAILWAY_VOLUME_MOUNT_PATH`; Railway provides them.
16. Railway collects changes before applying them. Click **Deploy** or **Apply changes** when prompted. In the service's **Deployments** tab, wait for the newest deployment to say **Success**. If it fails, click it and read **Runtime Logs**; the first error usually names a missing setting.

## Part E: Test the website

17. Open `YOUR_RAILWAY_URL/healthz` in a browser. You should see `{"ok": true}`.
18. Open `YOUR_RAILWAY_URL` without `/healthz`. The sign-up page should load even if your laptop's `python app.py` process is stopped.
19. Sign up with the Google account added under **Test users**. The online app starts with an empty database, so make a new profile. Refresh the inbox, save one rule, sign out, and sign back in. The rule should remain. Your local Windows database and Google tokens are not automatically copied online.

## If a step fails

- **404 on the Vercel link:** Open the new Railway URL instead.
- **Railway deployment fails:** Confirm the volume is attached at `/data` and all four variables are present. Read the newest deployment's **Runtime Logs**.
- **Google says `redirect_uri_mismatch`:** Compare the Google Cloud redirect URI with your Railway URL plus `/auth/callback`, character for character.
- **Google says `403 access_denied`:** Add the exact sign-in email under **Audience** > **Test users**.
- **App opens but sign-in fails:** Confirm the client ID and secret came from the same Web application client.

The app checks for new mail every 30 seconds while the dashboard is open. Keep one Railway replica for this SQLite setup. Configure [Railway volume backups](https://docs.railway.com/volumes/backups) after the app works. Google may require verification before people outside approved test users can use Gmail access.

Sources: [Railway quick start](https://docs.railway.com/quick-start), [volumes](https://docs.railway.com/volumes), [variables](https://docs.railway.com/variables), [Google web OAuth](https://developers.google.com/identity/protocols/oauth2/web-server), [Google test users](https://developers.google.com/workspace/guides/configure-oauth-consent).
