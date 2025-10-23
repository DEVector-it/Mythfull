# Study Buddy AI

Study Buddy AI is a Flask-powered student assistant that showcases the Myth Full beta plans. It serves a landing page with interactive chat and image generation workbenches and exposes JSON endpoints for the application UI.

## Features
- Myth Max, GOAT Myth, and Legendary Myth Full beta plan catalog
- Chat endpoint that demonstrates enhanced responses for each plan tier
- Image Lab endpoint that returns a base64-encoded PNG study card
- Publishing guidance API that lists cloud platforms suitable for deployment
- Health check endpoint used by Render (`/api/status`)

## Run Study Buddy AI locally

> 💡 **Quick start:** `bash scripts/run_local.sh`

1. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
3. Launch the development server with the helper script (sets the proper `FLASK_APP` and debug defaults):
   ```bash
   bash scripts/run_local.sh
   ```
4. Visit [http://localhost:5000](http://localhost:5000) to see the UI.

### Verify the APIs are running

Once the server is up, you can exercise the endpoints with the bundled beta key:

```bash
curl -H "X-StudyBuddy-Key: AIzaSyDe9DZANR3BiUFX-w1Ol7Rnkh_GHU8k-5w" \
  http://localhost:5000/api/status

curl -H "X-StudyBuddy-Key: AIzaSyDe9DZANR3BiUFX-w1Ol7Rnkh_GHU8k-5w" \
  -H "Content-Type: application/json" \
  -d '{"question": "How can I prepare for finals?", "plan": "goat-myth"}' \
  http://localhost:5000/api/chat

curl -H "X-StudyBuddy-Key: AIzaSyDe9DZANR3BiUFX-w1Ol7Rnkh_GHU8k-5w" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Create a biology revision poster", "plan": "myth-full-legend"}' \
  http://localhost:5000/api/image
```

The responses confirm that the Study Buddy AI chat, status, and image services are live.

## Deployment
This project includes a `render.yaml` spec so the app can be deployed directly from a GitHub repository to [Render](https://render.com/).

1. Push this repository to GitHub (see the next section for detailed commands).
2. In Render, create a new **Web Service** from the GitHub repo.
3. Use the provided build (`pip install -r requirements.txt`) and start (`gunicorn "app:app"`) commands.
4. Set any environment variables in the Render dashboard.

Render will call `/api/status` to confirm the service is healthy.

## Publishing the project to GitHub

If you have not already created a GitHub repository for Study Buddy AI, follow these steps:

1. [Create an empty repository on GitHub](https://github.com/new) (without a README, `.gitignore`, or license).
2. In your local project directory, initialize Git and add the GitHub remote:
   ```bash
   git init
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   ```
3. Commit the project files:
   ```bash
   git add .
   git commit -m "Initial commit"
   ```
4. Push the repository to GitHub:
   ```bash
   git push -u origin main
   ```

If your repository already exists, replace step 2 with `git remote set-url origin` to point at the correct GitHub URL before pushing.

### Publishing from an existing Render service

If you are already running Study Buddy AI on Render and need to push the live code to GitHub:

1. Open your Render service dashboard and click **Shell** to launch a terminal for the deployed instance.
2. From the shell, clone or initialize the project directory if it is not already a Git repository:
   ```bash
   cd /opt/render/project/src
   git init
   git remote add origin https://github.com/<your-username>/<your-repo>.git
   ```
3. Stage and commit the Render-managed files:
   ```bash
   git add .
   git commit -m "Import Render deployment"
   ```
4. Push the commit to GitHub (Render instances already include Git):
   ```bash
   git push -u origin main
   ```
5. Back in Render, switch the service to the **GitHub** tab and connect it to the repository so future deploys track the code in Git.

## License
Study Buddy AI © 2024. All rights reserved.
