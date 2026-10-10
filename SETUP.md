# Project Setup Guide

Follow these steps in order. Everyone on the team should complete all of this before writing any module code.

## 1\. Install Python

- Version: **Python 3.12**  
- Download: [https\://www\.python.org/downloads/](https://www.python.org/downloads/)  
- **Windows users:** check "Add Python to PATH" on the first installer screen.  
- Verify:  
    
  python \--version

## 2\. Install VS Code

- Download: [https\://code.visualstudio.com/](https://code.visualstudio.com/)  
- Install these extensions (Extensions tab, `Ctrl+Shift+X`):  
  - **Python** (Microsoft)  
  - **Pylance** (usually bundled with Python extension)  
  - **GitLens**  

## 3\. Install Git and set up GitHub

- Download Git: [https\://git-scm.com/downloads](https://git-scm.com/downloads)  
- Verify:  
    
  git \--version  
    
- Create a GitHub account if you don't have one.  
- Get added as a collaborator on the repo (repo owner: Settings → Collaborators).  
- First-time config:  
    
  git config \--global user.name "Your Name"  
    
  git config \--global user.email "your@email.com"  
    
- Clone the repo:  
    
  git clone \<repo-url\>  
    
  cd \<repo-folder\>

## 4\. Set up the Python virtual environment

Run inside the cloned repo folder:

\# create virtual environment

python \-m venv venv

\# activate it

venv\\Scripts\\activate        \# Windows

source venv/bin/activate     \# Mac/Linux

\# install dependencies

pip install \-r requirements.txt

Run this every time you start working — you'll need to re-activate `venv` each new terminal session.

## 5\. Core Python packages

These belong in `requirements.txt` at the repo root:

requests

httpx

beautifulsoup4

fastapi

uvicorn

python-dotenv

ollama

## 6\. Install sqlmap

Not a pip package — install separately.

| OS | Command |
| :---- | :---- |
| Linux (Debian/Ubuntu/Kali) | `sudo apt install sqlmap` |
| Mac | `brew install sqlmap` |
| Windows / any OS fallback | `git clone https://github.com/sqlmapproject/sqlmap.git` then run via `python sqlmap/sqlmap.py` |

Verify:

sqlmap \--version

## 7\. Install Ollama

1. Download and install Ollama for Windows: https://ollama.com/download/windows .  
2. Open PowerShell or the VS Code terminal and download the model:  
     
   ollama pull qwen2.5:7b-instruct 
     
3. **Make sure `.env` is listed in `.gitignore` before your first commit.** This file must never be pushed to GitHub, even on a private repo. Each person should use their own key locally, or the team shares one key through a private channel outside of git.

## 8\. Final sanity check

Run this after completing all the steps above. All three commands should run without errors:

python \-c "import requests, httpx, bs4, fastapi; print('OK')"

sqlmap \--version

git status

If this passes on your machine, you're ready to start building.

## Troubleshooting

- If anyone's environment breaks mid-project, they can delete the `venv` folder and redo step 4\.  
- If a new person joins or a grader wants to run the project, this file alone should get them from a fresh machine to a working setup in about 10 minutes.
