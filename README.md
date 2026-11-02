# SafePass

A web app that checks whether a password has appeared in a known data
breach, without ever sending the password anywhere.

**Live demo:**  https://austin100m.github.io/Safe-pass/

## Features
- Breach check using the Have I Been Pwned API
- Password strength meter
- Secure random password generator

## Tech used
Claude AI, HTML, CSS, JavaScript, Have I Been Pwned API, Git, GitHub Pages, VS Code

## How it works
1. The password is hashed (SHA-1) in the browser.
2. Only the first 5 characters of the hash are sent to the API (k-anonymity).
3. The API returns matching hashes, and the final comparison is done locally.

## Security measures
- Password never sent or stored
- Content Security Policy
- `textContent` instead of `innerHTML` to prevent XSS
- `crypto.getRandomValues` for secure generation

## Run locally
Open `index.html` in a browser or use VS Code's Live Server.

## What I learned
- Using a public API with fetch and async/await
- Applying basic web security practices
- Version control and deployment with Git and GitHub

Special thanks to Claude AI
