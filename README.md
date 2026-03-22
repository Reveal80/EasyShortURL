# Easy Short URL

A simple, self-hosted URL shortener with authentication, security features, and Docker support.

---

## Overview

Easy Short URL is a lightweight web application designed to shorten URLs and manage them through a secure admin panel.  
It is built with simplicity in mind and can be deployed quickly using Docker.

---

## Features

- URL shortening system
- Admin authentication
- Password protected access
- Login protection with IP blocking
- Docker-based deployment
- Minimal and easy-to-understand architecture

---

## Default Credentials

The application includes a default administrator account:

- Username: `admin`
- Password: `EasyShort2026`

> It is strongly recommended to change the password after the first login.

To update the password, refer to the `PASSWORD.md` file.

---

## Deployment

### Requirements

- Docker
- Docker Compose

### Run the application

```bash
docker-compose up -d
```

Once started, access the application via your browser.

---

## Project Structure

```
.
├── apache/                # Apache configuration
├── public/                # Web application
│   ├── data/              # Runtime data (logs, URLs, attempts)
│   └── .env               # Environment configuration
├── docker-compose.yml     # Deployment configuration
└── README.md
```

---

## Configuration

Application settings are defined in:

```
public/.env
```

Example:

```
APP_USER=admin
APP_PASSWORD=hashed_password
```

> Do not expose this file in production environments.

---

## Security

- Passwords are stored using bcrypt hashing
- Login attempts are limited (IP blocking after multiple failures)
- `.env` is protected via `.htaccess`

---

## Best Practices

- Change default credentials immediately
- Do not commit `.env` with real credentials
- Exclude runtime files (logs, json data) from version control
- Use strong passwords (minimum 12 characters)

---

## Roadmap

- Custom domains support
- API for automation
- Improved user interface
- Advanced analytics

---

## License

This project is provided as-is for educational and personal use.

---

## Author

Developed by Manu
