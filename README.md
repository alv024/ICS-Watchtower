# ICS Vulnerability Watchtower

A Python application for monitoring ICS (Industrial Control Systems) vulnerabilities from NIST NVD and CISA KEV feeds.

## Features

- Monitors NIST NVD API for new vulnerabilities
- Tracks CISA Known Exploited Vulnerabilities (KEV)
- Filters vulnerabilities by ICS-related keywords
- Configurable check intervals

## Setup

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Copy `.env.example` to `.env` and fill in your Telegram bot credentials:
```bash
cp .env.example .env
```

3. Run the application:
```bash
python -m src.main
```

## Configuration

Edit `src/config.py` to customize:
- API endpoints
- ICS keywords
- Check intervals

## Testing

Run tests with:
```bash
python -m pytest tests/
```

## License

MIT
