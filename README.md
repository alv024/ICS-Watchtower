# ICS Vulnerability Watchtower

A Python application for monitoring ICS (Industrial Control Systems) vulnerabilities from NIST NVD and CISA KEV feeds.

## Features

- Monitors NIST NVD API for new vulnerabilities
- Tracks CISA Known Exploited Vulnerabilities (KEV)
- Filters vulnerabilities by ICS-related keywords
- Interactive web dashboard with charts and visualizations
- Auto-refreshing data (every 5 minutes)
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

**Command-line interface:**
```bash
python src/main.py
```

**Web dashboard:**
```bash
python src/web_app.py
```
Then open http://127.0.0.1:5000 in your browser.

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
