FROM python:3.11-slim

WORKDIR /app

# Copy Oversecured source
COPY Oversecured-main/ /app/

# Install Python dependencies if present
RUN if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi && pip install uiautomator2 frida

# Expose default scanner port (adjust if your script uses a different one)
EXPOSE 5000

# Default command – runs the main scanner script (adjust if needed)
CMD ["python","scanner.py"]
