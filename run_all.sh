#!/usr/bin/env bash
# Run both parts of the merged project (Oversecured + Hacknova) using Docker Compose
# This script assumes Docker and Docker Compose are installed.

PROJECT_DIR=$(cd "$(dirname "$0")" && pwd)

echo "Starting the merged project from $PROJECT_DIR"
cd "$PROJECT_DIR"

docker compose up -d --build

if [ $? -eq 0 ]; then
  echo "✅ Services are up and running."
  echo "- Oversecured backend: http://localhost:5000"
  echo "- Hacknova UI:          http://localhost:3000"
else
  echo "❌ Failed to start services. Check docker compose logs."
fi
