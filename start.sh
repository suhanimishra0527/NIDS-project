#!/bin/bash
# Render Start Script - Dashboard Only Mode
# This starts the Flask dashboard WITHOUT live packet capture

cd dashboard
gunicorn app:app --bind 0.0.0.0:$PORT
