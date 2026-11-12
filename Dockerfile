# CDLSHS FeedTrack — Docker image for Render Web Service
# Runs feedtrack-server.ps1 on PowerShell (Linux)
FROM mcr.microsoft.com/powershell:latest

WORKDIR /app

# Copy only non-secret files (server.json + auth state are added at runtime)
COPY code2.html .
COPY feedtrack-server.ps1 .

# Render provides $PORT; we bind to 0.0.0.0:$PORT
ENV PORT=8765
EXPOSE 8765

# Start the server; Render injects PORT automatically
CMD ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "feedtrack-server.ps1"]