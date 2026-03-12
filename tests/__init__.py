# Create a project directory
mkdir -p ~/sqli-tool && cd ~/sqli-tool

# Create a docker-compose file for DVWA
cat > docker-compose.yml << 'EOF'
version: '3'
services:
  dvwa:
    image: vulnerables/web-dvwa
    ports:
      - "8080:80"
    restart: unless-stopped
EOF

# Launch DVWA
docker-compose up -d