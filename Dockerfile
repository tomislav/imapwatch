# Use Python 3.10 as requested
FROM python:3.10-slim

# Send Python output straight to terminal without buffering
ENV PYTHONUNBUFFERED=1

# Create and set the working directory
WORKDIR /app

# Copy the entire project folder into the container
COPY . /app/

# Install the required Python package
RUN pip install --no-cache-dir lockfile PyYAML python-daemon imapclient boto3

# Create the required log directory
RUN mkdir -p /app/log

# Default command to run the script
# CMD ["python3", "imapwatch", "-vDEBUG", "start"]
CMD ["python3", "imapwatch", "start"]
