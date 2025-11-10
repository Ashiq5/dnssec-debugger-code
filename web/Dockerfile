# Use an official lightweight Python base image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /data/ErroneousZoneGeneration

# Install dependencies first (better caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy the rest of your FastAPI app
COPY . .

# Expose the port your FastAPI runs on
EXPOSE 8000

# Default command to start Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
