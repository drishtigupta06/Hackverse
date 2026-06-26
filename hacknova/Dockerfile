FROM node:20-alpine

WORKDIR /app

# Copy only the frontend source
COPY hacknova_ps-main/frontend ./frontend

WORKDIR /app/frontend

# Install frontend dependencies
RUN npm install --silent

# Expose the Vite dev server port
EXPOSE 3000

# Start the Vite dev server
CMD ["npm", "run", "dev"]
