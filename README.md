# CyberSentinel-Backend

## Backend Initialization       

### Manual Setup Steps

1. Create and enter the backend workspace
`mkdir backend`
`cd backend`

2. Initialize Node.js (Creates package.json)
`npm init -y`

3. Install Production Dependencies
`npm install express mongoose cors dotenv`

4. Install Developer Dependencies (for auto-restart)
`npm install --save-dev nodemon`

5. Create the server file (PowerShell)
`New-Item server.js`


## Running the Server

### For Development (Recommended)

This uses nodemon to automatically restart the server when you save a file. Make sure you are inside the backend folder first!

`npx nodemon server.js`

### For Production / Standard Run

`node server.js`