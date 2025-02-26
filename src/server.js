const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware and routes setup here

const PORT = process.env.PORT || 1269;
server.listen(PORT, () => console.log(`Server running on port ${PORT}`));