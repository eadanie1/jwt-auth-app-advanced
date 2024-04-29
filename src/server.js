import express from 'express';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { tryCatch } from './global-logic/tryCatch.js';
import { errorHandler } from './global-logic/errorHandler.js';
import mongoose from 'mongoose';
import { User, Post, Admin, Editor, Viewer } from './models.js';
const app = express();
dotenv.config();
app.use(express.json());

mongoose.connect('mongodb://localhost/jwt-auth-app-adv')
  .then(() => console.log('Connected to MongoDB...'))
  .catch(err => console.error('Unable to connect to MongoDB', err));

function verifyToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.sendStatus(401);
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    } else {
      req.user = user;
      next();
    }
  });
}

function verifyUserRole(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) {
      return res.sendStatus(403);
    }
    const userRole = user.role;
    const requestedRole = req.path.substring(1).replace('-portal', '');

    if ((userRole === requestedRole ||
      userRole === 'admin' || userRole === 'editor') &&
      !(userRole === 'editor' && requestedRole === 'admin')) {
      next();
    } else {
      return res.status(403).json({ message: 'Access denied, user lacks required permissions' });
    }
  });
}

app.get(
  '/posts',
  verifyToken,
  tryCatch(async (req, res) => {
    const posts = await Post
    .find({})
    return res.json(posts);
  })
);

app.get(
  '/users',
  tryCatch(async (req, res) => {
    const users = await User
    .find({})
    return res.json(users);
  })
);

app.get(
  '/admin-portal',
  verifyUserRole,
  tryCatch(async (req, res) => {
    const adminPage = await Admin
      .find({})
    return res.json(adminPage);
  })
);

app.get(
  '/editor-portal',
  verifyUserRole,
  tryCatch(async (req, res) => {
    const editorPage = await Editor
    .find({})
    return res.json(editorPage);
  })
);

app.get(
  '/viewer-portal',
  verifyUserRole,
  tryCatch(async (req, res) => {
    const viewerPage = await Viewer
      .find({})
    return res.json(viewerPage);
  })
);

app.use(errorHandler);

app.listen(3000, () => {
  console.log('Listening on port 3000');
});