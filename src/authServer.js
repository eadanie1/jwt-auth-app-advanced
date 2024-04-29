import express from 'express';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
import { tryCatch } from './global-logic/tryCatch.js';
import mongoose from 'mongoose';
import { User, Refresh_Token } from './models.js';
const app = express();
dotenv.config();
app.use(express.json());

mongoose.connect('mongodb://localhost/jwt-auth-app-adv')
  .then(() => console.log('Connected to MongoDB...'))
  .catch(err => console.error('Unable to connect to MongoDB', err));

async function hashPasswords() {
  const users = await User.find();

  for (const user of users) {
      const hashedPassword = await bcrypt.hash(user.password, 10);
      user.password = hashedPassword;
      await user.save();
  }
  console.log('Passwords hashed successfully');
}
// passwords hashed per above
// hashPasswords().then();

export function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5m' });
}

export function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET, { expiresIn: '10m' });
}

app.post(
  '/login', 
  tryCatch(async (req, res) => {
    const { username, password } = req.body;
    const matchedUser = await User
      .findOne({username});

    if (!matchedUser) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    const isPasswordCorrect = await bcrypt.compare(password, matchedUser.password);

    if (isPasswordCorrect) {
      const user = { 
        username: matchedUser.username, 
        id: matchedUser.id, 
        role: matchedUser.role 
      };
      const accessToken = generateAccessToken(user);
      const refreshToken = generateRefreshToken(user);
      console.log(refreshToken);

      const newToken = new Refresh_Token({ refreshToken });
      const savedToken = await newToken.save();
      console.log('Token stored successfully:', savedToken);

      return res.status(200).json({ accessToken, refreshToken });
    } else {
      return res.status(401).json({ message: 'Invalid username or password' });
    }
}));

app.post(
  '/token', 
  tryCatch(async (req, res) => {
    const refreshToken = req.body.token;
    if (refreshToken === null) return res.sendStatus(401);

    const foundRefreshToken = await Refresh_Token
      .findOne({refreshToken});
    
    if (!foundRefreshToken) return res.status(403).json({message: 'Token not found in database'});
    
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
      if (err) {
        return res.sendStatus(403);
      } else {
        const { username, id, role } = user;
        const accessToken = generateAccessToken({ username, id, role });
        return res.json({ accessToken });
      }
    })
  })
);

app.delete(
  '/logout', 
  tryCatch(async (req, res) => {
    const refreshToken = req.body.token;
    const foundRefreshToken = await Refresh_Token
      .findOneAndDelete({refreshToken});
    
    if (foundRefreshToken) {
      return res.sendStatus(204);
    } else {
      return res.status(403).json({message: 'Token not found in database'});
    }
}));

app.listen(4000, () => {
  console.log('Listening on port 4000');
});