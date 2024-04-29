import { generateAccessToken, generateRefreshToken } from '../authServer.js';

describe('generateAccessToken', () => {
  test('should generate an access token', () => {
    const user = { username: 'testuser', id: '123' };
    const token = generateAccessToken(user);
    expect(token).toBeDefined();
  });
});

describe('generateRefreshToken', () => {
  test('should generate a refresh token', () => {
    const user = { username: 'testuser', id: '123' };
    const token = generateRefreshToken(user);
    expect(token).toBeDefined();
  });
});