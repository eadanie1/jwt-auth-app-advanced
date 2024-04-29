# Node.js JWT Authentication

This is a more advanced example of JWT (JSON Web Tokens) authentication implemented in a Node.js environment using Express.js.

## Features

- User authentication with username and password
- JSON Web Tokens (JWT) for token-based authentication
- Access to protected routes using JWT
- Token refresh mechanism
- Error handling middleware for consistent error responses
- Role based accessed to restricted portals

## Prerequisites

Before running the application, make sure you have the following installed:

- Node.js
- npm (Node Package Manager)

## Installation

1. Clone the repository:

   ```bash
   git clone https://https://github.com/eadanie1/jwt-auth-app-advanced
   ```

2. Navigate to the project directory:

   ```bash
   cd jwt-auth-app-advanced
   ```

3. Install dependencies:

   ```bash
   npm install
   ```

4. Create a `.env` file in the root directory and add the following environment variables:

   ```plaintext
   ACCESS_TOKEN_SECRET=your_access_token_secret
   REFRESH_TOKEN_SECRET=your_refresh_token_secret
   USER_ADMIN_PASSWORD_x5=user1_password
   USER_EDITOR_PASSWORD_x6=user2_password
   USER_VIEWER_PASSWORD_x7=user3_password
   USER_VIEWER_PASSWORD_x8=user4_password
   ```

   Replace `your_access_token_secret` and `your_refresh_token_secret` with your own secrets.

5. Start the servers in separate terminals, respectively:

   ```bash
   npm run devstart
   ```

   ```bash
   npm run devstart-auth
   ```

## Usage

The servers will start running on `http://localhost:3000`and `http://localhost:4000`.

### Endpoints

1. **Login**:

   - Endpoint: `/login`
   - Method: POST
   - Request Body: `{ "username": "your_username", "password": "your_password" }`
   - Response: Returns access token and refresh token upon successful authentication, and also stores the user data such as role in the encoded JWT token.

2. **Token Refresh**:

   - Endpoint: `/token`
   - Method: POST
   - Request Body: `{ "token": "your_refresh_token" }`
   - Response: Returns a new access token.

3. **Logout**:

   - Endpoint: `/logout`
   - Method: DELETE
   - Request Body: `{ "token": "your_refresh_token" }`
   - Response: Invalidates the refresh token.

4. **Get Posts**:

   - Endpoint: `/posts`
   - Method: GET
   - Requires authentication with access token.
   - Response: Returns posts for the authenticated user.

5. **Get 'user-role-based'-portals**:
   - Endpoint: `/admin-portal, /editor-portal, and /viewer-portal`
   - Method: GET
   - Requires authentication with access token, and to validate user role.
   - Response: Returns posts for the authenticated user.

### Error Handling

- Custom error handling middleware is implemented to handle various types of errors and return appropriate HTTP status codes and error messages.

## Contributing

Contributions are welcome! Feel free to open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
