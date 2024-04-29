import jwt from 'jsonwebtoken';
const { JsonWebTokenError, NotBeforeError, TokenExpiredError } = jwt;

export const errorHandler = (error, req, res, next) => {
  console.error(error);

  if (error.name === 'UnauthorizedError') {
    return res.status(401).json({
      error: 'UnauthorizedError',
      details: error.details
    });
  }

  if (error instanceof jwt.JsonWebTokenError) {
    return res.status(401).json({ 
      error: 'Unauthorized', 
      message: 'Invalid token' 
    });
  }  

  if (error instanceof jwt.TokenExpiredError) {
    return res.status(401).json({ 
      error: 'Unauthorized', 
      message: 'Token expired' 
    });
  } 
  
  if (error instanceof jwt.NotBeforeError) {
    return res.status(401).json({ 
      error: 'Unauthorized', 
      message: 'Token not yet valid' 
    });
  } 
  
  // if (error instanceof AuthenticationError) {
  //   return res.status(401).json({ 
  //     error: 'Unauthorized', 
  //     message: 'Authentication failed' 
  //   });
  // } 
  return res.status(500).send('Unexpected error occured');
};