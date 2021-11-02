const User = require('../users/users-model.js');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

const restricted = (req, res, next) => {
  const token = req.headers.authorization
  if(!token){
    res.status(401).json({ message: 'Token required'})
  } else {
    jwt.verify(token, JWT_SECRET, (error, decoded) => {
      if(error) {
        res.status(401).json('Token invalid', error.message)
      } else {
        req.decodedToken = decoded;
        next();
      }
    })
  }
}

const only = role_name => (req, res, next) => {
  if(!req.decodedToken.role_name === role_name){
    res.status(403).json({ message: 'This is not for you'})
  } else {
    next();
  }
}


const checkUsernameExists = async (req, res, next) => {
  try {
    const [user] = await User.findBy({ username: req.body.username });
      if(!user) {
        res.status(401).json({ message: 'Invalid credentials'})
      } else {
        req.user = user;
        next();
      }
    }
    catch (error) {
      next(error);
    }
  }


const validateRoleName = (req, res, next) => {
  const roleName = req.body.role_name ? req.body.role_name.trim() : ""

  if (roleName === 'admin') {
    return res.status(422).json({
      message: "Role name can not be admin",
    })
  } else if (roleName.length > 32) {
    return res.status(422).json({
      message: "Role name can not be longer than 32 chars",
    })
  } else if (roleName === "") {
    req.role_name = 'student'
  } else {
    req.role_name = roleName
  }
  next();
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
