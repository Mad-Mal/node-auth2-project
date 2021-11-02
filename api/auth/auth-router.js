const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const Users = require('../users/users-model.js');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;

  const rounds = process.env.BCRYPT_ROUNDS || 8;
  const hash = bcrypt.hashSync(user.password, rounds)

  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json({ message: `Great to have you, ${user.username}` })
    })
    .catch(
      next()
      )
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  
  try {
    const options = {
      expiresIn: '1d',
    }

    const payload = {
      subject: req.params.user_id,
      username: req.params.username,
      role_name: req.params.role_name,
    }

    const token = jwt.sign(payload, JWT_SECRET, options)

    console.log('this is the token value from post /login', token)
    
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token: token,
    })

  } catch (error) {
    next(error)
  }
});

module.exports = router;
