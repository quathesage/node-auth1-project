const Users = require("../users/users-model")
const bcrypt = require("bcryptjs")
/*
  If the user does not have a session saved in the server

  status 401
  {
    "message": "You shall not pass!"
  }
*/
function restricted(req, res, next) {
  if (req.session.user) {
    next()
  } else {
    next({
      status: 401,
      message: "You shall not pass",
    })
  }
}

/*
  If the username in req.body already exists in the database

  status 422
  {
    "message": "Username taken"
  }
*/
async function checkUsernameFree(req, res, next) {
  const [username] = await Users.findBy({ username: req.body.username })
  if (username !== undefined) {
    next({ status: 422, message: "Username taken" })
  } else {
    next()
  }
}

/*
  If the username in req.body does NOT exist in the database
  status 401
  {
    "message": "Invalid credentials"
  }
*/
async function checkUsernameExists(req, res, next) {
  const { username, password } = req.body
  const [existing] = await Users.findBy({ username })

  if (existing && bcrypt.compareSync(password, existing.password)) {
    req.user = existing
    next()
  } else {
    next({ status: 401, message: "Invalid credentials" })
  }
}

/*
  If password is missing from req.body, or if it's 3 chars or shorter
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
*/
function checkPasswordLength(req, res, next) {
  if (!req.body.password || req.body.password.length <= 3) {
    next({ status: 422, message: "Password must be longer than 3 chars" })
  } else {
    next()
  }
}

module.exports = {
  checkPasswordLength,
  checkUsernameExists,
  checkUsernameFree,
  restricted,
}
