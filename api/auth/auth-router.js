const router = require("express").Router()
const User = require("../users/users-model")
const bcrypt = require("bcryptjs")
const {
  checkUsernameFree,
  checkPasswordLength,
  checkUsernameExists,
} = require("./auth-middleware")

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }
  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }
  response on username taken:
  status 422
  {
    "message": "Username taken"
  }
  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post(
  "/register",
  checkUsernameFree,
  checkPasswordLength,
  async (req, res, next) => {
    try {
      const { username, password } = req.body
      const hash = bcrypt.hashSync(password, 8)

      const newUser = { username, password: hash }

      const insertedUser = await User.add(newUser)
      res.status(200).json(insertedUser)
    } catch (err) {
      next(err)
    }
  }
)

/**
 2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

 response:
 status 200
 {
   "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
  */

router.post("/login", checkUsernameExists, (req, res, next) => {
  try {
    req.session.user = req.user
    next({ status: 200, message: `Welcome ${req.user.username}!` })
  } catch (err) {
    next("error", err)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
  */
router.get("/logout", (req, res, next) => {
  if (req.session.user) {
    req.session.destroy((err) => {
      if (err) {
        res.json({
          message: "Sorry could you retry",
        })
      } else {
        next({ message: "logged out" })
      }
    })
  } else {
    next({ message: "no session" })
  }
})

// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router
