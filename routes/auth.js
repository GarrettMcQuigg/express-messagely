const { Router } = require("express");
const User = require("../models/user");
const router = new Router();
const jwt = require("jsonWebtoken");
const ExpressError = require("../expressError");
const { SECRET_KEY } = require("../config");

/** POST /login - login: {username, password} => {token}
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (await User.authenticate(username, password)) {
      let token = jwt.sign({ username }, SECRET_KEY);
      User.updateLoginTimestamp(username);
      return res.json({ token });
    } else {
      throw new ExpressError("Incorrect username/password", 400);
    }
  } catch (e) {
    return next(e);
  }
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 */

router.post("/register", async (req, res, next) => {
  try {
    const { username } = await User.register(req.body);

    let token = jwt.sign({ username }, SECRET_KEY);
    User.updateLoginTimestamp(username);
    return res.json({ token });
  } catch (e) {
    return next(e);
  }
});

module.exports = router;
