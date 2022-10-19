/** User class for message.ly */

/** User of the site. */

const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");

const { BCRYPT_WORK_FACTOR } = require("../config");

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const result = db.query(
      `
      INSERT INTO users (username, password, first_name, last_name, phone)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING username, password, first_name, last_name, phone
    `,
      [username, hashedPassword, first_name, last_name, phone]
    );
    return result.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    let result = await db.query(
      `
      SELECT password
      FROM users
      WHERE username=$1
    `,
      [username]
    );
    let user = result.rows[0];
    return user && (await bcrypt.compare(password, user.password));
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    let result = await db.query(
      `
      UPDATE users
      SET last_login_at = current_timestamp
      WHERE username=$1
      RETURNING last_login_at
    `,
      [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError("Username Not Found", 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    let result = await db.query(
      `
      SELECT username, first_name, last_name, phone
      FROM users
      RETURNING username, first_name, last_name, phone
    `
    );
    return result.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    let result = await db.query(
      `
    SELECT *
    FROM users
    WHERE username=$1
    `,
      [username]
    );
    let user = result.rows[0];
    if (!user) {
      throw new ExpressError(`User: ${username} not found.`, 404);
    }
    return user;
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    let result = await db.query(
      `
      SELECT *
      FROM messages AS m
      FULL JOIN users AS u
      ON m.to_username=u.username;
      WHERE from_username=$1
    `,
      [username]
    );
    return result.rows.map((m) => ({
      id: m.id,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    let result = await db.query(
      `
      SELECT *
      FROM messages AS m
      FULL JOIN users AS u
      ON m.from_username=u.username;
      WHERE to_username=$1
    `,
      [username]
    );
    return result.rows.map((m) => ({
      id: m.id,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
    }));
  }
}

module.exports = User;
