import { use, serializeUser, deserializeUser } from 'passport';
import { Strategy as LocalStrategy } from 'passport-local';

import { query } from '../database';
import { matchPassword, encryptPassword } from './helpers';

use('local.signin', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {
  const rows = await query('SELECT * FROM users WHERE username = ?', [username]);
  if (rows.length > 0) {
    const user = rows[0];
    const validPassword = await matchPassword(password, user.password)
    if (validPassword) {
      done(null, user, req.flash('success', 'Welcome ' + user.username));
    } else {
      done(null, false, req.flash('message', 'Incorrect Password'));
    }
  } else {
    return done(null, false, req.flash('message', 'The Username does not exists.'));
  }
}));

use('local.signup', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {

  const { fullname } = req.body;
  let newUser = {
    fullname,
    username,
    password
  };
  newUser.password = await encryptPassword(password);
  // Saving in the Database
  const result = await query('INSERT INTO users SET ? ', newUser);
  newUser.id = result.insertId;
  return done(null, newUser);
}));

serializeUser((user, done) => {
  done(null, user.id);
});

deserializeUser(async (id, done) => {
  const rows = await query('SELECT * FROM users WHERE id = ?', [id]);
  done(null, rows[0]);
});

