'use strict'

const Router = require('express').Router
const passport = require('passport')
var GoogleStrategy = require('passport-google-oauth20').Strategy
const config = require('../../../config')
const { setReturnToFromReferer, passportGeneralCallback } = require('../utils')

const googleAuth = module.exports = Router()

function googleCallback(accessToken, refreshToken, profile, done) {
  const allowedDomains = config.google.allowedDomains;
  // Check if allowedDomains is a string, we can have list in config.json file
  // and comma seperate domains in environment while using docker
  if (typeof(allowedDomains) === "string") {
    allowedDomains = allowedDomains.split(",");
  }

  // making sure that allowedDomainds is array
  if (allowedDomains === null) {
      allowedDomains = [];
  }

  if (allowedDomains.length && allowedDomains.indexOf(profile._json.hd) === -1) {
    return done('Domain not allowed', null);
  }
  return passportGeneralCallback(accessToken, refreshToken, profile, done);
}

passport.use(new GoogleStrategy({
  clientID: config.google.clientID,
  clientSecret: config.google.clientSecret,
  callbackURL: config.serverURL + '/auth/google/callback',
  userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
}, googleCallback));

googleAuth.get('/auth/google', function (req, res, next) {
  setReturnToFromReferer(req);
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});

// google auth callback
googleAuth.get('/auth/google/callback',
  passport.authenticate('google', {
    successReturnToOrRedirect: config.serverURL + '/',
    failureRedirect: config.serverURL + '/'
  })
);
