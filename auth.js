/* =====================================================================
   RC TRADING VAULT — shared auth (browser-only accounts, for now)
   ---------------------------------------------------------------------
   Accounts are stored in this browser's localStorage, keyed by email.
   Passwords are NEVER stored in plaintext — only a salted simple hash.
   This is a simple hash, not server-grade password storage: accounts
   live only in this browser, and cloud accounts are coming later.
   The sign-in and sign-up pages say this to the member, honestly.

   Keys (do not clash with the learning-state keys in app.html):
     rcv_auth_users_v1    { email: { name, email, salt, hash, createdAt } }
     rcv_auth_session_v1  { email }  — the signed-in member, or absent

   Pages:
     signup.html / signin.html  — forms that call signUp / signIn
     app.html                   — calls requireAuth() in <head> (redirects
                                  to signin.html when signed out) and
                                  initHeader() at the end of its script
                                  (fills the member chip, wires Sign out)
   ===================================================================== */
(function (global) {
  "use strict";

  var USERS_KEY = "rcv_auth_users_v1";
  var SESSION_KEY = "rcv_auth_session_v1";
  var MIN_PASSWORD = 8;

  function loadUsers() {
    try {
      var v = localStorage.getItem(USERS_KEY);
      var o = v ? JSON.parse(v) : {};
      return o && typeof o === "object" ? o : {};
    } catch (e) {
      return {};
    }
  }

  function saveUsers(users) {
    try {
      localStorage.setItem(USERS_KEY, JSON.stringify(users));
    } catch (e) {
      /* storage full or unavailable — sign-up will report it */
    }
  }

  function normEmail(email) {
    return String(email || "").trim().toLowerCase();
  }

  function validEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email);
  }

  /* Simple synchronous hash (FNV-1a, 32-bit) over salt + password.
     Deliberately simple — see the header note. Never store plaintext. */
  function hashPassword(password, salt) {
    var h = 0x811c9dc5;
    var s = salt + "::" + String(password);
    for (var i = 0; i < s.length; i++) {
      h ^= s.charCodeAt(i);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return ("0000000" + h.toString(16)).slice(-8);
  }

  function makeSalt() {
    var chars = "abcdefghijklmnopqrstuvwxyz0123456789";
    var s = "";
    for (var i = 0; i < 16; i++) {
      s += chars[Math.floor(Math.random() * chars.length)];
    }
    return s + Date.now().toString(36);
  }

  function setSession(email) {
    try {
      localStorage.setItem(SESSION_KEY, JSON.stringify({ email: email }));
    } catch (e) {}
  }

  function getSession() {
    try {
      var v = localStorage.getItem(SESSION_KEY);
      if (!v) return null;
      var s = JSON.parse(v);
      if (!s || !s.email) return null;
      var users = loadUsers();
      var u = users[normEmail(s.email)];
      if (!u) {
        localStorage.removeItem(SESSION_KEY);
        return null;
      }
      return { email: u.email, name: u.name };
    } catch (e) {
      return null;
    }
  }

  function signUp(name, email, password) {
    name = String(name || "").trim();
    email = normEmail(email);
    password = String(password || "");
    if (!name || !email || !password) {
      return { ok: false, error: "Please fill in your name, email and password." };
    }
    if (!validEmail(email)) {
      return { ok: false, error: "That email doesn't look right — check it and try again." };
    }
    if (password.length < MIN_PASSWORD) {
      return { ok: false, error: "Password needs to be at least 8 characters." };
    }
    var users = loadUsers();
    if (users[email]) {
      return { ok: false, error: "An account with that email already exists — sign in instead." };
    }
    var salt = makeSalt();
    users[email] = {
      name: name,
      email: email,
      salt: salt,
      hash: hashPassword(password, salt),
      createdAt: new Date().toISOString()
    };
    saveUsers(users);
    setSession(email);
    return { ok: true, user: { email: email, name: name } };
  }

  function signIn(email, password) {
    email = normEmail(email);
    password = String(password || "");
    if (!email || !password) {
      return { ok: false, error: "Please enter your email and password." };
    }
    var users = loadUsers();
    var u = users[email];
    if (!u) {
      return { ok: false, error: "No account with that email yet — create one first." };
    }
    if (hashPassword(password, u.salt) !== u.hash) {
      return { ok: false, error: "Wrong password — try again." };
    }
    setSession(email);
    return { ok: true, user: { email: u.email, name: u.name } };
  }

  function signOut() {
    try {
      localStorage.removeItem(SESSION_KEY);
    } catch (e) {}
  }

  /* App gate: call in <head> of app.html. Signed-out visitors go to
     the sign-in page before any app content renders. */
  function requireAuth() {
    if (!getSession()) {
      window.location.replace("signin.html");
    }
  }

  /* Auth pages: if already signed in, go straight to the app. */
  function redirectIfSignedIn() {
    if (getSession()) {
      window.location.replace("app.html");
    }
  }

  /* App header: fill the member chip and wire the Sign out button.
     Safe to call on any page — it no-ops when the elements are absent. */
  function initHeader() {
    var user = getSession();
    var chip = document.getElementById("memberChip");
    var nameEl = document.getElementById("memberName");
    var emailEl = document.getElementById("memberEmail");
    var btn = document.getElementById("signOutBtn");
    if (user) {
      if (nameEl) nameEl.textContent = user.name;
      if (emailEl) emailEl.textContent = user.email;
      if (chip) chip.hidden = false;
    }
    if (btn) {
      btn.addEventListener("click", function () {
        signOut();
        window.location.replace("index.html");
      });
    }
  }

  global.RCVAuth = {
    getSession: getSession,
    signUp: signUp,
    signIn: signIn,
    signOut: signOut,
    requireAuth: requireAuth,
    redirectIfSignedIn: redirectIfSignedIn,
    initHeader: initHeader
  };
})(window);
