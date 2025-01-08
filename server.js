import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import FacebookStrategy from "passport-facebook";
import GitHubStrategy from "passport-github2";
import session from "express-session";
import pgSession from "connect-pg-simple";
import {Authorization, Redirect} from "./OauthHelper.js"
import env from "dotenv";

const app = express();
const port = 3000;
env.config();

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

// Configure session 
app.use(
  session({
    store: new (pgSession(session))({
      pool: db, 
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false },
  })
);

app.set("view engine", "ejs");
app.set("views", "./views");
app.use(express.static("public"));
app.use(express.urlencoded({ extended: true }));
app.use(passport.initialize());
app.use(passport.session());


//Login Route
app.get("/", (req, res) => {
  res.render("login");
});

//Logout Route
app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

//Register Route
app.get('/signup', (req, res) => {
  res.render('register');
});

//Already have an Account Route
app.get('/loginacc', (req, res) => {
  res.render('login');
});

//Already have an Account
app.post("/login",
  passport.authenticate("local", {
    successRedirect: "/home",
    failureRedirect: "/login",
    failureFlash: true,
  })
);

//Local Redirection
app.get("/home", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("home", { user: req.user });
  } else {
    res.redirect("/login");
  }
});

app.get("/profile", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/auth/github");
  }
  res.json(req.user);
});

//Register Route
app.post("/register", async (req, res) => {
  const email = req.body.email;
  const password = req.body.password;
  const firstname = req.body.firstname;
  const lastname = req.body.lastname;

  try {
    const checkResult = await db.query("SELECT * FROM userlist WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send({ message: "Email already exists. Try logging in." });
    } else {
      bcrypt.hash(password, 10, async (err, hash) => {
        if (err) {
          console.error({ message: "Error hashing password:", err });
          res.status(500).send({ message: "Internal Server Error" });
        } else {
          await db.query(
            "INSERT INTO userlist (email, password, firstname, lastname) VALUES ($1, $2, $3, $4)",
            [email, hash, firstname, lastname]
          );
          res.render("login", { message: "Successfully Registered" });
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
  }
});

//Login Route
passport.use(
  "local",
  new LocalStrategy({ usernameField: "email" }, async (email, password, cb) => {
    try {
      const result = await db.query("SELECT * FROM userlist WHERE email = $1", [email]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const isValidPassword = await bcrypt.compare(password, user.password);

        if (isValidPassword) {
          return cb(null, user);
        } else {
          return cb(null, false, { message: "Invalid password" });
        }
      } else {
        return cb(null, false, { message: "User not found" });
      }
    } catch (err) {
      console.error("Error in LocalStrategy:", err);
      return cb(err);
    }
  })
);

//Google Authentication
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/home",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM userlist WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO userlist (email, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

//Google Redirection
app.get("/auth/google", 
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get("/auth/google/home", 
  passport.authenticate("google", {
    successRedirect: "/home",
    failureRedirect: "login",
  })
)

//Facebook Authentication
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_LOGIN_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_LOGIN_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/facebook/callback",
      profileFields: ["id", "emails", "name"],
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query(
          "SELECT id FROM userlist WHERE facebook_id = $1",
          [profile.id]
        );
        if (result.rows.length > 0) {
          return cb(null, result.rows[0]);
        } else {
          const insertResult = await db.query(
            "INSERT INTO userlist (id, email, firstname, lastname) VALUES ($1, $2, $3, $4) RETURNING id",
            [profile.id, profile.emails[0].value, profile.name.givenName, profile.name.familyName]
          );
          
          return cb(null, insertResult.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);

// Facebok Routes Redirection
app.get("/auth/facebook", passport.authenticate("facebook", { scope: ["email", "public_profile"] }));

app.get(
  "/auth/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: "/home",
    failureRedirect: "/login",
  })
);

app.get("/auth/facebook/authorize", async (req, res) => {
  return res.redirect(await Authorization());
});

app.get("/auth/facebook/redirect", async (req, res) => {
  return res.json(await Redirect(req.query.code));
});

//Github Authentication
passport.use(
  new GitHubStrategy(
    {
      clientID: process.env.GITHUB_LOGIN_CLIENT_ID,
      clientSecret: process.env.GITHUB_LOGIN_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/github/callback",
      scope: ["user:email"], 
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;

        if (!email) {
          console.error("GitHub profile does not have an email.");
          return cb(new Error("Email is required for registration."));
        }

        const result = await db.query("SELECT id FROM userlist WHERE id = $1", [profile.id]);
        if (result.rows.length > 0) {
          return cb(null, result.rows[0]);
        } else {
          const insertResult = await db.query(
            "INSERT INTO userlist (id, email) VALUES ($1, $2) RETURNING id",
            [profile.id, email]
          );
          return cb(null, insertResult.rows[0]);
        }
      } catch (err) {
        console.error("Database error:", err);
        return cb(err);
      }
    }
  )
);

//GitHub Routes Redirection
app.get("/auth/github", passport.authenticate("github", { scope: ["user:email"] }));

app.get(
  "/auth/github/callback",
  passport.authenticate("github", { failureRedirect: "/" }),
  (req, res) => {
    res.redirect("/home"); 
  }
);

// Serialization
passport.serializeUser((user, cb) => {
  cb(null, user.id);
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query(
      "SELECT id, email, firstname, lastname FROM userlist WHERE id = $1",
      [id]
    );
    if (result.rows.length > 0) {
      cb(null, result.rows[0]);
    } else {
      cb("User not found");
    }
  } catch (err) {
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});