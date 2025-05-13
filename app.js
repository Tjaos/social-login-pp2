require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const { PrismaClient } = require("./generated/prisma");

const prisma = new PrismaClient();

const app = express();
app.set("view engine", "ejs");
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      const email = profile.emails[0].value;
      const googleId = profile.id;
      const name = profile.displayName;

      try {
        // Verifica se já existe
        let user = await prisma.user.findUnique({
          where: { email },
        });

        // Se não existir, cria
        if (!user) {
          const role = email.endsWith("@cesar.school") ? "admin" : "user";
          user = await prisma.user.create({
            data: {
              googleId,
              name,
              email,
              role,
            },
          });
        }

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Middleware para checar se está logado
function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Middleware para admin
function isAdmin(req, res, next) {
  if (req.user.role === "admin") return next();
  res.send("Acesso negado: apenas administradores.");
}

// Rotas
app.get("/", (req, res) => res.redirect("/dashboard"));

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/dashboard", isLoggedIn, (req, res) => {
  res.render("dashboard", { user: req.user });
});

app.get("/manage-users", isLoggedIn, isAdmin, (req, res) => {
  res.render("manage_users", { user: req.user });
});

app.get("/logout", (req, res) => {
  req.logout(() => res.redirect("/login"));
});

// Google Auth
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login" }),
  (req, res) => res.redirect("/dashboard")
);

app.listen(3000, () =>
  console.log("Servidor rodando em http://localhost:3000")
);
