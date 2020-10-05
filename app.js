/* write your server code here */
const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

app.use(express.json());

let users = [
  {
    email: "admin@email.com",
    name: "admin",
    password: '$2b$10$ZkwWGWl2E53SI3CnxEbp7ubM79oGR3wUa.Ijt2F7hHOMqLdVA.kgG',
    isAdmin: true,
  },
];
let information = [{
    user: 'admin',
    info: 'admin info'
}];
let refreshTokens = [];

app.post("/users/register", async (req, res) => {
  if (users.some((user) => user.email === req.body.email)) {
    return res.status(409).json("user already exists");
  }
  const { email, name, password } = req.body;
  const newUser = {
    email,
    name,
    password: await bcrypt.hash(password, 10),
    isAdmin: false,
  };
  users.push(newUser);
  information.push({
    user: name,
    info: `${name} info`,
  });

  res.status(201).json({ message: "Register Success" });
});

app.post("/users/login", async (req, res) => {
  const user = users.find((user) => user.email === req.body.email);
  if (!user) {
    return res.status(404).send("cannot find user");
  } else if (!(await bcrypt.compare(req.body.password, user.password))) {
    return res.status(403).send("User or Password incorrect");
  } else {
    const accessToken = jwt.sign(
      { user: user.name, isAdmin: user.isAdmin },
      "access_key",
      {
        expiresIn: "30s",
      }
    );
    const refreshToken = jwt.sign(
      { user: user.name, isAdmin: user.isAdmin },
      "refresh_key"
    );
    refreshTokens.push(refreshToken);
    res.status(200).json({
      accessToken,
      refreshToken,
      userName: user.name,
      isAdmin: user.isAdmin,
    });
  }
});

app.post("/users/tokenValidate", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  if (bearerHeader) {
    const token = bearerHeader.slice(7);
    jwt.verify(token, "access_key", (error, decoded) => {
      if (error) {
        res.status(403).send("Invalid Access Token");
      } else {
        res.status(200).json({ valid: true });
      }
    });
  } else {
    res.status(401).send("Access Token Required");
  }
});

app.get("/api/v1/information", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  if (bearerHeader) {
    const token = bearerHeader.slice(7);
    console.log(token);
    jwt.verify(token, "access_key", (error, decoded) => {
      if (error) {
        res.status(403).send("Invalid Access Token");
      } else {
        if (decoded.isAdmin) {
            res.status(200).json(information);
        } else {
            const userInfo = information.find((info) => info.user === decoded.user);
            res.status(200).json([userInfo]);
        }
      }
    });
  } else {
    res.status(401).send("Access Token Required");
  }
});

app.post("/users/token", (req, res) => {
  const { token } = req.body;
  if (token) {
    jwt.verify(token, "refresh_key", (error, decoded) => {
      if (error) {
        res.status(403).send("Invalid Refresh Token");
      } else if (
        !refreshTokens.some((refreshToken) => token === refreshToken)
      ) {
        res.status(403).send("Invalid Refresh Token");
      } else {
        const accessToken = jwt.sign({ user: decoded.user, isAdmin: decoded.isAdmin }, "access_key", {
              expiresIn: "30s",
            }
          );
          console.log(accessToken);
        res.status(200).json({accessToken});
      }
    });
  } else {
    res.status(401).send("Refresh Token Required");
  }
});

app.post("/users/logout", (req, res) => {
  const { token } = req.body;
  if (token) {
    jwt.verify(token, "refresh_key", (error, decoded) => {
      if (error) {
        res.status(400).send("Invalid Refresh Token");
      } else if (
        !refreshTokens.some((refreshToken) => token === refreshToken)
      ) {
        res.status(400).send("Invalid Refresh Token");
      } else {
        refreshTokens.filter((refreshToken) => refreshToken !== token);
        res.status(200).json({ message: "User Logged Out Successfully" });
      }
    });
  } else {
    res.status(400).send("Refresh Token Required");
  }
});

app.get("/api/v1/users", (req, res) => {
  const bearerHeader = req.headers["authorization"];
  if (bearerHeader) {
    const token = bearerHeader.slice(7);
    jwt.verify(token, "access_key", (error, decoded) => {
      if (error) {
        res.status(403).send("Invalid Access Token");
      } else if (decoded.isAdmin === false) {
        res.status(403).send("Invalid Access Token");
      } else {
        res.status(200).json(users);
      }
    });
  } else {
    res.status(401).send("Access Token Required");
  }
});

module.exports = app;
