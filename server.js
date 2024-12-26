import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import mysql from "mysql2";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { configDotenv } from "dotenv";
import { rateLimit } from "express-rate-limit";

const app = express();
// const { rateLimit } = expressRateLimiter;
configDotenv();

app.use(cors());
app.use(bodyParser.json({ limit: "5mb" }));
app.use(bodyParser.urlencoded({ extended: true }));

const pool = mysql.createPool({
  host: process.env.HOST,
  user: process.env.USER,
  password: process.env.PASSWORD,
  database: process.env.DATABASE,
});

const db = pool.promise();
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

const auth = (req, res, next) => {
  try {
    const { token } = req.headers;

    if (!token) {
      return res.status(401).json({ message: "Token Required for authentication" });
    }

    const decoded = jwt.verify(token, process.env.SECRET_KEY);

    next();
  } catch (err) {
    if (err.name === "JsonWebTokenError") {
      console.log("Invalid Signature");
      return res.status(400).json({ message: "Invalid Token" });
    } else if (err.name === "TokenExpiredError") {
      console.log("Token Expired");
      return res.status(401).json({ message: "Token Expired" });
    } else {
      console.log(err);
      return res.status(500).json({ message: "Internal Server Error" });
    }
  }
};

app.post("/create-token", async (req, res) => {
  try {
    const { password, name, email, application } = req.body;
    if (!password || !name || !email || !application) {
      return res
        .status(400)
        .json({ message: "Fields required: password, name, email, application" });
    }

    const expectedPassword = process.env.HASHED_PASSWORD;
    if (bcrypt.compareSync(password, expectedPassword)) {
      const token = jwt.sign(
        { data: { name, email, application, password: expectedPassword } },
        process.env.SECRET_KEY
      );
      return res
        .status(200)
        .json({ token: `BEARER ${token}`, message: "Token generated successfully" });
    }

    res.status(403).json({ message: "Incorrect Password" });

    // if(password)
  } catch (error) {
    console.log(error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/countries", auth, async (req, res) => {
  try {
    const { name, id, search } = req.query;
    let result;
    if (name) {
      [result] = await db.query(
        "SELECT id, name, iso3, iso2, phonecode, capital, currency, currency_name, currency_symbol, region, region_id, subregion, subregion_id, nationality, latitude, longitude  FROM countries WHERE name = ?",
        [name]
      );
    } else if (id) {
      [result] = await db.query(
        "SELECT id, name, iso3, iso2, phonecode, capital, currency, currency_name, currency_symbol, region, region_id, subregion, subregion_id, nationality, latitude, longitude  FROM countries WHERE id = ?",
        [id]
      );
    } else if (search) {
      [result] = await db.query(
        "SELECT id, name, iso3, iso2, phonecode, capital, currency, currency_name, currency_symbol, region, region_id, subregion, subregion_id, nationality, latitude, longitude  FROM countries WHERE name LIKE ?",
        [`%${search}%`]
      );
    } else {
      [result] = await db.query(
        "SELECT id, name, iso2, phonecode, latitude, longitude  FROM countries"
      );
    }
    res.status(200).json({ data: result });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
});

app.get("/states", auth, async (req, res) => {
  try {
    const { name, id, country_id, search } = req.query;
    let result;
    if (country_id && search) {
      [result] = await db.query(
        "SELECT id, name, country_id, latitude, longitude FROM states WHERE country_id = ? AND name LIKE ?",
        [country_id, `%${search}%`]
      );
    } else if (name) {
      [result] = await db.query(
        "SELECT id, name, country_id, latitude, longitude FROM states WHERE name = ?",
        [name]
      );
    } else if (id) {
      [result] = await db.query(
        "SELECT id, name, country_id, latitude, longitude FROM states WHERE id = ?",
        [parseInt(id)]
      );
    } else if (country_id) {
      [result] = await db.query(
        "SELECT id, name, country_id, latitude, longitude FROM states WHERE country_id = ?",
        [parseInt(country_id)]
      );
    } else if (search) {
      [result] = await db.query(
        "SELECT id, name, country_id, latitude, longitude FROM states WHERE name LIKE ?",
        [`%${search}%`]
      );
    } else {
      [result] = await db.query("SELECT id, name, country_id, latitude, longitude FROM states");
    }
    res.status(200).json({ data: result });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
});

app.get("/cities", auth, async (req, res) => {
  try {
    const { name, id, state_id, search } = req.query;
    let result;
    console.log(state_id, search);
    if (state_id && search) {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities WHERE state_id = ? AND name LIKE ?",
        [state_id, `%${search}%`]
      );
    } else if (name) {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities WHERE name = ?",
        [name]
      );
    } else if (id) {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities WHERE id = ?",
        [parseInt(id)]
      );
    } else if (state_id) {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities WHERE state_id = ?",
        [parseInt(state_id)]
      );
    } else if (search) {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities WHERE name LIKE ?",
        [`%${search}%`]
      );
    } else {
      [result] = await db.query(
        "SELECT id, name, state_id, country_id, latitude, longitude FROM cities limit 1000"
      );
      return res.status(206).json({ result, message: "It Gives only 1000 rows" });
    }
    res.status(200).json({ data: result });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "Internal Server Error", error: err });
  }
});

app.get("/posts", auth, async (req, res) => {});

app.listen(process.env.PORT, (err) => {
  if (err) console.log(err);
  else console.log(`Server running at ${process.env.PORT}`);
});
