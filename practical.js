const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express()
app.use(express.json())

mongoose.connect("mongodb://127.0.0.1:27017/studentPortal")

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
})

const User = mongoose.model("User", userSchema)

const SECRET = "mysecretkey"

const auth = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1]
  if (!token) return res.status(401).json({ msg: "No token" })
  try {
    const decoded = jwt.verify(token, SECRET)
    req.user = await User.findById(decoded.id).select("-password")
    next()
  } catch {
    res.status(401).json({ msg: "Invalid token" })
  }
}

app.post("/registerUser", async (req, res) => {
  try {
    const { name, email, password } = req.body
    const hashed = await bcrypt.hash(password, 10)
    const user = await User.create({ name, email, password: hashed })
    res.json({ id: user._id, email: user.email })
  } catch {
    res.status(400).json({ msg: "User exists" })
  }
})

app.post("/login", async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email })
  if (!user) return res.status(400).json({ msg: "Invalid credentials" })

  const match = await bcrypt.compare(password, user.password)
  if (!match) return res.status(400).json({ msg: "Invalid credentials" })

  const token = jwt.sign({ id: user._id }, SECRET, { expiresIn: "1d" })
  res.json({ token })
})

app.get("/profile", auth, async (req, res) => {
  res.json(req.user)
})

app.post("/logout", async (req, res) => {
  res.json({ msg: "Logged out" })
})

app.listen(5000)