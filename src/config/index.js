const dotenv = require("dotenv");
dotenv.config();

module.exports = {
  MONGODB_URI: process.env.MONGODB_URI,
  JWT_SECRET: process.env.JWT_SECRET,
  ENCRYPTION_KEY: process.env.ENCRYPTION_KEY,
  PORT: process.env.PORT || 5000,
  ATTENDANCE_HOUR: 8,
  ATTENDANCE_MINUTE: 3,
};
