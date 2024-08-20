const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI);
    console.log("MongoDB connected");
  } catch (err) {
    console.error("MongoDB connection error:", err);
    process.exit(1);
  }
};

const constants = {
  ATTENDANCE_HOUR: 8,
  ATTENDANCE_MINUTE: 3,
};

module.exports = {
  connectDB,
  constants,
};
