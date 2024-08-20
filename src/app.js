const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const cron = require("node-cron");
const { connectDB } = require("./config");
const routes = require("./routes");
const { Attendance, AttendanceHistory } = require("./models");

dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Connect to database
connectDB();

// Routes
app.use("/api", routes);

// Cron job for daily attendance reset
cron.schedule("0 0 * * *", async () => {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  yesterday.setHours(0, 0, 0, 0);

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  try {
    const yesterdayAttendances = await Attendance.find({
      timestamp: { $gte: yesterday, $lt: today },
    });

    await AttendanceHistory.create({
      date: yesterday,
      records: yesterdayAttendances.map((a) => a._id),
    });

    await Attendance.updateMany(
      { timestamp: { $gte: yesterday, $lt: today } },
      { $set: { isLate: false, dailyLateMinutes: 0 } }
    );

    console.log("일일 출석 초기화 완료");
  } catch (error) {
    console.error("일일 출석 초기화 중 오류 발생:", error);
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
