const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const crypto = require("crypto");
const cron = require("node-cron");
dotenv.config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.error("MongoDB connection error:", err));

// User model
const UserSchema = new mongoose.Schema({
  studentId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  grade: { type: Number, required: true, enum: [1, 2, 3] },
  class: { type: Number, required: true, min: 1, max: 6 },
  number: { type: Number, required: true, min: 1, max: 100 },
  isAdmin: { type: Boolean, default: false },
  isReader: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);

// Attendance model
const AttendanceSchema = new mongoose.Schema({
  studentId: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  isLate: { type: Boolean, default: false },
  lateMinutes: { type: Number, default: 0 },
});

const Attendance = mongoose.model("Attendance", AttendanceSchema);

const ATTENDANCE_HOUR = 8;
const ATTENDANCE_MINUTE = 1;

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader) {
    return res
      .status(401)
      .json({ success: false, message: "Authorization 헤더가 없습니다." });
  }

  const [bearer, token] = authHeader.split(" ");

  if (bearer !== "Bearer" || !token) {
    return res
      .status(401)
      .json({ success: false, message: "잘못된 토큰 형식입니다." });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token verification error:", error);

    if (error.name === "TokenExpiredError") {
      return res
        .status(401)
        .json({ success: false, message: "토큰이 만료되었습니다." });
    }

    res
      .status(401)
      .json({ success: false, message: "유효하지 않은 토큰입니다." });
  }
};

// Middleware to check if user is admin
const isAdmin = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isAdmin) {
      return res.status(403).json({ message: "관리자 권한이 필요합니다." });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

// Middleware to check if user is reader
const isReader = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isReader && !user.isAdmin) {
      return res.status(403).json({ message: "리더 권한이 필요합니다." });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

// Routes
app.post("/api/signup", async (req, res) => {
  try {
    const {
      studentId,
      name,
      password,
      grade,
      class: classNumber,
      number,
    } = req.body;

    let user = await User.findOne({ studentId });
    if (user) {
      return res.status(400).json({ message: "이미 존재하는 학번입니다." });
    }

    const gradeNum = Number(grade);
    if (![1, 2, 3].includes(gradeNum)) {
      return res.status(400).json({ message: "유효하지 않은 학년입니다." });
    }

    const classNum = Number(classNumber);
    const numberNum = Number(number);

    if (classNum < 1 || classNum > 6) {
      return res.status(400).json({ message: "유효하지 않은 반입니다." });
    }
    if (numberNum < 1 || numberNum > 100) {
      return res.status(400).json({ message: "유효하지 않은 번호입니다." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({
      studentId,
      name,
      password: hashedPassword,
      grade: gradeNum,
      class: classNum,
      number: numberNum,
    });

    await user.save();

    res.status(201).json({
      message: "회원가입이 완료되었습니다. 관리자의 승인을 기다려주세요.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { studentId, password } = req.body;

    const user = await User.findOne({ studentId });
    if (!user) {
      return res.status(400).json({ message: "존재하지 않는 학번입니다." });
    }

    if (!user.isApproved) {
      return res
        .status(400)
        .json({ message: "관리자의 승인을 기다리고 있습니다." });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "비밀번호가 일치하지 않습니다." });
    }

    const token = jwt.sign(
      { id: user._id, isAdmin: user.isAdmin, isReader: user.isReader },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({
      token,
      user: {
        id: user._id,
        studentId: user.studentId,
        name: user.name,
        isAdmin: user.isAdmin,
        isReader: user.isReader,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/change-password", verifyToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id);
    if (!user) {
      return res.status(400).json({ message: "사용자를 찾을 수 없습니다." });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);
    if (!isMatch) {
      return res
        .status(400)
        .json({ message: "현재 비밀번호가 일치하지 않습니다." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    res.json({ message: "비밀번호가 성공적으로 변경되었습니다." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// Admin routes
app.get("/api/admin/pending-users", verifyToken, isAdmin, async (req, res) => {
  try {
    const pendingUsers = await User.find({ isApproved: false });
    res.json(pendingUsers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/admin/approve-user", verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId, isApproved } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    user.isApproved = isApproved;
    await user.save();
    res.json({ message: "사용자 승인 상태가 업데이트되었습니다." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/admin/set-admin", verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId, isAdmin } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    user.isAdmin = isAdmin;
    await user.save();
    res.json({ message: "사용자의 관리자 권한이 변경되었습니다." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/admin/set-reader", verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId, isReader } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }
    user.isReader = isReader;
    await user.save();
    res.json({ message: "사용자의 리더 권한이 변경되었습니다." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// Record attendance route
app.post("/api/attendance", verifyToken, isReader, async (req, res) => {
  try {
    const { encryptedData } = req.body;
    const [ivHex, encryptedHex] = encryptedData.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(process.env.ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    const [studentId, timestamp] = decrypted.split("|");
    const scanTime = parseInt(timestamp);
    const currentTime = Math.floor(Date.now() / 30000);
    if (Math.abs(currentTime - scanTime) > 1) {
      return res.status(400).json({ message: "QR 코드가 만료되었습니다." });
    }

    const student = await User.findOne({ studentId });
    if (!student) {
      return res.status(404).json({ message: "학생을 찾을 수 없습니다." });
    }
    if (!student.isApproved) {
      return res.status(400).json({ message: "승인되지 않은 학생입니다." });
    }

    const now = new Date();
    console.log(`현재 시간: ${now.toISOString()}`);

    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    console.log(`오늘 날짜: ${today.toISOString()}`);

    // 같은 날 중복 출석 확인
    const existingAttendance = await Attendance.findOne({
      studentId,
      timestamp: { $gte: today },
    });
    if (existingAttendance) {
      console.log(`중복 출석 시도: ${studentId}`);
      return res.status(400).json({ message: "이미 오늘 출석했습니다." });
    }

    const attendanceTime = new Date(today);
    attendanceTime.setHours(ATTENDANCE_HOUR, ATTENDANCE_MINUTE, 0, 0);
    console.log(`출석 기준 시간: ${attendanceTime.toISOString()}`);

    const isLate = now > attendanceTime;
    const lateMinutes = isLate ? Math.floor((now - attendanceTime) / 60000) : 0;

    console.log(`지각 여부: ${isLate}, 지각 시간: ${lateMinutes}분`);

    const attendance = new Attendance({
      studentId,
      timestamp: now,
      isLate,
      lateMinutes,
    });

    await attendance.save();

    console.log(
      `출석 기록: 학생 ID ${studentId}, 시간 ${now.toISOString()}, 지각 여부 ${isLate}, 지각 시간 ${lateMinutes}분`
    );

    const responseMessage = isLate
      ? `출석이 기록되었습니다. ${lateMinutes}분 지각입니다.`
      : "출석이 성공적으로 기록되었습니다.";

    res.status(201).json({
      message: responseMessage,
      isLate,
      lateMinutes,
    });
  } catch (error) {
    console.error("출석 기록 중 오류 발생:", error);
    res
      .status(500)
      .json({ message: "서버 오류가 발생했습니다.", error: error.message });
  }
});

// ATTENDANCE_HOUR와 ATTENDANCE_MINUTE 변수 확인
console.log(`출석 기준 시간: ${ATTENDANCE_HOUR}시 ${ATTENDANCE_MINUTE}분`);

// 대시보드 API 엔드포인트 수정
app.get("/api/dashboard", verifyToken, isAdmin, async (req, res) => {
  try {
    const { grade, class: classNumber, period } = req.query;
    let startDate, endDate;

    // 기간 설정
    const now = new Date();
    switch (period) {
      case "day":
        startDate = new Date(now.setHours(0, 0, 0, 0));
        endDate = new Date(now.setHours(23, 59, 59, 999));
        break;
      case "week":
        startDate = new Date(now.setDate(now.getDate() - now.getDay()));
        endDate = new Date(now.setDate(now.getDate() - now.getDay() + 6));
        break;
      case "month":
        startDate = new Date(now.getFullYear(), now.getMonth(), 1);
        endDate = new Date(now.getFullYear(), now.getMonth() + 1, 0);
        break;
      case "semester":
        // 학기 시작일과 종료일을 적절히 설정해야 합니다
        startDate = new Date(now.getFullYear(), 2, 1); // 3월 1일로 가정
        endDate = new Date(now.getFullYear(), 7, 31); // 8월 31일로 가정
        break;
      default:
        startDate = new Date(0);
        endDate = new Date();
    }

    // 사용자 쿼리
    const userQuery = {};
    if (grade) userQuery.grade = Number(grade);
    if (classNumber) userQuery.class = Number(classNumber);

    const users = await User.find(userQuery)
      .sort({ grade: 1, class: 1, number: 1 }) // number로 정렬 추가
      .lean();

    // 출석 기록 조회 (AttendanceHistory 포함)
    const attendanceRecords = await Attendance.find({
      studentId: { $in: users.map((user) => user.studentId) },
      timestamp: { $gte: startDate, $lte: endDate },
    }).lean();

    const attendanceHistory = await AttendanceHistory.find({
      date: { $gte: startDate, $lte: endDate },
    })
      .populate("records")
      .lean();

    // 출석 데이터 처리
    const attendanceData = users.map((user) => {
      const userAttendance = attendanceRecords.filter(
        (record) => record.studentId === user.studentId
      );
      const userHistoryAttendance = attendanceHistory.flatMap((history) =>
        history.records.filter((record) => record.studentId === user.studentId)
      );

      const allUserAttendance = [...userAttendance, ...userHistoryAttendance];

      const totalAttendance = allUserAttendance.length;
      const lateAttendance = allUserAttendance.filter(
        (record) => record.isLate
      ).length;
      const totalLateMinutes = allUserAttendance.reduce(
        (sum, record) => sum + (record.lateMinutes || 0),
        0
      );

      // lastAttendanceTime이 유효한 값인지 확인
      let lastAttendanceTime = null;
      if (allUserAttendance.length > 0) {
        const latestAttendance = allUserAttendance.reduce((latest, current) =>
          latest.timestamp > current.timestamp ? latest : current
        );
        lastAttendanceTime = latestAttendance.timestamp
          ? latestAttendance.timestamp.toISOString()
          : null;
      }

      return {
        name: user.name,
        studentId: user.studentId,
        grade: user.grade,
        class: user.class,
        number: user.number, // 실제 번호 추가
        totalAttendance,
        lateAttendance,
        totalLateMinutes,
        lastAttendanceTime,
        attendanceRate: (
          (totalAttendance / getWorkingDays(startDate, endDate)) *
          100
        ).toFixed(2),
        lateRate:
          totalAttendance > 0
            ? ((lateAttendance / totalAttendance) * 100).toFixed(2)
            : 0,
      };
    });
    // 전체 통계 계산
    const overallStats = calculateOverallStats(
      attendanceData,
      startDate,
      endDate
    );
    res.json({
      attendanceData,
      overallStats,
      period: { startDate, endDate },
    });
  } catch (error) {
    console.error("대시보드 데이터 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// Get attendance records route
app.get("/api/attendance", verifyToken, isAdmin, async (req, res) => {
  try {
    const attendanceRecords = await Attendance.find().sort({ timestamp: -1 });
    res.json(attendanceRecords);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// Get student info route
app.get("/api/student-info", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }
    res.json({ success: true, studentId: user.studentId, name: user.name });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ success: false, message: "서버 오류가 발생했습니다." });
  }
});

// Generate QR code data route
app.post("/api/generate-qr", verifyToken, async (req, res) => {
  try {
    const { studentId, timestamp } = req.body;
    const user = await User.findOne({ studentId });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }

    const qrData = `${studentId}|${timestamp}`;

    if (
      !process.env.ENCRYPTION_KEY ||
      process.env.ENCRYPTION_KEY.length !== 32
    ) {
      throw new Error("유효하지 않은 암호화 키");
    }

    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(
      "aes-256-cbc",
      Buffer.from(process.env.ENCRYPTION_KEY),
      iv
    );
    let encryptedData = cipher.update(qrData, "utf8", "hex");
    encryptedData += cipher.final("hex");

    const result = iv.toString("hex") + ":" + encryptedData;

    res.json({ success: true, encryptedData: result });
  } catch (error) {
    console.error("QR 코드 생성 오류:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다: " + error.message,
    });
  }
});

// Logout route
app.post("/api/logout", verifyToken, (req, res) => {
  res.json({ success: true, message: "로그아웃되었습니다." });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

app.get("/api/admin/users", verifyToken, isAdmin, async (req, res) => {
  try {
    const { grade, class: classNumber } = req.query;
    let query = {};
    if (grade) query.grade = Number(grade);
    if (classNumber) query.class = Number(classNumber);

    const users = await User.find(query).select("-password");
    res.json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.delete(
  "/api/admin/users/:userId",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { userId } = req.params;
      await User.findByIdAndDelete(userId);
      res.json({ message: "사용자가 삭제되었습니다." });
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }
  }
);

// 새로운 AttendanceHistory 모델 정의
const AttendanceHistorySchema = new mongoose.Schema({
  date: { type: Date, required: true },
  records: [{ type: mongoose.Schema.Types.ObjectId, ref: "Attendance" }],
});

const AttendanceHistory = mongoose.model(
  "AttendanceHistory",
  AttendanceHistorySchema
);

// 일일 출석 초기화를 위한 cron job
cron.schedule("0 0 * * *", async () => {
  const yesterday = new Date();
  yesterday.setDate(yesterday.getDate() - 1);
  yesterday.setHours(0, 0, 0, 0);

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  try {
    // 어제의 출석 기록을 가져옴
    const yesterdayAttendances = await Attendance.find({
      timestamp: { $gte: yesterday, $lt: today },
    });

    // AttendanceHistory에 어제의 기록 저장
    await AttendanceHistory.create({
      date: yesterday,
      records: yesterdayAttendances.map((a) => a._id),
    });

    // 어제의 출석 상태 초기화 (예: isLate 필드를 false로 설정)
    await Attendance.updateMany(
      { timestamp: { $gte: yesterday, $lt: today } },
      { $set: { isLate: false } }
    );

    console.log("일일 출석 초기화 완료");
  } catch (error) {
    console.error("일일 출석 초기화 중 오류 발생:", error);
  }
});

// 출석 수정 API 엔드포인트
app.post("/api/attendance/modify", verifyToken, isAdmin, async (req, res) => {
  try {
    const { studentId, date, status } = req.body;

    const attendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: new Date(date).setHours(0, 0, 0, 0),
        $lt: new Date(date).setHours(23, 59, 59, 999),
      },
    });

    if (!attendance) {
      return res
        .status(404)
        .json({ message: "해당 날짜의 출석 기록을 찾을 수 없습니다." });
    }

    attendance.isLate = status === "late";
    attendance.lateMinutes =
      status === "late" ? calculateLateMinutes(attendance.timestamp) : 0;

    await attendance.save();

    res.json({ message: "출석 상태가 성공적으로 수정되었습니다.", attendance });
  } catch (error) {
    console.error("출석 수정 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 유틸리티 함수들
function getWorkingDays(startDate, endDate) {
  let count = 0;
  const curDate = new Date(startDate.getTime());
  while (curDate <= endDate) {
    const dayOfWeek = curDate.getDay();
    if (dayOfWeek !== 0 && dayOfWeek !== 6) count++;
    curDate.setDate(curDate.getDate() + 1);
  }
  return count;
}

// 수정된 calculateOverallStats 함수
function calculateOverallStats(attendanceData, startDate, endDate) {
  const stats = attendanceData.reduce(
    (acc, curr) => {
      acc.totalStudents++;
      acc.totalAttendance += curr.totalAttendance;
      acc.totalLateAttendance += curr.lateAttendance;
      acc.totalLateMinutes += curr.totalLateMinutes;
      return acc;
    },
    {
      totalStudents: 0,
      totalAttendance: 0,
      totalLateAttendance: 0,
      totalLateMinutes: 0,
    }
  );

  stats.averageAttendanceRate = (
    (stats.totalAttendance /
      (stats.totalStudents * getWorkingDays(startDate, endDate))) *
    100
  ).toFixed(2);
  stats.averageLateRate =
    stats.totalAttendance > 0
      ? ((stats.totalLateAttendance / stats.totalAttendance) * 100).toFixed(2)
      : 0;

  return stats;
}

function calculateLateMinutes(timestamp) {
  const attendanceTime = new Date(timestamp);
  const expectedTime = new Date(timestamp);
  expectedTime.setHours(ATTENDANCE_HOUR, ATTENDANCE_MINUTE, 0, 0);

  if (attendanceTime > expectedTime) {
    return Math.floor((attendanceTime - expectedTime) / 60000); // 분 단위로 반환
  }
  return 0;
}

app.post(
  "/api/admin/reset-password",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { userId } = req.body;
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
      }

      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash("1234", salt);
      user.password = hashedPassword;
      await user.save();

      res.json({ message: "비밀번호가 초기화되었습니다." });
    } catch (error) {
      console.error("비밀번호 초기화 중 오류 발생:", error);
      res.status(500).json({ message: "서버 오류가 발생했습니다." });
    }
  }
);
