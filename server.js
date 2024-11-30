const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const moment = require("moment-timezone");
require("dotenv").config();
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const winston = require("winston");

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

// JWT Secret 키 확인
if (!process.env.JWT_SECRET || !process.env.REFRESH_TOKEN_SECRET) {
  console.error(
    "JWT_SECRET or REFRESH_TOKEN_SECRET is not defined in environment variables"
  );
  process.exit(1);
}

// JWT 토큰 생성 함수
const generateAccessToken = (user) => {
  return jwt.sign(
    {
      id: user._id,
      studentId: user.studentId,
      isAdmin: user.isAdmin,
      isReader: user.isReader,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || "1h" }
  );
};

// 리프레시 토큰 생성 함수
const generateRefreshToken = () => {
  return crypto.randomBytes(40).toString("hex");
};

// 리프레시 토큰 만료 시간 설정 수정
const REFRESH_TOKEN_EXPIRES_IN =
  parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN) || 7 * 24 * 60 * 60 * 1000;

// 토큰 검증 미들웨어 수정
const verifyToken = (req, res, next) => {
  try {
    const authHeader = req.header("Authorization");
    if (!authHeader) {
      return res.status(401).json({
        success: false,
        message: "Authorization 헤더가 없습니다.",
      });
    }

    const [bearer, token] = authHeader.split(" ");
    if (bearer !== "Bearer" || !token || token.trim() === "") {
      return res.status(401).json({
        success: false,
        message: "잘못된 토큰 형식입니다.",
      });
    }

    const cleanToken = token.trim();
    jwt.verify(cleanToken, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        console.error("Token verification error:", err);

        if (err.name === "TokenExpiredError") {
          return res.status(401).json({
            success: false,
            message: "토큰이 만료되었습니다.",
            needRefresh: true,
          });
        }

        return res.status(401).json({
          success: false,
          message: "유효하지 않은 토큰입니다.",
          error: err.message,
        });
      }

      req.user = decoded;
      next();
    });
  } catch (error) {
    console.error("Token verification error:", error);
    return res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다.",
      error: error.message,
    });
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
      return res.status(400).json({
        success: false,
        message: "존재하지 않는 학번입니다.",
      });
    }

    if (!user.isApproved) {
      return res.status(400).json({
        success: false,
        message: "관리자의 승인을 기다리고 있습니다.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "비밀번호가 일치하지 않습니다.",
      });
    }

    // 액세스 토큰 생성
    const accessToken = generateAccessToken(user);

    // 리프레시 토큰 생성
    const refreshToken = generateRefreshToken();
    const refreshTokenDoc = new RefreshToken({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN),
    });

    // 기존 리프레시 토큰 삭제
    await RefreshToken.deleteMany({ userId: user._id });
    await refreshTokenDoc.save();

    // 응답에 토큰과 사용자 정보 포함
    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        studentId: user.studentId,
        name: user.name,
        isAdmin: user.isAdmin,
        isReader: user.isReader,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다.",
    });
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
        .json({ message: "현재 비밀번호가 일치지 않습니다." });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    user.password = hashedPassword;
    await user.save();

    res.json({ message: "비밀번호가 성공적으로 변경되었습니다." });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발했습니다." });
  }
});

app.get("/api/student-info", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json({ success: true, studentId: user.studentId, name: user.name });
  } catch (error) {
    res
      .status(500)
      .json({ success: false, message: "서버 오류가 발생했습니다." });
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

// Logout route
app.post("/api/logout", verifyToken, async (req, res) => {
  try {
    const { refreshToken } = req.body;
    await RefreshToken.deleteOne({ token: refreshToken });
    res.json({ success: true, message: "로그아웃되었습니다." });
  } catch (error) {
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
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

// QR리더 라우트
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

// QR생성 라우트
app.post("/api/generate-qr", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.body;

    // 요청한 사용자의 studentId와 토큰의 studentId가 일치하는지 확인
    if (req.user.studentId !== studentId) {
      return res.status(403).json({
        success: false,
        message: "권한이 없습니다.",
      });
    }

    const timestamp = toKoreanTimeString(new Date());
    const qrData = `${studentId}|${timestamp}`;

    if (
      !process.env.ENCRYPTION_KEY ||
      process.env.ENCRYPTION_KEY.length !== 32
    ) {
      throw new Error("유효하지 않 암호화 키");
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

    res.json({
      success: true,
      encryptedData: result,
      timestamp: timestamp,
    });
  } catch (error) {
    console.error("QR 코드 생성 오류:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다: " + error.message,
    });
  }
});

// 한국 시간으로 변환하는 함수
function toKoreanTimeString(date) {
  return moment(date).tz("Asia/Seoul").format("YYYY-MM-DD HH:mm:ss");
}

// 기존 AttendanceSchema 제거하고 새로운 스키마로 통합
const AttendanceSchema = new mongoose.Schema({
  studentId: { type: String, required: true },
  timestamp: { type: String, required: true },
  status: {
    type: String,
    enum: ["present", "late", "absent", "excused"],
    required: true,
  },
  lateMinutes: { type: Number, default: 0 },
  reason: { type: String },
  isExcused: { type: Boolean, default: false },
});

const Attendance = mongoose.model("Attendance", AttendanceSchema);

// 출석 상태 결정 함수 수정
function determineAttendanceStatus(timestamp) {
  const koreanTime = moment.tz(timestamp, "YYYY-MM-DD HH:mm:ss", "Asia/Seoul");
  const currentDate = koreanTime.clone().startOf("day");

  const normalAttendanceTime = process.env.NORMAL_ATTENDANCE_TIME || "08:03";
  const lateAttendanceTime = process.env.LATE_ATTENDANCE_TIME || "09:00";

  const [normalHour, normalMinute] = normalAttendanceTime
    .split(":")
    .map(Number);
  const [lateHour, lateMinute] = lateAttendanceTime.split(":").map(Number);

  const normalTime = currentDate
    .clone()
    .add(normalHour, "hours")
    .add(normalMinute, "minutes");
  const lateTime = currentDate
    .clone()
    .add(lateHour, "hours")
    .add(lateMinute, "minutes");

  console.log(`Current time: ${koreanTime.format("YYYY-MM-DD HH:mm:ss")}`);
  console.log(
    `Normal attendance time: ${normalTime.format("YYYY-MM-DD HH:mm:ss")}`
  );
  console.log(
    `Late attendance time: ${lateTime.format("YYYY-MM-DD HH:mm:ss")}`
  );

  if (koreanTime.isSameOrBefore(normalTime)) {
    return { status: "present", lateMinutes: 0 };
  } else if (koreanTime.isBefore(lateTime)) {
    const lateMinutes = koreanTime.diff(normalTime, "minutes");
    return { status: "late", lateMinutes };
  } else {
    return { status: "absent", lateMinutes: 0 };
  }
}

app.post("/api/attendance", verifyToken, isReader, async (req, res) => {
  try {
    const { encryptedData } = req.body;

    // 암호화된 데이터 복호화
    const [ivHex, encryptedHex] = encryptedData.split(":");
    const iv = Buffer.from(ivHex, "hex");
    const encrypted = Buffer.from(encryptedHex, "hex");
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      Buffer.from(process.env.ENCRYPTION_KEY),
      iv
    );
    let decrypted = decipher.update(encrypted);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    const [studentId, timestamp] = decrypted.toString().split("|");

    console.log(`Decrypted timestamp: ${timestamp}`);

    // 출석 상태 결정
    const { status, lateMinutes } = determineAttendanceStatus(timestamp);

    console.log(`Determined status: ${status}, Late minutes: ${lateMinutes}`);

    // Check for existing attendance on the same day
    const today = moment
      .tz(timestamp, "Asia/Seoul")
      .startOf("day")
      .format("YYYY-MM-DD");
    const tomorrow = moment
      .tz(timestamp, "Asia/Seoul")
      .add(1, "days")
      .startOf("day")
      .format("YYYY-MM-DD");

    const existingAttendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: today,
        $lt: tomorrow,
      },
    });

    if (existingAttendance) {
      return res
        .status(400)
        .json({ message: "이미 오늘 출석이 기록되었습니다." });
    }

    // 출석 기록 생성 및 저장
    const attendance = new Attendance({
      studentId,
      timestamp: timestamp,
      status,
      lateMinutes,
    });

    await attendance.save();

    console.log(`Saved attendance: ${JSON.stringify(attendance)}`);

    let message;
    if (status === "present") {
      message = "출석 처리되었습니다.";
    } else if (status === "late") {
      message = `지각 처리되었습니다. 지각 시간: ${lateMinutes}분`;
    } else {
      message = "결석 처리되었습니다.";
    }

    res.status(201).json({ message, attendance });
  } catch (error) {
    console.error("출석 처리 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 출석 통계 API
app.get("/api/attendance/stats", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, grade, classNum } = req.query;
    const today = moment().tz("Asia/Seoul").startOf("day");
    const thisMonth = moment().tz("Asia/Seoul").startOf("month");

    // 기본 쿼리 조건
    let matchCondition = {};
    if (startDate && endDate) {
      matchCondition.timestamp = {
        $gte: moment.tz(startDate, "Asia/Seoul").startOf("day").format(),
        $lte: moment.tz(endDate, "Asia/Seoul").endOf("day").format(),
      };
    }

    // 학생 필터링
    let userMatchCondition = {};
    if (grade) userMatchCondition.grade = parseInt(grade);
    if (classNum) userMatchCondition.class = parseInt(classNum);

    // 학생 목록 조회
    const students = await User.find(userMatchCondition).sort({
      grade: 1,
      class: 1,
      number: 1,
    });

    // 각 학생의 출석 통계 계산
    const studentStats = await Promise.all(
      students.map(async (student) => {
        const attendances = await Attendance.find({
          studentId: student.studentId,
          ...matchCondition,
        });

        const presentCount = attendances.filter(
          (a) => a.status === "present"
        ).length;
        const lateCount = attendances.filter((a) => a.status === "late").length;
        const absentCount = attendances.filter(
          (a) => a.status === "absent" && !a.isExcused
        ).length;
        const totalLateMinutes = attendances.reduce(
          (sum, a) => sum + (a.lateMinutes || 0),
          0
        );

        // 오늘의 출석 상태 확인
        const todayAttendance = await Attendance.findOne({
          studentId: student.studentId,
          timestamp: {
            $gte: today.format(),
            $lt: today.add(1, "day").format(),
          },
        });

        return {
          studentId: student.studentId,
          name: student.name,
          grade: student.grade,
          class: student.class,
          number: student.number,
          presentCount,
          lateCount,
          absentCount,
          totalLateMinutes,
          lastAttendance:
            attendances.length > 0
              ? moment(attendances[attendances.length - 1].timestamp).format(
                  "YYYY-MM-DD HH:mm:ss"
                )
              : "없음",
          todayStatus: todayAttendance ? todayAttendance.status : "미출석",
        };
      })
    );

    // 전체 통계
    const overallStats = {
      totalStudents: students.length,
      totalPresent: studentStats.reduce((sum, s) => sum + s.presentCount, 0),
      totalLate: studentStats.reduce((sum, s) => sum + s.lateCount, 0),
      totalAbsent: studentStats.reduce((sum, s) => sum + s.absentCount, 0),
    };

    // 이달의 출석왕
    const monthlyAttendanceKing = await Attendance.aggregate([
      {
        $match: {
          studentId: { $in: students.map((s) => s.studentId) },
          timestamp: {
            $gte: thisMonth.format(),
            $lte: today.format(),
          },
          status: "present",
        },
      },
      {
        $group: {
          _id: "$studentId",
          presentCount: { $sum: 1 },
        },
      },
      { $sort: { presentCount: -1 } },
      { $limit: 1 },
    ]);

    // 지각왕
    const lateKing = await Attendance.aggregate([
      {
        $match: {
          studentId: { $in: students.map((s) => s.studentId) },
          status: "late",
          timestamp: {
            $gte: thisMonth.format(),
            $lte: today.format(),
          },
        },
      },
      {
        $group: {
          _id: "$studentId",
          lateCount: { $sum: 1 },
          totalLateMinutes: { $sum: "$lateMinutes" },
        },
      },
      { $sort: { lateCount: -1 } },
      { $limit: 1 },
    ]);

    // 결석 통계
    const excusedAbsences = await Attendance.find({
      studentId: { $in: students.map((s) => s.studentId) },
      isExcused: true,
      timestamp: {
        $gte: thisMonth.format(),
        $lte: today.format(),
      },
    }).sort({ timestamp: -1 });

    const absences = await Attendance.find({
      studentId: { $in: students.map((s) => s.studentId) },
      status: "absent",
      isExcused: false,
      timestamp: {
        $gte: thisMonth.format(),
        $lte: today.format(),
      },
    }).sort({ timestamp: -1 });

    res.json({
      success: true,
      studentStats,
      overallStats,
      specialStats: {
        monthlyAttendanceKing: monthlyAttendanceKing[0],
        lateKing: lateKing[0],
        excusedAbsences,
        absences,
      },
    });
  } catch (error) {
    console.error("통계 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "통계 조회 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 1. 비밀번호 정책 강화
const validatePassword = (password) => {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*]/.test(password);

  return (
    password.length >= minLength &&
    hasUpperCase &&
    hasLowerCase &&
    hasNumbers &&
    hasSpecialChar
  );
};

// 2. 요청 제한 미웨어 추가
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // IP당 최대 요청 수
});

app.use(limiter);

// 3. 보안 헤더 추가
app.use(helmet());

// 4. 로그 시스템 추가
const logger = winston.createLogger({
  level: "info",
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// RefreshToken 모델 추가
const RefreshTokenSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  token: { type: String, required: true },
  expiresAt: {
    type: Date,
    required: true,
    validate: {
      validator: function (v) {
        return v instanceof Date && !isNaN(v);
      },
      message: "유효한 날짜가 아닙니다.",
    },
  },
});

const RefreshToken = mongoose.model("RefreshToken", RefreshTokenSchema);

// 리프레시 토큰 엔드포인트 수정
app.post("/api/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      return res.status(400).json({ message: "리프레시 토큰이 필요합니다." });
    }

    const refreshTokenDoc = await RefreshToken.findOne({
      token: refreshToken,
      expiresAt: { $gt: new Date() },
    });

    if (!refreshTokenDoc) {
      return res.status(401).json({
        success: false,
        message: "유효하지 않거나 만료된 리프레시 토큰입니다.",
        needRelogin: true,
      });
    }

    const user = await User.findById(refreshTokenDoc.userId);
    if (!user) {
      await RefreshToken.deleteOne({ _id: refreshTokenDoc._id });
      return res.status(401).json({
        success: false,
        message: "사용자를 찾을 수 없습니다.",
        needRelogin: true,
      });
    }

    // 새로운 액세스 토큰 생성
    const accessToken = generateAccessToken(user);

    // 새로운 리프레시 토큰 생성
    const newRefreshToken = generateRefreshToken();
    await RefreshToken.findByIdAndUpdate(refreshTokenDoc._id, {
      token: newRefreshToken,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_EXPIRES_IN),
    });

    res.json({
      success: true,
      accessToken,
      refreshToken: newRefreshToken,
      user: {
        id: user._id,
        studentId: user.studentId,
        name: user.name,
        isAdmin: user.isAdmin,
        isReader: user.isReader,
      },
    });
  } catch (error) {
    console.error("Refresh token error:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 인정결석 처리 API
app.post("/api/attendance/excuse", verifyToken, isAdmin, async (req, res) => {
  try {
    const { studentId, date, reason } = req.body;

    const attendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: moment.tz(date, "Asia/Seoul").startOf("day").format(),
        $lt: moment.tz(date, "Asia/Seoul").endOf("day").format(),
      },
    });

    if (!attendance) {
      return res
        .status(404)
        .json({ message: "해당 날짜의 출석 기록을 찾을 수 없습니다." });
    }

    attendance.isExcused = true;
    attendance.reason = reason;
    await attendance.save();

    res.json({ message: "인정결석 처리가 완료되었습니다." });
  } catch (error) {
    console.error("인정결석 처리 중 오류:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});
