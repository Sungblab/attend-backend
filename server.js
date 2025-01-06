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
const axios = require("axios");
const schedule = require("node-schedule");
const XLSX = require("xlsx");

// 로그 시스템 초기화를 가장 먼저 수행
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.printf(({ level, message, timestamp }) => {
      return `${timestamp} ${level}: ${message}`;
    })
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// 개발 환경에서는 콘솔에도 로그 출력
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

const app = express();

// trust proxy 설정 추가
app.set("trust proxy", 1);

// Middleware
app.use(cors());
app.use(express.json());

// rate limiter 설정
const limiter = rateLimit({
  windowMs: process.env.RATE_LIMIT_WINDOW_MS || 15 * 60 * 1000,
  max: process.env.RATE_LIMIT_MAX_REQUESTS || 1000,
  standardHeaders: true,
  legacyHeaders: false,
});

// rate limiter 적용
app.use(limiter);

// MongoDB connection
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => logger.info("MongoDB connected"))
  .catch((err) => logger.error("MongoDB connection error:", err));

// User model
const UserSchema = new mongoose.Schema({
  studentId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  password: { type: String, required: true },
  grade: { type: Number, required: true, enum: [1, 2, 3] },
  class: { type: Number, required: true, min: 1, max: 6 },
  number: { type: Number, required: true, min: 1, max: 100 },
  isAdmin: { type: Boolean, default: false },
  isTeacher: { type: Boolean, default: false },
  isReader: { type: Boolean, default: false },
  isApproved: { type: Boolean, default: false },
  timestamp: { type: Date, default: Date.now },
  // 담당 학년과 반 추가
  teacherGrade: { type: Number, enum: [1, 2, 3] },
  teacherClass: { type: Number, min: 1, max: 6 },
  deviceId: { type: String }, // deviceId 필드 추가
  device: { type: mongoose.Schema.Types.ObjectId, ref: "Device" }, // Device 모델 참조 추가
});

const User = mongoose.model("User", UserSchema);

// 출결 설정 모델 추가
const AttendanceSettingsSchema = new mongoose.Schema({
  startTime: { type: String, required: true, default: "07:30" },
  normalTime: { type: String, required: true, default: "08:03" },
  lateTime: { type: String, required: true, default: "09:00" },
  updatedAt: { type: Date, default: Date.now },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  autoAbsentTime: { type: String, required: true, default: "09:00" },
});

const AttendanceSettings = mongoose.model(
  "AttendanceSettings",
  AttendanceSettingsSchema
);

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
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRES_IN || "7d" }
  );
};

// 리프레시 토큰 생성 함수
const generateRefreshToken = () => {
  return crypto.randomBytes(40).toString("hex");
};

// 리프레시 토큰 만료 시간을 로그인 유지 여부에 따라 설정
const getRefreshTokenExpiresIn = (keepLoggedIn) => {
  return keepLoggedIn
    ? parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN) ||
        365 * 24 * 60 * 60 * 1000
    : parseInt(process.env.REFRESH_TOKEN_EXPIRES_IN) ||
        30 * 24 * 60 * 60 * 1000;
};

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

// Middleware to check if user is teacher
const isTeacher = async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user.isTeacher && !user.isAdmin) {
      return res.status(403).json({ message: "선생님 권한이 필요합니다." });
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

// 회원가입 라우트 수정
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

    // 학번 형식 검증 (4자리 숫자)
    if (!/^\d{4}$/.test(studentId)) {
      return res.status(400).json({ message: "학번은 4자리 숫자여야 합니다." });
    }

    // 이름 형식 검증 (2-4자 한글)
    if (!/^[가-힣]{2,4}$/.test(name)) {
      return res
        .status(400)
        .json({ message: "이름은 2-4자의 한글이어야 합니다." });
    }

    // 비밀번호 길이 검증
    const { isValid } = validatePassword(password);
    if (!isValid) {
      return res.status(400).json({
        message: "비밀번호는 8자 이상이어야 합니다.",
      });
    }

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

// 로그인 시도 횟수 관리를 위한 Map
const loginAttempts = new Map();

// 로그인 시도 횟수 체크 미들웨어
const checkLoginAttempts = async (req, res, next) => {
  const ip = req.ip;
  const currentAttempts = loginAttempts.get(ip) || {
    count: 0,
    timestamp: Date.now(),
  };

  // 최대 시도 횟수를 10회로 늘리고, 잠금 시간을 5분으로 설정
  const MAX_ATTEMPTS = process.env.MAX_LOGIN_ATTEMPTS || 50;
  const LOCKOUT_TIME = process.env.LOGIN_LOCKOUT_TIME || 5 * 60 * 1000; // 기본값 5분

  // 잠금 시간이 지났는지 확인
  if (currentAttempts.count >= MAX_ATTEMPTS) {
    const timeSinceLock = Date.now() - currentAttempts.timestamp;
    if (timeSinceLock < LOCKOUT_TIME) {
      return res.status(429).json({
        success: false,
        message: "너무 많은 로그인 시도. 잠시 후 다시 시도해주세요.",
        remainingTime: Math.ceil((LOCKOUT_TIME - timeSinceLock) / 1000),
      });
    } else {
      // 잠금 시간이 지났으면 초기화
      loginAttempts.delete(ip);
    }
  }

  next();
};

// 로그인 라우트에 미들웨어 적용
app.post("/api/login", checkLoginAttempts, async (req, res) => {
  try {
    const {
      studentId,
      password,
      deviceInfo = null,
      keepLoggedIn = false,
      isWeb = false,
    } = req.body;
    const ip = req.ip;

    // 입력값 검증
    if (!studentId || !password) {
      return res.status(400).json({
        success: false,
        message: "필번과 비밀번호를 모두 입력해주세요.",
      });
    }

    // 사용자 찾기
    const user = await User.findOne({ studentId });
    if (!user) {
      incrementLoginAttempts(ip);
      return res.status(401).json({
        success: false,
        message: "학번 또는 비밀번호가 일치하지 않습니다.",
      });
    }

    // 계정 승인 여부 확인
    if (!user.isApproved) {
      return res.status(403).json({
        success: false,
        message: "아직 승인되지 않은 계정입니다. 관리자의 승인을 기다려주세요.",
      });
    }

    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      incrementLoginAttempts(ip);
      return res.status(401).json({
        success: false,
        message: "학번 또는 비밀번호가 일치하지 않습니다.",
      });
    }

    // 웹이 아닌 앱에서 접속한 경우에만 디바이스 확인
    if (!isWeb && deviceInfo && deviceInfo.deviceId) {
      try {
        // 디바이스 ID 디코딩
        const buff = Buffer.from(deviceInfo.deviceId, "base64");
        const decodedDeviceInfo = JSON.parse(buff.toString("utf-8"));

        // 기존 디바이스 확인
        const existingDevice = await Device.findOne({
          deviceId: deviceInfo.deviceId,
          userId: { $ne: user._id },
        });

        if (existingDevice) {
          return res.status(403).json({
            success: false,
            message: "이 기기는 이미 다른 계정에 등록되어 있습니다.",
          });
        }

        // 디바이스 정보 업데이트 또는 생성
        const device = await Device.findOneAndUpdate(
          { userId: user._id },
          {
            deviceId: deviceInfo.deviceId,
            deviceInfo: {
              model: decodedDeviceInfo.model,
              platform: decodedDeviceInfo.osName,
              version: decodedDeviceInfo.osVersion.toString(),
              isEmulator: !decodedDeviceInfo.isDevice,
              lastLogin: new Date(),
            },
          },
          { upsert: true, new: true }
        );

        // User 모델에도 디바이스 정보 연결
        user.deviceId = deviceInfo.deviceId;
        user.device = device._id;
        await user.save();
      } catch (error) {
        console.error("Device info processing error:", error);
      }
    }

    // 로그인 성공 시 시도 횟수 초기화
    loginAttempts.delete(ip);

    // 토큰 생성
    const accessToken = generateAccessToken(user);
    const refreshToken = generateRefreshToken();

    // 리프레시 토큰 저장
    const refreshTokenDoc = new RefreshToken({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + getRefreshTokenExpiresIn(keepLoggedIn)),
    });

    await RefreshToken.deleteMany({ userId: user._id });
    await refreshTokenDoc.save();

    // 리다이렉트 URL 설정
    const redirectUrl =
      user.isAdmin || user.isReader ? "/hub.html" : "/qr.html";

    res.json({
      success: true,
      accessToken,
      refreshToken,
      redirectUrl,
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
    res.status(500).json({ message: "서버 오류가 했습니다." });
  }
});

app.get("/api/student-info", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    res.json({
      success: true,
      studentId: user.studentId,
      name: user.name,
      isAdmin: user.isAdmin,
      isTeacher: user.isTeacher,
      teacherGrade: user.teacherGrade,
      teacherClass: user.teacherClass,
    });
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

// 선생님 권한 설정 API
app.post("/api/admin/set-teacher", verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId, isTeacher, teacherGrade, teacherClass } = req.body;
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    user.isTeacher = isTeacher;

    // 선생님 권한이 있을 때만 담당 반 정보 업데이트
    if (isTeacher) {
      if (teacherGrade && teacherClass) {
        user.teacherGrade = teacherGrade;
        user.teacherClass = teacherClass;
      }
    } else {
      // 선생님 권한이 없어지면 담당 반 정보도 삭제
      user.teacherGrade = undefined;
      user.teacherClass = undefined;
    }

    await user.save();
    res.json({
      message: "사용자의 선생님 권한이 변경되었습니다.",
      user: {
        id: user._id,
        name: user.name,
        isTeacher: user.isTeacher,
        teacherGrade: user.teacherGrade,
        teacherClass: user.teacherClass,
      },
    });
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

      res.json({ message: "비밀번호가 초기화되었니다." });
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
    enum: ["present", "late", "absent"],
    required: true,
  },
  lateMinutes: { type: Number, default: 0 },
  isExcused: { type: Boolean, default: false },
  reason: { type: String },
  excusedAt: { type: Date },
  excusedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
});

const Attendance = mongoose.model("Attendance", AttendanceSchema);

// 출석 시간 상수 추가 (server.js 파일 상단에 추가)
const ATTENDANCE_START_TIME = "07:30"; // 출석 시작 시간
const NORMAL_ATTENDANCE_TIME = "08:03"; // 정상 출석 마감 시간
const LATE_ATTENDANCE_TIME = "09:00"; // 지각 마감 시간

// 서버 시작 시 시간대 설정
process.env.TZ = "Asia/Seoul";
moment.tz.setDefault("Asia/Seoul");

// 시간 관련 유틸리티 함수 추가
function getCurrentKoreanTime() {
  return moment().tz("Asia/Seoul");
}

// determineAttendanceStatus 함수 수정
async function determineAttendanceStatus(timestamp, student) {
  try {
    const koreanTime = moment.tz(
      timestamp,
      "YYYY-MM-DD HH:mm:ss",
      "Asia/Seoul"
    );
    const currentDate = koreanTime.clone().startOf("day");

    // 휴일 체크 (주말 포함)
    const isHoliday = await Holiday.findOne({
      date: currentDate.toDate(),
    });
    if (isHoliday) {
      return {
        status: "holiday",
        message: `${isHoliday.reason}입니다. 오늘은 출석체크를 하지 않습니다.`,
        success: false,
        details: {
          holiday: isHoliday.reason,
          date: koreanTime.format("YYYY-MM-DD"),
          student: {
            studentId: student.studentId,
            name: student.name,
          },
        },
      };
    }

    // 현재 설정 가져오기
    const settings = await AttendanceSettings.findOne().sort({ updatedAt: -1 });
    if (!settings) {
      throw new Error("출결 설정을 찾을 수 없습니다. 관리자에게 문의해주세요.");
    }

    // 시간 비교를 위해 현재 날짜의 시작 시간들을 설정
    const [startHour, startMinute] = settings.startTime.split(":").map(Number);
    const [normalHour, normalMinute] = settings.normalTime
      .split(":")
      .map(Number);
    const [lateHour, lateMinute] = settings.lateTime.split(":").map(Number);

    // 현재 시간을 분 단위로 변환
    const currentMinutes = koreanTime.hours() * 60 + koreanTime.minutes();

    // 각 기준 시간을 분 단위로 변환
    const startMinutes = startHour * 60 + startMinute;
    const normalMinutes = normalHour * 60 + normalMinute;
    const lateMinutes = lateHour * 60 + lateMinute;

    // 출석 시작 시간 전
    if (currentMinutes < startMinutes) {
      return {
        status: "early",
        message: `출석 시작 시간(${settings.startTime})이 되지 않았습니다.`,
        success: false,
        details: {
          currentTime: koreanTime.format("HH:mm"),
          startTime: settings.startTime,
          student: {
            studentId: student.studentId,
            name: student.name,
          },
        },
      };
    }

    // 정상 출석
    if (currentMinutes <= normalMinutes) {
      return {
        status: "present",
        lateMinutes: 0,
        message: "정상 출석 처리되었습니다.",
        success: true,
        details: {
          currentTime: koreanTime.format("HH:mm"),
          normalTime: settings.normalTime,
          student: {
            studentId: student.studentId,
            name: student.name,
          },
        },
      };
    }

    // 지각
    if (currentMinutes < lateMinutes) {
      const minutesLate = currentMinutes - normalMinutes;
      return {
        status: "late",
        lateMinutes: minutesLate,
        message: `지각 처리되었습니다. (${minutesLate}분 지각)`,
        success: true,
        details: {
          currentTime: koreanTime.format("HH:mm"),
          lateTime: settings.lateTime,
          minutesLate: minutesLate,
          student: {
            studentId: student.studentId,
            name: student.name,
          },
        },
      };
    }

    // 결석
    return {
      status: "absent",
      lateMinutes: 0,
      message: `지각 마감 시간(${settings.lateTime})이 지나 결석 처리되었습니다.`,
      success: true,
      details: {
        currentTime: koreanTime.format("HH:mm"),
        lateTime: settings.lateTime,
        student: {
          studentId: student.studentId,
          name: student.name,
        },
      },
    };
  } catch (error) {
    console.error("출석 상태 결정 중 오류:", error);
    throw error;
  }
}

// 출석 처리 API 수정
app.post("/api/attendance", verifyToken, isReader, async (req, res) => {
  try {
    const { encryptedData } = req.body;

    // QR 코드 데이터 검증
    if (!encryptedData || typeof encryptedData !== "string") {
      return res.status(422).json({
        success: false,
        message: "QR 코드를 다시 스캔해주세요. 유효하지 않은 QR 코드입니다.",
        type: "INVALID_QR",
      });
    }

    // QR 코드 형식 검사
    const [ivHex, encryptedHex] = encryptedData.split(":");
    if (!ivHex || !encryptedHex) {
      return res.status(422).json({
        success: false,
        message:
          "QR 코드 형식이 올바르지 않습니다. 새로운 QR 코드를 생성해주세요.",
        type: "INVALID_FORMAT",
      });
    }

    try {
      const iv = Buffer.from(ivHex.trim(), "hex");
      const encrypted = Buffer.from(encryptedHex.trim(), "hex");
      const decipher = crypto.createDecipheriv(
        "aes-256-cbc",
        Buffer.from(process.env.ENCRYPTION_KEY),
        iv
      );
      let decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted, decipher.final()]);
      const [studentId, timestamp] = decrypted.toString().split("|");

      // 복호화된 데이터 검증
      if (!studentId || !timestamp) {
        return res.status(422).json({
          success: false,
          message: "QR 코드가 손상되었습니다. 새로운 QR 코드를 생성해주세요.",
          type: "CORRUPTED_QR",
        });
      }

      // 학생 정보 조회
      const student = await User.findOne({ studentId });
      if (!student) {
        return res.status(404).json({
          success: false,
          message: "등록되지 않은 학생입니다. 학생 등록 후 다시 시도해주세요.",
          type: "STUDENT_NOT_FOUND",
        });
      }

      // 출석 상태 결정
      const attendanceStatus = await determineAttendanceStatus(
        timestamp,
        student
      );
      if (!attendanceStatus.success) {
        return res.status(200).json({
          success: false,
          message: attendanceStatus.message,
          type: attendanceStatus.status.toUpperCase(),
          details: attendanceStatus.details || {},
        });
      }

      // 기존 출석 기록 확인 및 삭제
      const today = moment.tz(timestamp, "Asia/Seoul").startOf("day");
      const tomorrow = moment(today).add(1, "days");

      // 당일의 모든 출석 기록 삭제 (인정결석 제외)
      await Attendance.deleteMany({
        studentId,
        timestamp: {
          $gte: today.format(),
          $lt: tomorrow.format(),
        },
        isExcused: { $ne: true }, // 인정결석은 삭제하지 않음
      });

      // 새로운 출석 기록 생성
      const attendance = new Attendance({
        studentId,
        timestamp,
        status: attendanceStatus.status,
        lateMinutes: attendanceStatus.lateMinutes,
      });

      await attendance.save();

      // 상태별 메시지 설정
      let responseMessage = "";
      let responseType = "";

      switch (attendance.status) {
        case "present":
          responseMessage = "정상 출석 처리되었습니다.";
          responseType = "PRESENT_SUCCESS";
          break;
        case "late":
          responseMessage = `지각 처리되었습니다. (${attendance.lateMinutes}분 지각)`;
          responseType = "LATE_SUCCESS";
          break;
        case "absent":
          responseMessage = "결석 처리되었습니다.";
          responseType = "ABSENT_SUCCESS";
          break;
      }

      res.status(201).json({
        success: true,
        message: responseMessage,
        type: responseType,
        attendance: {
          ...attendance.toObject(),
          name: student.name,
        },
      });
    } catch (cryptoError) {
      console.error("복호화 오류:", cryptoError);
      return res.status(422).json({
        success: false,
        message: "QR 코드를 읽을 수 없습니다. 새로운 QR 코드를 생성해주세요.",
        type: "DECRYPTION_ERROR",
        details: cryptoError.message,
      });
    }
  } catch (error) {
    console.error("출석 처리 중 오류:", error);
    return res.status(500).json({
      success: false,
      message: "출석 처리 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요.",
      type: "SERVER_ERROR",
      details: error.message,
    });
  }
});

// 자동 결석 처리 함수 수정
async function processAutoAbsent() {
  try {
    const now = moment().tz("Asia/Seoul");
    const today = now.format("YYYY-MM-DD");
    const currentTime = now.format("HH:mm:ss");

    logger.info(`[자동 결석 처리] 시작 - ${today} ${currentTime}`);

    // 이미 오늘 자동 결석 처리가 실행되었는지 확인
    const processLog = await ProcessLog.findOne({
      type: "auto_absent",
      processDate: today,
    });

    if (processLog) {
      logger.info(
        `[자동 결석 처리] 오늘(${today})은 이미 ${processLog.processTime}에 처리되었습니다.`
      );
      return;
    }

    // 실행 중인 프로세스를 표시하기 위한 임시 로그 생성
    const tempLog = new ProcessLog({
      type: "auto_absent",
      processDate: today,
      processTime: currentTime,
      processedCount: 0,
      details: "처리 중...",
    });
    await tempLog.save();

    try {
      // 주말인 경우 처리하지 않음
      if (now.day() === 0 || now.day() === 6) {
        logger.info("[자동 결석 처리] 주말이므로 처리하지 않습니다.");
        await ProcessLog.deleteOne({ _id: tempLog._id });
        return;
      }

      // 휴일 체크
      const holiday = await Holiday.findOne({
        date: now.startOf("day").toDate(),
      });

      if (holiday) {
        logger.info(
          `[자동 결석 처리] ${holiday.reason}은(는) 휴일이므로 처리하지 않습니다.`
        );
        await ProcessLog.deleteOne({ _id: tempLog._id });
        return;
      }

      // 출석하지 않은 학생들 조회
      const allStudents = await User.find({
        isApproved: true,
        isAdmin: false,
        isReader: false,
        isTeacher: false,
      });

      // 오늘 출석 기록이 있는 학생들 조회 (모든 상태 포함)
      const todayAttendances = await Attendance.find({
        timestamp: {
          $gte: moment(today).startOf("day").format(),
          $lt: moment(today).add(1, "day").startOf("day").format(),
        },
      });

      // 오늘 출석 기록이 있는 학생들의 ID 목록
      const studentsWithAttendance = todayAttendances.map((a) => a.studentId);

      // 오늘 출석 기록이 전혀 없는 학생들만 필터링
      const absentStudents = allStudents.filter(
        (student) => !studentsWithAttendance.includes(student.studentId)
      );

      // 결석 처리
      let processedCount = 0;
      for (const student of absentStudents) {
        // 결석 처리 전에 한번 더 확인
        const hasAttendance = await Attendance.findOne({
          studentId: student.studentId,
          timestamp: {
            $gte: moment(today).startOf("day").format(),
            $lt: moment(today).add(1, "day").startOf("day").format(),
          },
        });

        // 정말로 출석 기록이 없는 경우에만 결석 처리
        if (!hasAttendance) {
          const attendance = new Attendance({
            studentId: student.studentId,
            timestamp: now.format(),
            status: "absent",
            lateMinutes: 0,
          });
          await attendance.save();
          processedCount++;
          logger.info(
            `[자동 결석 처리] 학생 ${student.studentId} (${student.name}) 결석 처리 완료`
          );
        }
      }

      // 처리 로그 업데이트
      await ProcessLog.findByIdAndUpdate(tempLog._id, {
        processedCount: processedCount,
        details: `총 ${allStudents.length}명 중 ${processedCount}명 결석 처리됨`,
      });

      logger.info(
        `[자동 결석 처리] 완료 - ${processedCount}명의 학생이 결석 처리되었습니다.`
      );
    } catch (error) {
      // 오류 발생 시 임시 로그 삭제
      await ProcessLog.deleteOne({ _id: tempLog._id });
      throw error;
    }
  } catch (error) {
    logger.error("[자동 결석 처리] 오류 발생:", error);
  }
}

// ProcessLog 모델 수정
const ProcessLogSchema = new mongoose.Schema({
  type: { type: String, required: true },
  processDate: { type: String, required: true }, // YYYY-MM-DD 형식
  processTime: { type: String, required: true }, // HH:mm:ss 형식
  processedCount: { type: Number, required: true },
  details: { type: String },
});

const ProcessLog = mongoose.model("ProcessLog", ProcessLogSchema);

// 수동 지각 처리 API
app.post(
  "/api/attendance/process-late",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const now = moment();
      const today = now.format("YYYY-MM-DD");
      const currentTime = now.format("HH:mm:ss");

      // 휴일 체크
      const holiday = await Holiday.findOne({
        date: now.startOf("day").toDate(),
      });

      if (holiday) {
        return res.status(400).json({
          success: false,
          message: "휴일에는 지각 처리를 할 수 없습니다.",
        });
      }

      // 출석 설정 가져오기
      const settings = await AttendanceSettings.findOne().sort({
        updatedAt: -1,
      });
      if (!settings) {
        return res.status(400).json({
          success: false,
          message: "출석 설정을 찾을 수 없습니다.",
        });
      }

      // 미출석 학생 조회
      const allStudents = await User.find({
        isApproved: true,
        isAdmin: false,
        isReader: false,
        isTeacher: false,
      });

      const attendedStudents = await Attendance.find({
        timestamp: {
          $gte: today.format("YYYY-MM-DD 00:00:00"),
          $lt: moment(today).add(1, "day").format("YYYY-MM-DD 00:00:00"),
        },
      }).distinct("studentId");

      const unattendedStudents = allStudents.filter(
        (student) => !attendedStudents.includes(student.studentId)
      );

      // 지각 처리 결과
      const results = {
        processedCount: unattendedStudents.length,
        successCount: 0,
        failedCount: 0,
        details: [],
      };

      // 지각 처리
      for (const student of unattendedStudents) {
        try {
          const [normalHour, normalMinute] = settings.normalTime
            .split(":")
            .map(Number);
          const normalTime = now
            .clone()
            .add(normalHour, "hours")
            .add(normalMinute, "minutes");

          const lateMinutes = moment().diff(normalTime, "minutes");

          const attendance = new Attendance({
            studentId: student.studentId,
            timestamp: now.format(),
            status: "late",
            lateMinutes: Math.max(0, lateMinutes),
          });

          await attendance.save();
          results.successCount++;
          results.details.push({
            success: true,
            message: `${student.studentId} (${student.name}) - 지각 처리 완료`,
          });
        } catch (error) {
          results.failedCount++;
          results.details.push({
            success: false,
            message: `${student.studentId} (${student.name}) - 처리 실패: ${error.message}`,
          });
        }
      }

      // 처리 로그 저장
      await new ProcessLog({
        type: "manual_late",
        processDate: today,
        processTime: currentTime,
        processedCount: results.successCount,
        details: `성공: ${results.successCount}명, 실패: ${results.failedCount}명`,
      }).save();

      res.json({
        success: true,
        message: "지각 처리가 완료되었습니다.",
        ...results,
      });
    } catch (error) {
      logger.error("수동 지각 처리 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "지각 처리 중 오류가 발생했습니다.",
      });
    }
  }
);

// 수동 결석 처리 API
app.post(
  "/api/attendance/process-absent",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const now = moment().tz("Asia/Seoul");
      const today = now.format("YYYY-MM-DD");
      const currentTime = now.format("HH:mm:ss");

      // 휴일 체크
      const holiday = await Holiday.findOne({
        date: now.startOf("day").toDate(),
      });

      if (holiday) {
        return res.status(400).json({
          success: false,
          message: "휴일에는 결석 처리를 할 수 없습니다.",
        });
      }

      // 미출석 학생 조회
      const allStudents = await User.find({
        isApproved: true,
        isAdmin: false,
        isReader: false,
        isTeacher: false,
      });

      const attendedStudents = await Attendance.find({
        timestamp: {
          $gte: `${today} 00:00:00`,
          $lt: moment(today).add(1, "day").format("YYYY-MM-DD 00:00:00"),
        },
      }).distinct("studentId");

      const unattendedStudents = allStudents.filter(
        (student) => !attendedStudents.includes(student.studentId)
      );

      // 결석 처리 결과
      const results = {
        processedCount: unattendedStudents.length,
        successCount: 0,
        failedCount: 0,
        details: [],
      };

      // 결석 처리
      for (const student of unattendedStudents) {
        try {
          const attendance = new Attendance({
            studentId: student.studentId,
            timestamp: now.format(),
            status: "absent",
            lateMinutes: 0,
          });

          await attendance.save();
          results.successCount++;
          results.details.push({
            success: true,
            message: `${student.studentId} (${student.name}) - 결석 처리 완료`,
          });
        } catch (error) {
          console.error(`학생 ${student.studentId} 결석 처리 중 오류:`, error);
          results.failedCount++;
          results.details.push({
            success: false,
            message: `${student.studentId} (${student.name}) - 처리 실패: ${error.message}`,
          });
        }
      }

      // 처리 로그 저장
      await new ProcessLog({
        type: "manual_absent",
        processDate: today,
        processTime: currentTime,
        processedCount: results.successCount,
        details: `성공: ${results.successCount}명, 실패: ${results.failedCount}명`,
      }).save();

      res.json({
        success: true,
        message: "결석 처리가 완료되었습니다.",
        ...results,
      });
    } catch (error) {
      console.error("결석 처리 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "결석 처리 중 오류가 발생했습니다.",
        error: error.message,
      });
    }
  }
);

// 전역 스케줄러 객체 저장
let autoAbsentJob = null;

// 매일 자동 결석 처리 실행 스케줄 설정
async function setupAutoAbsentSchedule() {
  try {
    // 기존 스케줄이 있다면 취소
    if (autoAbsentJob) {
      autoAbsentJob.cancel();
      logger.info("[스케줄러] 기존 자동 결석 처리 스케줄이 취소되었습니다.");
    }

    const settings = await AttendanceSettings.findOne().sort({ updatedAt: -1 });
    if (!settings || !settings.autoAbsentTime) {
      logger.error(
        "[스케줄러] 출석 설정을 찾을 수 없어 기본값으로 스케줄을 설정합니다."
      );
      const defaultSettings = new AttendanceSettings({
        startTime: "07:30",
        normalTime: "08:03",
        lateTime: "09:00",
        autoAbsentTime: "09:00",
      });
      await defaultSettings.save();
      autoAbsentJob = schedule.scheduleJob("0 9 * * 1-5", processAutoAbsent);
      logger.info(
        "[스케줄러] 자동 결석 처리 스케줄이 기본값(09:00, 월-금)으로 설정되었습니다."
      );
      return {
        success: true,
        message: "자동 결석 처리 시간이 기본값(09:00)으로 설정되었습니다.",
        nextInvocation: autoAbsentJob.nextInvocation(),
      };
    }

    const [hour, minute] = settings.autoAbsentTime.split(":").map(Number);
    const cronExpression = `${minute} ${hour} * * 1-5`;

    // 현재 시간이 설정된 시간을 지났는지 확인
    const now = getCurrentKoreanTime();
    const currentMinutes = now.hours() * 60 + now.minutes();
    const scheduledMinutes = hour * 60 + minute;

    // 오늘의 처리 로그 확인
    const today = now.format("YYYY-MM-DD");
    const processLog = await ProcessLog.findOne({
      type: "auto_absent",
      processDate: today,
    });

    // 스케줄 설정
    autoAbsentJob = schedule.scheduleJob(cronExpression, processAutoAbsent);
    logger.info(
      `[스케줄러] 자동 결석 처리 스케줄이 ${settings.autoAbsentTime} (KST, 월-금)으로 설정되었습니다.`
    );

    // 현재 시간이 설정된 시간을 지났고, 아직 처리되지 않았으며, 주말이 아닌 경우에만 즉시 실행
    if (
      !processLog &&
      now.day() !== 0 &&
      now.day() !== 6 &&
      currentMinutes >= scheduledMinutes
    ) {
      logger.info(
        "[스케줄러] 현재 시간이 설정된 시간을 지났으므로 자동 결석 처리를 즉시 실행합니다."
      );
      await processAutoAbsent();
    }

    return {
      success: true,
      message: `자동 결석 처리 시간이 ${settings.autoAbsentTime}으로 설정되었습니다.`,
      nextInvocation: autoAbsentJob.nextInvocation(),
    };
  } catch (error) {
    logger.error(
      "[스케줄러] 자동 결석 처리 스케줄 설정 중 오류: " + error.message
    );
    throw error;
  }
}

// 출석 설정이 변경될 때마다 스케줄 재설정
app.put("/api/settings/attendance", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startTime, normalTime, lateTime, autoAbsentTime } = req.body;

    // 시간 형식 검증 (HH:mm)
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
    if (
      !timeRegex.test(startTime) ||
      !timeRegex.test(normalTime) ||
      !timeRegex.test(lateTime) ||
      !timeRegex.test(autoAbsentTime)
    ) {
      return res.status(400).json({
        success: false,
        message: "잘못된 시간 형식입니다. (HH:mm)",
      });
    }

    // 시간 순서 검증
    const start = moment(startTime, "HH:mm");
    const normal = moment(normalTime, "HH:mm");
    const late = moment(lateTime, "HH:mm");
    const autoAbsent = moment(autoAbsentTime, "HH:mm");

    if (
      start.isAfter(normal) ||
      normal.isAfter(late) ||
      late.isAfter(autoAbsent)
    ) {
      return res.status(400).json({
        success: false,
        message: "시간 순서가 올바르지 않습니다.",
      });
    }

    const settings = new AttendanceSettings({
      startTime,
      normalTime,
      lateTime,
      autoAbsentTime,
      updatedBy: req.user.id,
    });

    await settings.save();

    // 자동 결석 처리 스케줄 재설정
    try {
      const scheduleResult = await setupAutoAbsentSchedule();
      logger.info(
        "[설정] 자동 결석 처리 스케줄이 업데이트되었습니다:",
        scheduleResult
      );
    } catch (scheduleError) {
      logger.error("[설정] 스케줄 업데이트 중 오류:", scheduleError);
      return res.status(500).json({
        success: false,
        message:
          "출결 설정은 저장되었으나, 자동 결석 처리 스케줄 업데이트에 실패했습니다.",
        error: scheduleError.message,
      });
    }

    res.json({
      success: true,
      message: "출결 설정이 업데이트되었습니다.",
      settings: {
        startTime: settings.startTime,
        normalTime: settings.normalTime,
        lateTime: settings.lateTime,
        autoAbsentTime: settings.autoAbsentTime,
        updatedAt: settings.updatedAt,
        updatedBy: req.user.name,
      },
    });
  } catch (error) {
    console.error("출결 설정 업데이트 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "출결 설정 업데이트 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 서버 시작 시 자동 결석 처리 스케줄 설정
setupAutoAbsentSchedule().catch((error) => {
  logger.error("초기 자동 결석 처리 스케줄 설정 중 오류: " + error.message);
});

// 출석 통계 API 개선
app.get("/api/attendance/stats", verifyToken, async (req, res) => {
  try {
    let { startDate, endDate, grade, classNum } = req.query;
    const today = moment().tz("Asia/Seoul").startOf("day");
    const thisMonth = moment().tz("Asia/Seoul").startOf("month");

    // 현재 로그인한 사용자 정보 조회
    const currentUser = await User.findById(req.user.id);

    // 권한 확인 (관리자나 선생님만 접근 가능)
    if (!currentUser.isAdmin && !currentUser.isTeacher) {
      return res.status(403).json({
        success: false,
        message: "통계 조회 권한이 없습니다.",
      });
    }

    // 필터 조건 설정
    let matchCondition = {};
    if (startDate && endDate) {
      matchCondition.timestamp = {
        $gte: moment.tz(startDate, "Asia/Seoul").startOf("day").format(),
        $lte: moment.tz(endDate, "Asia/Seoul").endOf("day").format(),
      };
    }

    // 학생 필터링
    let userMatchCondition = { isApproved: true };
    if (grade) userMatchCondition.grade = parseInt(grade);
    if (classNum) userMatchCondition.class = parseInt(classNum);

    // 학생 목록 조회
    const students = await User.find(userMatchCondition).sort({
      grade: 1,
      class: 1,
      number: 1,
    });

    // 월간 랭킹 계산
    const monthlyRankings = {
      attendance: await calculateMonthlyRankings(
        students,
        "present",
        3,
        startDate,
        endDate
      ),
      punctuality: await calculateMonthlyRankings(
        students,
        "late",
        3,
        startDate,
        endDate
      ),
    };

    // 전체 통계 계산
    const attendances = await Attendance.find(matchCondition);
    const totalPresent = attendances.filter(
      (a) => a.status === "present"
    ).length;
    const totalLate = attendances.filter((a) => a.status === "late").length;
    const totalAbsent = attendances.filter(
      (a) => a.status === "absent" && !a.isExcused
    ).length;
    const totalExcused = attendances.filter((a) => a.isExcused).length;
    const totalLateMinutes = attendances.reduce(
      (sum, a) => sum + (a.lateMinutes || 0),
      0
    );

    const overallStats = {
      totalStudents: students.length,
      totalPresent,
      totalLate,
      totalAbsent,
      totalExcused,
      totalLateMinutes,
      averageAttendanceRate:
        attendances.length > 0
          ? (
              ((totalPresent + totalExcused) / attendances.length) *
              100
            ).toFixed(1)
          : 0,
    };

    // 학생별 상세 통계
    const studentStats = await Promise.all(
      students.map(async (student) => {
        const studentAttendances = attendances.filter(
          (a) => a.studentId === student.studentId
        );
        const presentCount = studentAttendances.filter(
          (a) => a.status === "present"
        ).length;
        const lateCount = studentAttendances.filter(
          (a) => a.status === "late"
        ).length;
        const absentCount = studentAttendances.filter(
          (a) => a.status === "absent" && !a.isExcused
        ).length;
        const excusedCount = studentAttendances.filter(
          (a) => a.isExcused
        ).length;
        const totalLateMinutes = studentAttendances.reduce(
          (sum, a) => sum + (a.lateMinutes || 0),
          0
        );

        // 오늘의 출석 상태
        const today = moment().tz("Asia/Seoul").startOf("day");
        const todayAttendance = await Attendance.findOne({
          studentId: student.studentId,
          timestamp: {
            $gte: today.format("YYYY-MM-DD 00:00:00"),
            $lt: moment(today).add(1, "day").format("YYYY-MM-DD 00:00:00"),
          },
        });

        return {
          studentId: student.studentId,
          name: student.name,
          grade: student.grade,
          class: student.class,
          number: student.number,
          summary: {
            presentCount,
            lateCount,
            absentCount,
            excusedCount,
            totalLateMinutes,
            attendanceRate:
              studentAttendances.length > 0
                ? (
                    ((presentCount + excusedCount) /
                      studentAttendances.length) *
                    100
                  ).toFixed(1)
                : 0,
          },
          todayStatus: todayAttendance
            ? {
                status: todayAttendance.status,
                isExcused: todayAttendance.isExcused,
                lateMinutes: todayAttendance.lateMinutes,
              }
            : null,
        };
      })
    );

    res.json({
      success: true,
      studentStats,
      overallStats,
      monthlyRankings,
      userInfo: {
        isAdmin: currentUser.isAdmin,
        isTeacher: currentUser.isTeacher,
        teacherGrade: currentUser.teacherGrade,
        teacherClass: currentUser.teacherClass,
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

// 월간 랭킹 계산 함수 추가
async function calculateMonthlyRankings(
  students,
  type,
  limit = 3,
  startDate = null,
  endDate = null
) {
  // 기간 설정
  const start = startDate
    ? moment.tz(startDate, "Asia/Seoul").startOf("day")
    : moment().tz("Asia/Seoul").startOf("month");
  const end = endDate
    ? moment.tz(endDate, "Asia/Seoul").endOf("day")
    : moment().tz("Asia/Seoul").endOf("month");

  const rankings = await Promise.all(
    students.map(async (student) => {
      const attendances = await Attendance.find({
        studentId: student.studentId,
        timestamp: {
          $gte: start.format(),
          $lte: end.format(),
        },
      });

      // 출석 횟수 계산
      const presentCount = attendances.filter(
        (a) => a.status === "present"
      ).length;
      const lateCount = attendances.filter((a) => a.status === "late").length;
      const totalLateMinutes = attendances.reduce(
        (sum, a) => sum + (a.lateMinutes || 0),
        0
      );

      // 개선도 계산
      const previousStart = start.clone().subtract(1, "month");
      const previousEnd = end.clone().subtract(1, "month");
      const lastMonthAttendances = await Attendance.find({
        studentId: student.studentId,
        timestamp: {
          $gte: previousStart.format(),
          $lte: previousEnd.format(),
        },
      });

      const improvement = calculateImprovement(
        {
          present: lastMonthAttendances.filter((a) => a.status === "present")
            .length,
          late: lastMonthAttendances.filter((a) => a.status === "late").length,
          total: lastMonthAttendances.length,
        },
        {
          present: presentCount,
          late: lateCount,
          total: attendances.length,
        }
      );

      return {
        studentId: student.studentId,
        name: student.name,
        grade: student.grade,
        class: student.class,
        count: type === "present" ? presentCount : lateCount,
        lateMinutes: totalLateMinutes,
        improvement,
      };
    })
  );

  // 정렬 및 상위 N개 반
  return rankings
    .sort((a, b) => {
      if (type === "present") return b.count - a.count;
      if (type === "improvement") return b.improvement - a.improvement;
      return a.count - b.count || a.lateMinutes - b.lateMinutes;
    })
    .slice(0, limit);
}

// 1. 비밀번호 정책 강화
const validatePassword = (password) => {
  return {
    isValid: password.length >= 8,
    requirements: {
      length: password.length >= 8,
    },
  };
};

app.use(limiter);

// 3. 보안 헤더 추가
app.use(helmet());
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

// 리프레시 토큰 엔드 포인트 수정
app.post("/api/refresh-token", async (req, res) => {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(400).json({
        success: false,
        message: "리프레시 토큰이 필요합니다.",
      });
    }

    // 리프레시 토큰 검증
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

    // 사용자 정보 조회
    const user = await User.findById(refreshTokenDoc.userId);
    if (!user) {
      await RefreshToken.deleteOne({ _id: refreshTokenDoc._id });
      return res.status(401).json({
        success: false,
        message: "사용자를 찾을 수 없습니다.",
        needRelogin: true,
      });
    }

    // 새운 액세스 토큰 생성
    const accessToken = generateAccessToken(user);

    // 새로운 리프레시 토큰 생성
    const newRefreshToken = generateRefreshToken();

    // 기존 리프레시 토큰 업데이트
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
    res.status(500).json({
      success: false,
      message: "토큰 갱신 중 오류가 발생했습니다.",
    });
  }
});

// 인정결석 처리 API
app.post("/api/attendance/excuse", verifyToken, isAdmin, async (req, res) => {
  try {
    const { studentId, date, reason } = req.body;

    if (!studentId || !date || !reason) {
      return res.status(400).json({
        success: false,
        message: "학번, 날짜, 사유가 모두 필요합니다.",
      });
    }

    // 해당 날짜의 출석 기록 찾기
    const targetDate = moment.tz(date, "YYYY-MM-DD", "Asia/Seoul");
    const startOfDay = targetDate.format("YYYY-MM-DD 00:00:00");
    const endOfDay = targetDate.format("YYYY-MM-DD 23:59:59");

    let attendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: startOfDay,
        $lt: endOfDay,
      },
    });

    if (!attendance) {
      // 출석 기록이 없는 경우 새로 생성
      attendance = new Attendance({
        studentId,
        timestamp: targetDate.format("YYYY-MM-DD HH:mm:ss"),
        status: "absent",
        isExcused: true,
        reason,
        excusedAt: moment().tz("Asia/Seoul").format("YYYY-MM-DD HH:mm:ss"),
        excusedBy: req.user.id,
      });
    } else {
      // 기존 출석 기록을 인정결석으로 변경
      attendance.status = "absent";
      attendance.isExcused = true;
      attendance.reason = reason;
      attendance.lateMinutes = 0;
      attendance.excusedAt = moment()
        .tz("Asia/Seoul")
        .format("YYYY-MM-DD HH:mm:ss");
      attendance.excusedBy = req.user.id;
    }

    await attendance.save();

    res.json({
      success: true,
      message: "인정결석 처리가 완료되었습니다.",
      attendance,
    });
  } catch (error) {
    console.error("인정결석 처리 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "인정결석 처리 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 월별 통통계 계산 함수
async function calculateMonthStats(studentId, monthStart) {
  const monthEnd = moment(monthStart).endOf("month");

  const attendances = await Attendance.find({
    studentId,
    timestamp: {
      $gte: monthStart.format(),
      $lte: monthEnd.format(),
    },
  });

  return {
    total: attendances.length,
    present: attendances.filter((a) => a.status === "present").length,
    late: attendances.filter((a) => a.status === "late").length,
    absent: attendances.filter((a) => a.status === "absent" && !a.isExcused)
      .length,
    excused: attendances.filter((a) => a.isExcused).length,
    lateMinutes: attendances.reduce((sum, a) => sum + (a.lateMinutes || 0), 0),
    attendanceRate:
      attendances.length > 0
        ? (
            (attendances.filter((a) => a.status === "present" || a.isExcused)
              .length /
              attendances.length) *
            100
          ).toFixed(1)
        : 0,
  };
}

// 개선도 계산 함수 완성
function calculateImprovement(lastMonth, thisMonth) {
  let improvement = 0;

  // 출석률 개선
  const attendanceImprovement =
    thisMonth.attendanceRate - lastMonth.attendanceRate;

  // 지각 감소율
  const lateReduction =
    lastMonth.late > 0
      ? ((lastMonth.late - thisMonth.late) / lastMonth.late) * 100
      : thisMonth.late === 0
      ? 100
      : 0;

  // 지각 시간 감소율
  const lateMinutesReduction =
    lastMonth.lateMinutes > 0
      ? ((lastMonth.lateMinutes - thisMonth.lateMinutes) /
          lastMonth.lateMinutes) *
        100
      : thisMonth.lateMinutes === 0
      ? 100
      : 0;

  // 결석 감소율
  const absentReduction =
    lastMonth.absent > 0
      ? ((lastMonth.absent - thisMonth.absent) / lastMonth.absent) * 100
      : thisMonth.absent === 0
      ? 100
      : 0;

  // 가중치 적용
  improvement =
    attendanceImprovement * 0.4 + // 출률 개선 40%
    lateReduction * 0.2 + // 지각 수 감소 20%
    lateMinutesReduction * 0.2 + // 지각 시간 감소 20%
    absentReduction * 0.2; // 결석 감소 20%

  return parseFloat(improvement.toFixed(1));
}

// 학학생별 상세 통계 API
app.get("/api/attendance/student/:studentId", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.params;
    const { startDate, endDate } = req.query;

    // 권한 확인 (관리자이거나 본인 정보만 조회 가능)
    const requestUser = await User.findById(req.user.id);
    if (!requestUser.isAdmin && requestUser.studentId !== studentId) {
      return res.status(403).json({
        success: false,
        message: "권한이 없습니다.",
      });
    }

    // 학생 정보 조회
    const student = await User.findOne({ studentId });
    if (!student) {
      return res.status(404).json({
        success: false,
        message: "학생을 찾을 수 없습니다.",
      });
    }

    // 기간 설정
    const start = startDate
      ? moment.tz(startDate, "Asia/Seoul").startOf("day")
      : moment().tz("Asia/Seoul").subtract(6, "months").startOf("month");
    const end = endDate
      ? moment.tz(endDate, "Asia/Seoul").endOf("day")
      : moment().tz("Asia/Seoul").endOf("day");

    // 출석 기록 조회
    const attendances = await Attendance.find({
      studentId,
      timestamp: {
        $gte: start.format(),
        $lte: end.format(),
      },
    }).sort({ timestamp: 1 });

    // 월별 통계 계산
    const monthlyStats = {};
    const months = [];
    let currentMonth = start.clone();

    while (currentMonth.isSameOrBefore(end, "month")) {
      const monthKey = currentMonth.format("YYYY-MM");
      months.push(monthKey);
      monthlyStats[monthKey] = await calculateMonthStats(
        studentId,
        currentMonth
      );
      currentMonth.add(1, "month");
    }

    // 전체 기간 통계
    const totalStats = {
      total: attendances.length,
      present: attendances.filter((a) => a.status === "present").length,
      late: attendances.filter((a) => a.status === "late").length,
      absent: attendances.filter((a) => a.status === "absent" && !a.isExcused)
        .length,
      excused: attendances.filter((a) => a.isExcused).length,
      totalLateMinutes: attendances.reduce(
        (sum, a) => sum + (a.lateMinutes || 0),
        0
      ),
      attendanceRate:
        attendances.length > 0
          ? (
              (attendances.filter((a) => a.status === "present" || a.isExcused)
                .length /
                attendances.length) *
              100
            ).toFixed(1)
          : 0,
    };

    // 개선도 계산
    const improvements = [];
    for (let i = 1; i < months.length; i++) {
      const lastMonth = monthlyStats[months[i - 1]];
      const thisMonth = monthlyStats[months[i]];
      improvements.push({
        month: months[i],
        improvement: calculateImprovement(lastMonth, thisMonth),
      });
    }

    // 오늘의 출석 상태
    const today = moment().tz("Asia/Seoul").startOf("day");
    const todayAttendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: today.format("YYYY-MM-DD 00:00:00"),
        $lt: moment(today).add(1, "day").format("YYYY-MM-DD 00:00:00"),
      },
    });

    res.json({
      success: true,
      student: {
        studentId: student.studentId,
        name: student.name,
        grade: student.grade,
        class: student.class,
        number: student.number,
      },
      period: {
        start: start.format("YYYY-MM-DD"),
        end: end.format("YYYY-MM-DD"),
      },
      totalStats,
      monthlyStats,
      improvements,
      todayStatus: todayAttendance
        ? {
            status: todayAttendance.status,
            isExcused: todayAttendance.isExcused,
            lateMinutes: todayAttendance.lateMinutes,
            timestamp: todayAttendance.timestamp,
          }
        : null,
      attendances: attendances
        .map((a) => ({
          date: moment(a.timestamp).format("YYYY-MM-DD"),
          month: moment(a.timestamp).format("YYYY년 MM월"),
          status: a.status,
          isExcused: a.isExcused,
          lateMinutes: a.lateMinutes,
          reason: a.reason,
        }))
        .sort((a, b) => moment(b.date).diff(moment(a.date)))
        .reduce((groups, attendance) => {
          const month = attendance.month;
          if (!groups[month]) {
            groups[month] = [];
          }
          groups[month].push(attendance);
          return groups;
        }, {}),
    });
  } catch (error) {
    console.error("학생별 통계 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "통계 조회 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 인정결석 목록 조회 API 수정
app.get("/api/attendance/excused", verifyToken, async (req, res) => {
  try {
    const { grade, classNum, startDate, endDate, limit = 20 } = req.query;

    // 기본 쿼리 조건
    let query = { isExcused: true };

    // 날짜 범위 필터
    if (startDate || endDate) {
      query.timestamp = {};
      if (startDate) {
        query.timestamp.$gte = moment
          .tz(startDate, "Asia/Seoul")
          .startOf("day")
          .format();
      }
      if (endDate) {
        query.timestamp.$lte = moment
          .tz(endDate, "Asia/Seoul")
          .endOf("day")
          .format();
      }
    }

    // 학생 정보로 필터링하기 위한 학생 목록 조회
    let studentQuery = { isApproved: true };
    if (grade) studentQuery.grade = parseInt(grade);
    if (classNum) studentQuery.class = parseInt(classNum);

    if (grade || classNum) {
      const students = await User.find(studentQuery);
      const studentIds = students.map((student) => student.studentId);
      query.studentId = { $in: studentIds };
    }

    const excusedAttendances = await Attendance.find(query)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));

    // 학생 정보 조회를 위한 Promise.all 사용
    const excusedWithStudentInfo = await Promise.all(
      excusedAttendances.map(async (attendance) => {
        const student = await User.findOne({ studentId: attendance.studentId });
        return {
          _id: attendance._id,
          studentId: attendance.studentId,
          studentName: student ? student.name : "알 수 없음",
          grade: student ? student.grade : null,
          class: student ? student.class : null,
          number: student ? student.number : null,
          date: attendance.timestamp,
          reason: attendance.reason,
          excusedAt: attendance.excusedAt,
          excusedBy: attendance.excusedBy,
        };
      })
    );

    // 학년, 반 순으로 정렬
    const sortedExcused = excusedWithStudentInfo.sort((a, b) => {
      if (a.grade !== b.grade) return a.grade - b.grade;
      if (a.class !== b.class) return a.class - b.class;
      return a.number - b.number;
    });

    res.json({
      success: true,
      excused: sortedExcused,
      total: await Attendance.countDocuments(query),
    });
  } catch (error) {
    console.error("인정결석 목록 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "인정결석 목록 조회 중 오류가 발생했습니다.",
    });
  }
});

// Holiday 모델 수정 (source 필드 추가)
const HolidaySchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  reason: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  source: {
    type: String,
    enum: ["MANUAL", "NEIS", "SYSTEM"],
    default: "MANUAL",
  },
});

// 날짜 검증을 위한 미들웨어 추가
HolidaySchema.pre("save", function (next) {
  if (this.date) {
    this.date = moment(this.date).startOf("day").toDate();
  }
  next();
});

const Holiday = mongoose.model("Holiday", HolidaySchema);

// 휴일 등록 API 수정
app.post("/api/holidays", verifyToken, isAdmin, async (req, res) => {
  try {
    const { date, reason } = req.body;

    // 입력값 검증
    if (!date || !reason) {
      return res.status(400).json({
        success: false,
        message: "날짜와 사유를 모두 입력해주세요.",
      });
    }

    // 날짜 형식 검증
    const holidayDate = moment(date);
    if (!holidayDate.isValid()) {
      return res.status(400).json({
        success: false,
        message: "유효하지 않은 날짜 형식입니다.",
      });
    }

    const formattedDate = holidayDate.startOf("day").toDate();

    // 이미 존재하는 휴일인지 확인
    const existingHoliday = await Holiday.findOne({
      date: formattedDate,
    });

    if (existingHoliday) {
      return res.status(400).json({
        success: false,
        message: "이미 등록된 휴일입니다.",
        existingHoliday: {
          date: moment(existingHoliday.date).format("YYYY-MM-DD"),
          reason: existingHoliday.reason,
          source: existingHoliday.source,
        },
      });
    }

    const holiday = new Holiday({
      date: formattedDate,
      reason,
      createdBy: req.user.id,
      source: "MANUAL",
    });

    await holiday.save();

    res.status(201).json({
      success: true,
      message: "휴일이 성공적으로 등록되었습니다.",
      holiday: {
        id: holiday._id,
        date: moment(holiday.date).format("YYYY-MM-DD"),
        reason: holiday.reason,
        createdBy: req.user.name || "관리자",
        source: "MANUAL",
      },
    });
  } catch (error) {
    console.error("휴일 등록 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "휴일 등록 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 휴일 목록 조회 API 수정
app.get("/api/holidays", verifyToken, async (req, res) => {
  try {
    const { year, month } = req.query;
    let query = {};

    if (year && month) {
      const startDate = moment(`${year}-${month}-01`).startOf("month").toDate();
      const endDate = moment(startDate).endOf("month").toDate();
      query.date = {
        $gte: startDate,
        $lte: endDate,
      };
    }

    const holidays = await Holiday.find(query)
      .sort({ date: 1 })
      .populate("createdBy", "name");

    res.json({
      success: true,
      holidays: holidays.map((h) => ({
        id: h._id,
        date: moment(h.date).format("YYYY-MM-DD"),
        reason: h.reason,
        createdAt: moment(h.createdAt).format("YYYY-MM-DD HH:mm:ss"),
        createdBy: h.createdBy?.name || "관리자",
        source: h.source || "MANUAL",
      })),
    });
  } catch (error) {
    console.error("휴일 목록 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "휴일 목록 조회 중 오류가 발생했습니다.",
    });
  }
});

// 휴일 삭제 API 수정
app.delete("/api/holidays/:id", verifyToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const holiday = await Holiday.findById(id);
    if (!holiday) {
      return res.status(404).json({
        success: false,
        message: "해당 휴일을 찾을 수 없습니다.",
      });
    }

    await Holiday.findByIdAndDelete(id);

    res.json({
      success: true,
      message: "휴일이 성공적으로 삭제되었습니다.",
      deletedHoliday: {
        id: holiday._id,
        date: moment(holiday.date).format("YYYY-MM-DD"),
        reason: holiday.reason,
      },
    });
  } catch (error) {
    console.error("휴일 삭제 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "휴일 삭제 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 인정결석 삭제 API 추가
app.delete(
  "/api/attendance/excuse/:id",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      const attendance = await Attendance.findById(id);
      if (!attendance) {
        return res.status(404).json({
          success: false,
          message: "해당 인정결석 기록을 찾을 수 없습니다.",
        });
      }

      // 인정결석 상태 제거
      attendance.isExcused = false;
      attendance.reason = null;
      attendance.excusedAt = null;
      attendance.excusedBy = null;

      await attendance.save();

      res.json({
        success: true,
        message: "인정결석이 취소되었습니다.",
      });
    } catch (error) {
      console.error("인정결석 삭제 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "인정결석 삭제 중 오류가 발생했습니다.",
      });
    }
  }
);

// 단체 인정결석 처리 API 추가
app.post(
  "/api/attendance/excuse-group",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { date, reason, filters } = req.body;

      if (!date || !reason || !filters) {
        return res.status(400).json({
          success: false,
          message: "날짜, 사유, 필터 조건이 모두 필요합니다.",
        });
      }

      // 필터 조건에 맞는 학생들 조회
      let query = { isApproved: true };

      if (filters.grade) {
        query.grade = filters.grade;
      }
      if (filters.class) {
        query.class = filters.class;
      }
      if (filters.studentIds && filters.studentIds.length > 0) {
        query.studentId = { $in: filters.studentIds };
      }

      const students = await User.find(query);

      if (students.length === 0) {
        return res.status(404).json({
          success: false,
          message: "조건에 맞는 학생이 없습니다.",
        });
      }

      const startOfDay = moment.tz(date, "Asia/Seoul").startOf("day");
      const endOfDay = moment.tz(date, "Asia/Seoul").endOf("day");

      // 각 학생에 대해 인정결석 처리
      const results = await Promise.all(
        students.map(async (student) => {
          // 기존 출석 기록 확인
          let attendance = await Attendance.findOne({
            studentId: student.studentId,
            timestamp: {
              $gte: startOfDay.format(),
              $lt: endOfDay.format(),
            },
          });

          if (!attendance) {
            // 출석 기록이 없는 경우 새로 생성
            attendance = new Attendance({
              studentId: student.studentId,
              timestamp: startOfDay.format(),
              status: "absent",
              isExcused: true,
              reason,
              excusedAt: new Date(),
              excusedBy: req.user.id,
            });
          } else {
            // 기존 기록을 인정결석으로 변경
            attendance.status = "absent";
            attendance.isExcused = true;
            attendance.reason = reason;
            attendance.excusedAt = new Date();
            attendance.excusedBy = req.user.id;
          }

          await attendance.save();
          return {
            studentId: student.studentId,
            name: student.name,
            success: true,
          };
        })
      );

      res.json({
        success: true,
        message: `${results.length}명의 학생이 인정결석 처리되었습니다.`,
        results,
      });
    } catch (error) {
      console.error("단체 인정결석 처리 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "단체 인정결석 처리 중 오류가 발생했습니다.",
        error: error.message,
      });
    }
  }
);

// 환경 변수 검증 함수에 NEIS_API_KEY 추가
function validateEnvVariables() {
  const requiredEnvVars = [
    "MONGODB_URI",
    "JWT_SECRET",
    "REFRESH_TOKEN_SECRET",
    "ENCRYPTION_KEY",
    "NEIS_API_KEY",
  ];

  const missingEnvVars = requiredEnvVars.filter(
    (envVar) => !process.env[envVar]
  );

  if (missingEnvVars.length > 0) {
    console.error("필수 환경 변수가 설정되지 않았습니다:", missingEnvVars);
    process.exit(1);
  }

  // ENCRYPTION_KEY 검증
  if (process.env.ENCRYPTION_KEY.length !== 32) {
    console.error("ENCRYPTION_KEY는 정확히 32자여야 합니다.");
    process.exit(1);
  }
}

// 서버 시작 전에 환경 변수 검증
validateEnvVariables();

// XSS 방지를 위한 미들웨어 추가
app.use(helmet.xssFilter());
app.use(helmet.noSniff());

// CORS 설정 강화
// app.use(
//   cors({
//     origin:
//       process.env.NODE_ENV === "production"
//         ? ["https://attendhs.netlify.app"]
//         : ["http://localhost:5500"],
//     methods: ["GET", "POST", "PUT", "DELETE"],
//     allowedHeaders: ["Content-Type", "Authorization"],
//     credentials: true,
//   })
// );

app.use(
  cors({
    origin: true, // 모든 origin 허용
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);

// 출결 설정 조회 API
app.get("/api/settings/attendance", verifyToken, async (req, res) => {
  try {
    const settings = await AttendanceSettings.findOne()
      .sort({ updatedAt: -1 })
      .populate("updatedBy", "name");

    if (!settings) {
      const defaultSettings = new AttendanceSettings({
        startTime: "07:30",
        normalTime: "08:03",
        lateTime: "09:00",
        autoAbsentTime: "09:00",
      });
      await defaultSettings.save();
      return res.json({
        success: true,
        settings: {
          startTime: defaultSettings.startTime,
          normalTime: defaultSettings.normalTime,
          lateTime: defaultSettings.lateTime,
          autoAbsentTime: defaultSettings.autoAbsentTime,
          updatedAt: defaultSettings.updatedAt,
          updatedBy: null,
        },
      });
    }

    res.json({
      success: true,
      settings: {
        startTime: settings.startTime,
        normalTime: settings.normalTime,
        lateTime: settings.lateTime,
        autoAbsentTime: settings.autoAbsentTime,
        updatedAt: settings.updatedAt,
        updatedBy: settings.updatedBy?.name,
      },
    });
  } catch (error) {
    console.error("출결 설정 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "출결 설정 조회 중 오류가 발생했습니다.",
    });
  }
});

// NEIS API 관련 상수 추가
const NEIS_API_KEY = process.env.NEIS_API_KEY;
const SCHOOL_CODE = "8490065"; // 완도고등학교
const OFFICE_CODE = "Q10"; // 전라남도교육청

// 학사일정을 휴일로 자동 등록하는 API 수정
app.post("/api/holidays/sync-neis", verifyToken, isAdmin, async (req, res) => {
  try {
    const { year, month } = req.body;

    if (!year || !month) {
      return res.status(400).json({
        success: false,
        message: "년도와 월을 지정해주세요.",
      });
    }

    const fromDate = `${year}${String(month).padStart(2, "0")}01`;
    const toDate = `${year}${String(month).padStart(2, "0")}${new Date(
      year,
      month,
      0
    ).getDate()}`;

    // NEIS API 호출
    const response = await axios.get(
      "https://open.neis.go.kr/hub/SchoolSchedule",
      {
        params: {
          KEY: NEIS_API_KEY,
          Type: "json",
          ATPT_OFCDC_SC_CODE: OFFICE_CODE,
          SD_SCHUL_CODE: SCHOOL_CODE,
          AA_FROM_YMD: fromDate,
          AA_TO_YMD: toDate,
        },
      }
    );

    // NEIS API 응답 처리
    let schedules = [];
    if (response.data.SchoolSchedule) {
      schedules = response.data.SchoolSchedule[1].row;
    }

    const addedHolidays = [];
    const skippedDates = [];

    // 휴일로 처리할 이벤트 유형 정의
    const holidayEventTypes = [
      "공휴일",
      "방학",
      "휴업일",
      "재량휴업일",
      "학교장재량휴업일",
      "단기방학",
      "하계방학",
      "동계방학",
      "창립기념일",
      "개교기념일",
      "명절",
      "추석",
      "설날",
      "봄방학",
      "여름방학",
      "겨울방학",
    ];

    // 주말 자동 등록 (토, 일요일)
    const startMoment = moment(
      `${year}-${String(month).padStart(2, "0")}-01`,
      "YYYY-MM-DD"
    );
    const endMoment = startMoment.clone().endOf("month");
    let currentDate = startMoment.clone();

    while (currentDate.isSameOrBefore(endMoment)) {
      if (currentDate.day() === 0 || currentDate.day() === 6) {
        const existingHoliday = await Holiday.findOne({
          date: currentDate.toDate(),
        });

        if (!existingHoliday) {
          const holiday = new Holiday({
            date: currentDate.toDate(),
            reason: currentDate.day() === 0 ? "일요일" : "토요일",
            createdBy: req.user.id,
            source: "SYSTEM",
          });
          await holiday.save();
          addedHolidays.push({
            date: currentDate.format("YYYY-MM-DD"),
            reason: currentDate.day() === 0 ? "일요일" : "토요일",
          });
        }
      }
      currentDate.add(1, "days");
    }

    // NEIS 학사일정 처리
    for (const schedule of schedules) {
      const eventName = schedule.EVENT_NM;
      const date = moment(schedule.AA_YMD, "YYYYMMDD").startOf("day");

      // 이미 등록된 휴일인지 확인
      const existingHoliday = await Holiday.findOne({
        date: date.toDate(),
      });

      if (existingHoliday) {
        skippedDates.push({
          date: date.format("YYYY-MM-DD"),
          reason: eventName,
          status: "이미 등록됨",
        });
        continue;
      }

      // 휴일 이벤트인지 확인
      const isHoliday = holidayEventTypes.some(
        (type) =>
          eventName.includes(type) ||
          (eventName.includes("휴일") && !eventName.includes("휴일안내"))
      );

      if (isHoliday) {
        const holiday = new Holiday({
          date: date.toDate(),
          reason: eventName,
          createdBy: req.user.id,
          source: "NEIS",
        });

        await holiday.save();
        addedHolidays.push({
          date: date.format("YYYY-MM-DD"),
          reason: eventName,
        });
      }
    }

    const message =
      addedHolidays.length > 0
        ? `${addedHolidays.length}개의 휴일이 등록되었습니다.`
        : "새로 등록할 휴일이 없습니다.";

    res.json({
      success: true,
      message,
      addedHolidays,
      skippedDates,
    });
  } catch (error) {
    console.error("NEIS 학사일정 동기화 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "학사일정 동기화 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 학사일정 조회 API 수정
app.get("/api/schedule", async (req, res) => {
  try {
    const { year, month } = req.query;
    const fromDate = `${year}${String(month).padStart(2, "0")}01`;
    const toDate = `${year}${String(month).padStart(2, "0")}${new Date(
      year,
      month,
      0
    ).getDate()}`;

    const response = await axios.get(
      "https://open.neis.go.kr/hub/SchoolSchedule",
      {
        params: {
          KEY: NEIS_API_KEY,
          Type: "json",
          ATPT_OFCDC_SC_CODE: OFFICE_CODE,
          SD_SCHUL_CODE: SCHOOL_CODE,
          AA_FROM_YMD: fromDate,
          AA_TO_YMD: toDate,
        },
      }
    );

    // NEIS API 응답 처리
    let schedules = [];
    if (response.data.SchoolSchedule) {
      schedules = response.data.SchoolSchedule[1].row.map((schedule) => ({
        date: moment(schedule.AA_YMD, "YYYYMMDD").format("YYYY-MM-DD"),
        eventName: schedule.EVENT_NM,
        isHoliday:
          [
            "공휴일",
            "방학",
            "휴업일",
            "재량휴업일",
            "학교장재량휴업일",
            "단기방학",
            "하계방학",
            "동계방학",
            "창립기념일",
            "개교기념일",
            "명절",
            "추석",
            "설날",
            "봄방학",
            "여름방학",
            "겨울방학",
          ].some((type) => schedule.EVENT_NM.includes(type)) ||
          (schedule.EVENT_NM.includes("휴일") &&
            !schedule.EVENT_NM.includes("휴일안내")),
      }));
    }

    // 주말 추가
    const startMoment = moment(
      `${year}-${String(month).padStart(2, "0")}-01`,
      "YYYY-MM-DD"
    );
    const endMoment = startMoment.clone().endOf("month");
    let currentDate = startMoment.clone();

    while (currentDate.isSameOrBefore(endMoment)) {
      if (currentDate.day() === 0 || currentDate.day() === 6) {
        schedules.push({
          date: currentDate.format("YYYY-MM-DD"),
          eventName: currentDate.day() === 0 ? "일요일" : "토요일",
          isHoliday: true,
        });
      }
      currentDate.add(1, "days");
    }

    // 날짜순으로 정렬
    schedules.sort((a, b) => moment(a.date).diff(moment(b.date)));

    // 이미 등록된 휴일 정보 조회
    const existingHolidays = await Holiday.find({
      date: {
        $gte: startMoment.toDate(),
        $lte: endMoment.toDate(),
      },
    });

    // 스케줄에 휴일 등록 여부 추가
    const schedulesWithHolidayInfo = schedules.map((schedule) => ({
      ...schedule,
      isRegisteredHoliday: existingHolidays.some(
        (holiday) => moment(holiday.date).format("YYYY-MM-DD") === schedule.date
      ),
    }));

    res.json({
      success: true,
      schedules: schedulesWithHolidayInfo,
    });
  } catch (error) {
    console.error("학사일정 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "학사일정 조회 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 서버 시작 시 기본 출결 설정 확인 및 생성
async function initializeAttendanceSettings() {
  try {
    const settings = await AttendanceSettings.findOne().sort({ updatedAt: -1 });
    if (!settings) {
      const defaultSettings = new AttendanceSettings({
        startTime: "07:30",
        normalTime: "08:03",
        lateTime: "09:00",
      });
      await defaultSettings.save();
      logger.info("기본 출결 설정이 생성되었습니다.");
    }
  } catch (error) {
    logger.error("기본 출결 설정 초기화 중 오류: " + error.message);
  }
}

// 서버 시작 시 초기화 함수들 실행
async function initializeServer() {
  try {
    await initializeAttendanceSettings();
    await setupAutoAbsentSchedule();
    logger.info("서버 초기화가 완료되었습니다.");
  } catch (error) {
    logger.error("서버 초기화 중 오류: " + error.message);
  }
}

// Promise.all 대신 단일 초기화 함수 호출
initializeServer();

// 엑셀 다운로드 API 추가
app.get("/api/attendance/export", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, grade, classNum } = req.query;

    // 필터 조건 설정
    let query = {};
    if (startDate && endDate) {
      query.timestamp = {
        $gte: moment.tz(startDate, "Asia/Seoul").startOf("day").format(),
        $lte: moment.tz(endDate, "Asia/Seoul").endOf("day").format(),
      };
    }

    // 학생 필터링
    let userQuery = { isApproved: true };
    if (grade) userQuery.grade = parseInt(grade);
    if (classNum) userQuery.class = parseInt(classNum);

    // 학생 목록 조회
    const students = await User.find(userQuery).sort({
      grade: 1,
      class: 1,
      number: 1,
    });

    // 각 학생별 출석 데이터 수집
    const attendanceData = await Promise.all(
      students.map(async (student) => {
        const attendances = await Attendance.find({
          ...query,
          studentId: student.studentId,
        }).sort({ timestamp: 1 });

        const presentCount = attendances.filter(
          (a) => a.status === "present"
        ).length;
        const lateCount = attendances.filter((a) => a.status === "late").length;
        const absentCount = attendances.filter(
          (a) => a.status === "absent" && !a.isExcused
        ).length;
        const excusedCount = attendances.filter((a) => a.isExcused).length;
        const totalLateMinutes = attendances.reduce(
          (sum, a) => sum + (a.lateMinutes || 0),
          0
        );

        return {
          학년: student.grade,
          반: student.class,
          번호: student.number,
          학번: student.studentId,
          이름: student.name,
          출석: presentCount,
          지각: lateCount,
          결석: absentCount,
          인정결석: excusedCount,
          "지각시간(분)": totalLateMinutes,
          "출석률(%)": attendances.length
            ? (
                ((presentCount + excusedCount) / attendances.length) *
                100
              ).toFixed(1)
            : "100.0",
        };
      })
    );

    // 엑셀 워크북 생성
    const wb = XLSX.utils.book_new();
    const ws = XLSX.utils.json_to_sheet(attendanceData);

    // 열 너비 설정
    const colWidths = {
      A: 5, // 학년
      B: 5, // 반
      C: 5, // 번호
      D: 10, // 학번
      E: 10, // 이름
      F: 8, // 출석
      G: 8, // 지각
      H: 8, // 결석
      I: 10, // 인정결석
      J: 12, // 지각시간
      K: 10, // 출석률
    };

    ws["!cols"] = Object.keys(colWidths).map((key) => ({
      wch: colWidths[key],
    }));

    // 워크시트를 워크북에 추가
    XLSX.utils.book_append_sheet(wb, ws, "출결현황");

    // 파일 이름 설정
    const fileName = `출결현황_${moment().format("YYYY-MM-DD")}.xlsx`;
    const encodedFileName = encodeURIComponent(fileName);

    // 파일 생성 및 전송
    const excelBuffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      `attachment; filename*=UTF-8''${encodedFileName}`
    );
    res.send(excelBuffer);
  } catch (error) {
    console.error("엑셀 파일 생성 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "엑셀 파일 생성 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 상세 출결 데이터 엑셀 다운로드 API 추가
app.get(
  "/api/attendance/export/detail",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { startDate, endDate, grade, classNum } = req.query;

      // 필터 조건 설정
      let query = {};
      if (startDate && endDate) {
        query.timestamp = {
          $gte: moment.tz(startDate, "Asia/Seoul").startOf("day").format(),
          $lte: moment.tz(endDate, "Asia/Seoul").endOf("day").format(),
        };
      }

      // 학생 필터링
      let userQuery = { isApproved: true };
      if (grade) userQuery.grade = parseInt(grade);
      if (classNum) userQuery.class = parseInt(classNum);

      // 학생 목록 조회
      const students = await User.find(userQuery).sort({
        grade: 1,
        class: 1,
        number: 1,
      });

      // 날짜 범위 생성
      const start = moment.tz(startDate, "Asia/Seoul").startOf("day");
      const end = moment.tz(endDate, "Asia/Seoul").endOf("day");
      const dates = [];
      let current = start.clone();

      while (current.isSameOrBefore(end)) {
        dates.push(current.format("YYYY-MM-DD"));
        current.add(1, "days");
      }

      // 각 학생별 상세 출결 데이터 수집
      const detailedData = [];

      for (const student of students) {
        const attendances = await Attendance.find({
          ...query,
          studentId: student.studentId,
        });

        const attendanceMap = new Map(
          attendances.map((a) => [
            moment(a.timestamp).format("YYYY-MM-DD"),
            {
              status: a.status,
              isExcused: a.isExcused,
              lateMinutes: a.lateMinutes,
              reason: a.reason,
            },
          ])
        );

        const studentRow = {
          학년: student.grade,
          반: student.class,
          번호: student.number,
          학번: student.studentId,
          이름: student.name,
        };

        // 각 날짜별 출결 상태 추가
        dates.forEach((date) => {
          const attendance = attendanceMap.get(date);
          let status = "-";
          if (attendance) {
            if (attendance.isExcused) {
              status = `인정(${attendance.reason || ""})`;
            } else {
              switch (attendance.status) {
                case "present":
                  status = "출석";
                  break;
                case "late":
                  status = `지각(${attendance.lateMinutes}분)`;
                  break;
                case "absent":
                  status = "결석";
                  break;
              }
            }
          }
          studentRow[date] = status;
        });

        detailedData.push(studentRow);
      }

      // 엑셀 워크북 생성
      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(detailedData);

      // 열 너비 설정
      const baseColWidths = {
        A: 5, // 학년
        B: 5, // 반
        C: 5, // 번호
        D: 10, // 학번
        E: 10, // 이름
      };

      // 날짜 열의 너비 설정
      const dateColWidths = {};
      dates.forEach((_, index) => {
        dateColWidths[String.fromCharCode(70 + index)] = 15;
      });

      ws["!cols"] = Object.keys({ ...baseColWidths, ...dateColWidths }).map(
        (key) => ({
          wch: { ...baseColWidths, ...dateColWidths }[key],
        })
      );

      // 워크시트를 워크북에 추가
      XLSX.utils.book_append_sheet(wb, ws, "상세출결현황");

      // 파일 이름 설정
      const fileName = `상세출결현황_${moment().format("YYYY-MM-DD")}.xlsx`;
      const encodedFileName = encodeURIComponent(fileName);

      // 파일 생성 및 전송
      const excelBuffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename*=UTF-8''${encodedFileName}`
      );
      res.send(excelBuffer);
    } catch (error) {
      console.error("상세 엑셀 파일 생성 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "상세 엑셀 파일 생성 중 오류가 발생했습니다.",
        error: error.message,
      });
    }
  }
);

// 인정결석 엑셀 다운로드 API 추가
app.get(
  "/api/attendance/export/excused",
  verifyToken,
  isAdmin,
  async (req, res) => {
    try {
      const { startDate, endDate, grade, classNum } = req.query;

      // 기본 쿼리 조건
      let query = { isExcused: true };

      // 날짜 범위 필터
      if (startDate || endDate) {
        query.timestamp = {};
        if (startDate) {
          query.timestamp.$gte = moment
            .tz(startDate, "Asia/Seoul")
            .startOf("day")
            .format();
        }
        if (endDate) {
          query.timestamp.$lte = moment
            .tz(endDate, "Asia/Seoul")
            .endOf("day")
            .format();
        }
      }

      // 학생 필터링
      let studentQuery = { isApproved: true };
      if (grade) studentQuery.grade = parseInt(grade);
      if (classNum) studentQuery.class = parseInt(classNum);

      if (grade || classNum) {
        const students = await User.find(studentQuery);
        const studentIds = students.map((student) => student.studentId);
        query.studentId = { $in: studentIds };
      }

      // 인정결석 데이터 조회
      const excusedAttendances = await Attendance.find(query).sort({
        timestamp: -1,
      });

      // 엑셀 데이터 준비
      const excelData = await Promise.all(
        excusedAttendances.map(async (attendance) => {
          const student = await User.findOne({
            studentId: attendance.studentId,
          });
          const excusedBy = await User.findById(attendance.excusedBy);

          return {
            날짜: moment(attendance.timestamp).format("YYYY-MM-DD"),
            학년: student ? student.grade : "-",
            반: student ? student.class : "-",
            번호: student ? student.number : "-",
            학번: attendance.studentId,
            이름: student ? student.name : "알 수 없음",
            사유: attendance.reason || "-",
            처리일시: moment(attendance.excusedAt).format(
              "YYYY-MM-DD HH:mm:ss"
            ),
            처리자: excusedBy ? excusedBy.name : "알 수 없음",
          };
        })
      );

      // 엑셀 워크북 생성
      const wb = XLSX.utils.book_new();
      const ws = XLSX.utils.json_to_sheet(excelData);

      // 열 너비 설정
      const colWidths = {
        A: 12, // 날짜
        B: 5, // 학년
        C: 5, // 반
        D: 5, // 번호
        E: 10, // 학번
        F: 10, // 이름
        G: 30, // 사유
        H: 20, // 처리일시
        I: 10, // 처리자
      };

      ws["!cols"] = Object.keys(colWidths).map((key) => ({
        wch: colWidths[key],
      }));

      // 워크시트를 워크북에 추가
      XLSX.utils.book_append_sheet(wb, ws, "인정결석현황");

      // 파일 이름 설정
      const fileName = `인정결석현황_${moment().format("YYYY-MM-DD")}.xlsx`;
      const encodedFileName = encodeURIComponent(fileName);

      // 파일 생성 및 전송
      const excelBuffer = XLSX.write(wb, { type: "buffer", bookType: "xlsx" });

      res.setHeader(
        "Content-Type",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
      );
      res.setHeader(
        "Content-Disposition",
        `attachment; filename*=UTF-8''${encodedFileName}`
      );
      res.send(excelBuffer);
    } catch (error) {
      console.error("인정결석 엑셀 파일 생성 중 오류:", error);
      res.status(500).json({
        success: false,
        message: "인정결석 엑셀 파일 생성 중 오류가 발생했습니다.",
        error: error.message,
      });
    }
  }
);

// 단일 사용자 정보 조회 API
app.get("/api/admin/users/:userId", verifyToken, isAdmin, async (req, res) => {
  try {
    const { userId } = req.params;
    const user = await User.findById(userId)
      .select("-password")
      .populate("device"); // device 정보를 함께 가져옴

    if (!user) {
      return res.status(404).json({ message: "사용자를 찾을 수 없습니다." });
    }

    // 디바이스 정보가 있는 경우 응답에 포함
    const device = await Device.findOne({ userId: user._id });
    const responseData = {
      ...user.toObject(),
      deviceInfo: device ? device.deviceInfo : null,
      deviceId: device ? device.deviceId : null,
    };

    res.json(responseData);
  } catch (error) {
    console.error("Error fetching user:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

// 디바이스 스키마 추가
const DeviceSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  deviceId: { type: String, required: true, unique: true },
  deviceInfo: {
    model: String,
    platform: String,
    version: String,
    isEmulator: Boolean,
    lastLogin: { type: Date, default: Date.now }, // lastLogin을 deviceInfo 내부로 이동
  },
});

DeviceSchema.index({ deviceId: 1 }, { unique: true });
const Device = mongoose.model("Device", DeviceSchema);

// 디바이스 등록 해제 API 수정
app.delete("/api/device", verifyToken, async (req, res) => {
  try {
    const { deviceId } = req.body;

    if (!deviceId) {
      return res.status(400).json({
        success: false,
        message: "디바이스 ID가 필요합니다.",
      });
    }

    // 디바이스 찾기
    const device = await Device.findOne({ deviceId });
    if (!device) {
      return res.status(404).json({
        success: false,
        message: "등록되지 않은 디바이스입니다.",
      });
    }

    // 권한 확인
    if (device.userId.toString() !== req.user.id) {
      return res.status(403).json({
        success: false,
        message: "이 디바이스를 해제할 권한이 없습니다.",
      });
    }

    // User 모델에서 디바이스 참조 제거
    await User.findByIdAndUpdate(device.userId, {
      $unset: { deviceId: "", device: "" },
    });

    // 디바이스 삭제
    await Device.deleteOne({ deviceId });

    res.json({
      success: true,
      message: "디바이스가 성공적으로 해제되었습니다.",
    });
  } catch (error) {
    console.error("Device unregister error:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다.",
      error: error.message,
    });
  }
});

// 처리 로그 조회 API
app.get("/api/process-logs", verifyToken, isAdmin, async (req, res) => {
  try {
    const logs = await ProcessLog.find()
      .sort({ processDate: -1, processTime: -1 })
      .limit(20); // 최근 20개 로그만 반환

    res.json({
      success: true,
      logs: logs.map((log) => ({
        type: log.type,
        processDate: log.processDate,
        processTime: log.processTime,
        processedCount: log.processedCount,
        details: log.details,
      })),
    });
  } catch (error) {
    console.error("처리 로그 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "처리 로그 조회 중 오류가 발생했습니다.",
    });
  }
});

// 출결 설정 조회 API
app.get("/api/settings/attendance", verifyToken, async (req, res) => {
  try {
    const settings = await AttendanceSettings.findOne()
      .sort({ updatedAt: -1 })
      .populate("updatedBy", "name");

    if (!settings) {
      // 기본 설정값 반환
      return res.json({
        success: true,
        settings: {
          startTime: "07:30",
          normalTime: "08:03",
          lateTime: "09:00",
          autoAbsentTime: "09:00",
          updatedAt: new Date(),
          updatedBy: null,
        },
      });
    }

    res.json({
      success: true,
      settings: {
        startTime: settings.startTime,
        normalTime: settings.normalTime,
        lateTime: settings.lateTime,
        autoAbsentTime: settings.autoAbsentTime,
        updatedAt: settings.updatedAt,
        updatedBy: settings.updatedBy?.name,
      },
    });
  } catch (error) {
    console.error("출결 설정 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "출결 설정 조회 중 오류가 발생했습니다.",
    });
  }
});

// 출결 설정 업데이트 API
app.put("/api/settings/attendance", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startTime, normalTime, lateTime, autoAbsentTime } = req.body;

    // 시간 형식 검증 (HH:mm)
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
    if (
      !timeRegex.test(startTime) ||
      !timeRegex.test(normalTime) ||
      !timeRegex.test(lateTime) ||
      !timeRegex.test(autoAbsentTime)
    ) {
      return res.status(400).json({
        success: false,
        message: "잘못된 시간 형식입니다. (HH:mm)",
      });
    }

    // 시간 순서 검증
    const start = moment(startTime, "HH:mm");
    const normal = moment(normalTime, "HH:mm");
    const late = moment(lateTime, "HH:mm");
    const autoAbsent = moment(autoAbsentTime, "HH:mm");

    if (
      start.isAfter(normal) ||
      normal.isAfter(late) ||
      late.isAfter(autoAbsent)
    ) {
      return res.status(400).json({
        success: false,
        message: "시간 순서가 올바르지 않습니다.",
      });
    }

    const settings = new AttendanceSettings({
      startTime,
      normalTime,
      lateTime,
      autoAbsentTime,
      updatedBy: req.user.id,
    });

    await settings.save();

    // 자동 결석 처리 스케줄 재설정
    try {
      const scheduleResult = await setupAutoAbsentSchedule();
      logger.info(
        "[설정] 자동 결석 처리 스케줄이 업데이트되었습니다:",
        scheduleResult
      );
    } catch (scheduleError) {
      logger.error("[설정] 스케줄 업데이트 중 오류:", scheduleError);
      return res.status(500).json({
        success: false,
        message:
          "출결 설정은 저장되었으나, 자동 결석 처리 스케줄 업데이트에 실패했습니다.",
        error: scheduleError.message,
      });
    }

    res.json({
      success: true,
      message: "출결 설정이 업데이트되었습니다.",
      settings: {
        startTime: settings.startTime,
        normalTime: settings.normalTime,
        lateTime: settings.lateTime,
        autoAbsentTime: settings.autoAbsentTime,
        updatedAt: settings.updatedAt,
        updatedBy: req.user.name,
      },
    });
  } catch (error) {
    console.error("출결 설정 업데이트 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "출결 설정 업데이트 중 오류가 발생했습니다.",
      error: error.message,
    });
  }
});
