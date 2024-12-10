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
  const MAX_ATTEMPTS = process.env.MAX_LOGIN_ATTEMPTS || 50;  // 기본값 10회
  const LOCKOUT_TIME = process.env.LOGIN_LOCKOUT_TIME || 5 * 60 * 1000;  // 기본값 5분

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
    const { studentId, password, keepLoggedIn } = req.body;
    const ip = req.ip;

    // 입력값 검증
    if (!studentId || !password) {
      return res.status(400).json({
        success: false,
        message: "학번과 비밀번호를 모두 입력해주세요."
      });
    }

    // 사용자 찾기
    const user = await User.findOne({ studentId });
    if (!user) {
      incrementLoginAttempts(ip);
      return res.status(401).json({
        success: false,
        message: "존재하지 않는 학번입니다."
      });
    }

    // 계정 승인 여부 확인
    if (!user.isApproved) {
      return res.status(403).json({
        success: false,
        message: "아직 승인되지 않은 계정입니다. 관리자의 승인을 기다려주세요."
      });
    }

    // 비밀번호 확인
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      incrementLoginAttempts(ip);
      return res.status(401).json({
        success: false,
        message: "비밀번호가 일치하지 않습니다."
      });
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
      expiresAt: new Date(Date.now() + getRefreshTokenExpiresIn(keepLoggedIn))
    });

    // 기존 리프레시 토큰 삭제 후 새로 저장
    await RefreshToken.deleteMany({ userId: user._id });
    await refreshTokenDoc.save();

    // 응답
    res.json({
      success: true,
      accessToken,
      refreshToken,
      user: {
        id: user._id,
        studentId: user.studentId,
        name: user.name,
        isAdmin: user.isAdmin,
        isReader: user.isReader
      },
      redirectUrl: user.isAdmin || user.isReader ? "/hub.html" : "/qr.html"
    });

  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다."
    });
  }
});

// 로그인 시도 횟수 증가 함수
function incrementLoginAttempts(ip) {
  const MAX_ATTEMPTS = process.env.MAX_LOGIN_ATTEMPTS || 10;
  const currentAttempts = loginAttempts.get(ip) || {
    count: 0,
    timestamp: Date.now(),
  };

  // 최대 시도 횟수에 도달하면 타임스탬프 갱신
  if (currentAttempts.count >= MAX_ATTEMPTS) {
    currentAttempts.timestamp = Date.now();
  } else {
    currentAttempts.count += 1;
  }

  loginAttempts.set(ip, currentAttempts);
}

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
const ATTENDANCE_START_TIME = "08:30"; // 출석 시작 시간
const NORMAL_ATTENDANCE_TIME = "08:40"; // 정상 출석 마감 시간
const LATE_ATTENDANCE_TIME = "09:00"; // 지각 마감 시간

// determineAttendanceStatus 함수 수정
async function determineAttendanceStatus(timestamp) {
  try {
    const koreanTime = moment.tz(
      timestamp,
      "YYYY-MM-DD HH:mm:ss",
      "Asia/Seoul"
    );
    const currentDate = koreanTime.clone().startOf("day");

    // 주말 체크
    const isWeekend = koreanTime.day() === 0 || koreanTime.day() === 6;
    if (isWeekend) {
      return {
        status: "weekend",
        message: "주말은 출석체크를 하지 않습니다.",
        success: false,
      };
    }

    // 휴일 체크
    const isHoliday = await Holiday.findOne({
      date: currentDate.toDate(),
    });
    if (isHoliday) {
      return {
        status: "holiday",
        message: `휴일(${isHoliday.reason})은 출석체크를 하지 않습니다.`,
        success: false,
      };
    }

    const [startHour, startMinute] =
      ATTENDANCE_START_TIME.split(":").map(Number);
    const [normalHour, normalMinute] =
      NORMAL_ATTENDANCE_TIME.split(":").map(Number);
    const [lateHour, lateMinute] = LATE_ATTENDANCE_TIME.split(":").map(Number);

    const startTime = currentDate
      .clone()
      .add(startHour, "hours")
      .add(startMinute, "minutes");
    const normalTime = currentDate
      .clone()
      .add(normalHour, "hours")
      .add(normalMinute, "minutes");
    const lateTime = currentDate
      .clone()
      .add(lateHour, "hours")
      .add(lateMinute, "minutes");

    // 출석 시작 시간 전
    if (koreanTime.isBefore(startTime)) {
      return {
        status: "early",
        message: "아직 출석 시간이 아닙니다.",
        success: false,
      };
    }

    // 정상 출석
    if (koreanTime.isSameOrBefore(normalTime)) {
      return {
        status: "present",
        lateMinutes: 0,
        message: "정상 출석 처리되었습니다.",
        success: true,
      };
    }

    // 지각
    if (koreanTime.isBefore(lateTime)) {
      const lateMinutes = koreanTime.diff(normalTime, "minutes");
      return {
        status: "late",
        lateMinutes,
        message: `지각 처리되었습니다. (${lateMinutes}분 지각)`,
        success: true,
      };
    }

    // 결석
    return {
      status: "absent",
      lateMinutes: 0,
      message: "결석 처리되었습니다.",
      success: true,
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

    // 데이터 유효성 검사 강화
    if (!encryptedData || typeof encryptedData !== "string") {
      return res.status(400).json({
        success: false,
        message: "유효하지 않은 QR 코드 데이터입니다.",
      });
    }

    // QR 코드 형식 검사 추가
    const [ivHex, encryptedHex] = encryptedData.split(":");
    if (!ivHex || !encryptedHex) {
      return res.status(400).json({
        success: false,
        message: "잘못된 QR 코드 형식입니다.",
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

      // 복호화된 데이터 검증 추가
      if (!studentId || !timestamp) {
        throw new Error("QR 코드 데이터 형식이 올바르지 않습니다.");
      }

      // 학생 정보 조회
      const student = await User.findOne({ studentId });
      if (!student) {
        return res.status(400).json({
          success: false,
          message: "등록되지 않은 학생입니다.",
        });
      }

      // 출석 상태 결정
      const attendanceStatus = await determineAttendanceStatus(timestamp);
      if (!attendanceStatus.success) {
        return res.status(400).json({
          success: false,
          message: attendanceStatus.message,
        });
      }

      // 기존 출석 기록 확인
      const today = moment.tz(timestamp, "Asia/Seoul").startOf("day");
      const tomorrow = moment(today).add(1, "days");

      const existingAttendance = await Attendance.findOne({
        studentId,
        timestamp: {
          $gte: today.format(),
          $lt: tomorrow.format(),
        },
      });

      if (existingAttendance) {
        return res.status(400).json({
          success: false,
          message: "이미 오늘 출석이 기록되었습니다.",
          attendance: {
            ...existingAttendance.toObject(),
            name: student.name,
          },
        });
      }

      // 새로운 출석 기록 생성
      const attendance = new Attendance({
        studentId,
        timestamp,
        status: attendanceStatus.status,
        lateMinutes: attendanceStatus.lateMinutes,
      });

      await attendance.save();

      res.status(201).json({
        success: true,
        message: attendanceStatus.message,
        attendance: {
          ...attendance.toObject(),
          name: student.name,
        },
      });
    } catch (cryptoError) {
      console.error("복호화 오류:", cryptoError);
      return res.status(400).json({
        success: false,
        message: "QR 코드 복호화에 실패했습니다.",
      });
    }
  } catch (error) {
    console.error("출석 처리 중 오류:", error);
    return res.status(500).json({
      success: false,
      message: error.message || "출석 처리 중 오류가 발생했습니다.",
    });
  }
});

// 자동 결석 처리 함수 추가
async function processAutoAbsent() {
  try {
    const now = moment().tz("Asia/Seoul");
    const today = now.startOf("day");

    // 주말 체크
    if (now.day() === 0 || now.day() === 6) {
      console.log("주말 자동 결석 처리를 하지 않습니다.");
      return;
    }

    // 휴일 체크
    const holiday = await Holiday.findOne({
      date: today.toDate(),
    });

    if (holiday) {
      console.log(`휴일(${holiday.reason})은 자동 결석 처리를 하지 않습니다.`);
      return;
    }

    // 결석 처리 시간 인 (9시 이후)
    const [lateHour, lateMinute] = LATE_ATTENDANCE_TIME.split(":").map(Number);
    const cutoffTime = today
      .clone()
      .add(lateHour, "hours")
      .add(lateMinute, "minutes");

    if (now.isBefore(cutoffTime)) {
      console.log("아직 자동 결석 처리 시간이 되지 않았습니다.");
      return;
    }

    // 오늘 출석하지 않은 학생들 조회
    const allStudents = await User.find({
      isApproved: true,
      isAdmin: false,
    });

    const attendedStudents = await Attendance.find({
      timestamp: {
        $gte: today.format(),
        $lt: moment(today).add(1, "day").format(),
      },
    }).distinct("studentId");

    const absentStudents = allStudents.filter(
      (student) => !attendedStudents.includes(student.studentId)
    );

    // 결석 처리
    for (const student of absentStudents) {
      const attendance = new Attendance({
        studentId: student.studentId,
        timestamp: now.format(),
        status: "absent",
        lateMinutes: 0,
      });
      await attendance.save();
    }

    console.log(
      `${absentStudents.length}명의 학생이 자동으로 결석 처리되었습니다.`
    );
  } catch (error) {
    console.error("자동 결석 처리 중 오류:", error);
  }
}

// 매일 9시에 자동 결석 처리 실행
const schedule = require("node-schedule");
schedule.scheduleJob("0 9 * * *", processAutoAbsent);

// 출석 통계 API 개선
app.get("/api/attendance/stats", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, grade, classNum } = req.query;
    const today = moment().tz("Asia/Seoul").startOf("day");
    const thisMonth = moment().tz("Asia/Seoul").startOf("month");

    // 필터 조건 설정
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

    // 월간 랭킹 계산
    const monthlyRankings = {
      attendance: await calculateMonthlyRankings(students, "present", 3),
      punctuality: await calculateMonthlyRankings(students, "late", 3),
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
        const todayAttendance = await Attendance.findOne({
          studentId: student.studentId,
          timestamp: {
            $gte: today.format(),
            $lt: moment(today).add(1, "day").format(),
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
async function calculateMonthlyRankings(students, type, limit = 3) {
  // 이번 달의 시작과 끝
  const thisMonth = moment().tz("Asia/Seoul").startOf("month");
  const nextMonth = moment().tz("Asia/Seoul").endOf("month");

  const rankings = await Promise.all(
    students.map(async (student) => {
      const attendances = await Attendance.find({
        studentId: student.studentId,
        timestamp: {
          $gte: thisMonth.format(),
          $lte: nextMonth.format(),
        },
      });

      // 출석 횟수 계
      const presentCount = attendances.filter(
        (a) => a.status === "present"
      ).length;
      const lateCount = attendances.filter((a) => a.status === "late").length;
      const totalLateMinutes = attendances.reduce(
        (sum, a) => sum + (a.lateMinutes || 0),
        0
      );

      // 개선도 계산
      const lastMonth = moment().subtract(1, "month");
      const lastMonthAttendances = await Attendance.find({
        studentId: student.studentId,
        timestamp: {
          $gte: lastMonth.startOf("month").format(),
          $lte: lastMonth.endOf("month").format(),
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

// 4. 로그 시스템 추가
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.simple(),
    })
  );
}

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
    const attendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: moment.tz(date, "Asia/Seoul").startOf("day").format(),
        $lt: moment.tz(date, "Asia/Seoul").endOf("day").format(),
      },
    });

    if (!attendance) {
      // 출석 기록이 없는 경우 새로 생성
      const newAttendance = new Attendance({
        studentId,
        timestamp: moment.tz(date, "Asia/Seoul").format(),
        status: "absent",
        isExcused: true,
        reason,
        excusedAt: new Date(),
        excusedBy: req.user.id,
      });
      await newAttendance.save();

      return res.json({
        success: true,
        message: "인정결석이 새로 등록되었습니다.",
        attendance: newAttendance,
      });
    }

    // 기존 출석 기록을 인정결석으로 변경
    attendance.status = "absent";
    attendance.isExcused = true;
    attendance.reason = reason;
    attendance.lateMinutes = 0;
    attendance.excusedAt = new Date();
    attendance.excusedBy = req.user.id;

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

// 인정결석 목록 조회 API 수정
app.get("/api/attendance/excused", verifyToken, async (req, res) => {
  try {
    const excusedAttendances = await Attendance.find({
      isExcused: true,
    })
      .sort({ timestamp: -1 }) // 최신순으로 정렬
      .populate('excusedBy', 'name'); // 승인자 정보 포함

    // 학생 정보 조회를 위한 Promise.all 사용
    const excusedWithStudentInfo = await Promise.all(
      excusedAttendances.map(async (attendance) => {
        const student = await User.findOne({ studentId: attendance.studentId });
        return {
          _id: attendance._id, // ID 추가
          studentId: attendance.studentId,
          studentName: student ? student.name : "알 수 없음",
          date: attendance.timestamp,
          reason: attendance.reason,
          excusedAt: attendance.excusedAt,
          excusedBy: attendance.excusedBy?.name || "알 수 없음",
        };
      })
    );

    res.json({
      success: true,
      excused: excusedWithStudentInfo,
    });
  } catch (error) {
    console.error("인정결석 목록 조회 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "인정결석 목록 조회 중 오류가 발생했습니다.",
    });
  }
});

// 인정결석 취소 API 추가
app.delete("/api/attendance/excuse/:id", verifyToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    
    const attendance = await Attendance.findById(id);
    if (!attendance) {
      return res.status(404).json({
        success: false,
        message: "해당 인정결석 기록을 찾을 수 없습니다."
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
      message: "인정결석이 취소되었습니다."
    });
  } catch (error) {
    console.error("인정결석 삭제 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "인정결석 삭제 중 오류가 발생했습니다."
    });
  }
});

// 단체 인정결석 처리 API 추가
app.post("/api/attendance/excuse-group", verifyToken, isAdmin, async (req, res) => {
  try {
    const { date, reason, filters } = req.body;
    
    if (!date || !reason || !filters) {
      return res.status(400).json({
        success: false,
        message: "날짜, 사유, 필터 조건이 모두 필요합니다."
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
        message: "조건에 맞는 학생이 없습니다."
      });
    }

    const startOfDay = moment.tz(date, "Asia/Seoul").startOf("day");
    const endOfDay = moment.tz(date, "Asia/Seoul").endOf("day");

    // 각 학생에 대해 인정결석 처리
    const results = await Promise.all(students.map(async (student) => {
      // 기존 출석 기록 확인
      let attendance = await Attendance.findOne({
        studentId: student.studentId,
        timestamp: {
          $gte: startOfDay.format(),
          $lt: endOfDay.format()
        }
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
          excusedBy: req.user.id
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
        success: true
      };
    }));

    res.json({
      success: true,
      message: `${results.length}명의 학생이 인정결석 처리되었습니다.`,
      results
    });

  } catch (error) {
    console.error("단체 인정결석 처리 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "단체 인정결석 처리 중 오류가 발생했습니다.",
      error: error.message
    });
  }
});

// 환경 변수 검증 함수
function validateEnvVariables() {
  const requiredEnvVars = [
    "MONGODB_URI",
    "JWT_SECRET",
    "REFRESH_TOKEN_SECRET",
    "ENCRYPTION_KEY",
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
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? ["https://attendhs.netlify.app"]
        : ["http://localhost:5500"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true,
  })
);
