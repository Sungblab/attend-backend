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

  // 잠금 시간이 지났는지 확인
  if (currentAttempts.count >= process.env.MAX_LOGIN_ATTEMPTS) {
    const lockoutTime = parseInt(process.env.LOGIN_LOCKOUT_TIME);
    if (Date.now() - currentAttempts.timestamp < lockoutTime) {
      return res.status(429).json({
        success: false,
        message: "너무 많은 로그인 시도. 잠시 후 다시 시도해주세요.",
        remainingTime: Math.ceil(
          (lockoutTime - (Date.now() - currentAttempts.timestamp)) / 1000
        ),
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

    const user = await User.findOne({ studentId });
    if (!user) {
      incrementLoginAttempts(ip);
      return res.status(400).json({
        success: false,
        message: "존재하지 않는 학번입니다.",
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      incrementLoginAttempts(ip);
      return res.status(400).json({
        success: false,
        message: "비밀번호가 일치하지 않습니다.",
      });
    }

    // 로그인 성공 시 시도 횟수 초기화
    loginAttempts.delete(ip);

    // 액세스 토큰 생성
    const accessToken = generateAccessToken(user);

    // 리프레시 토큰 생성
    const refreshToken = generateRefreshToken();
    const refreshTokenDoc = new RefreshToken({
      userId: user._id,
      token: refreshToken,
      expiresAt: new Date(Date.now() + getRefreshTokenExpiresIn(keepLoggedIn)),
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
      redirectUrl: user.isAdmin || user.isReader ? "/hub.html" : "/qr.html",
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다.",
    });
  }
});

// 로그인 시도 횟수 증가 함수
function incrementLoginAttempts(ip) {
  const currentAttempts = loginAttempts.get(ip) || {
    count: 0,
    timestamp: Date.now(),
  };
  currentAttempts.count += 1;
  currentAttempts.timestamp = Date.now();
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
    res.status(500).json({ message: "서버 오류가 발��했습니다." });
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

    if (!encryptedData) {
      return res.status(400).json({
        success: false,
        message: "QR 코드 데이터가 없습니다.",
      });
    }

    // QR 코드 복호화 및 데이터 추출
    const [ivHex, encryptedHex] = encryptedData.split(":");
    if (!ivHex || !encryptedHex) {
      return res.status(400).json({
        success: false,
        message: "잘못된 QR 코드 형식입니다.",
      });
    }

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

    if (!studentId || !timestamp) {
      return res.status(400).json({
        success: false,
        message: "QR 코드에서 학생 정보를 추출�� 수 없습니다.",
      });
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
  } catch (error) {
    console.error("출석 처리 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "출석 처리 중 오류가 발생했습니다.",
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
      console.log("주말은 자동 결석 처리를 하지 않습니다.");
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

    // 결석 처리 시간 확인 (9시 이후)
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
    lateReduction * 0.2 + // 지각 횟수 감소 20%
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
      lateMinutes: attendances.reduce(
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
        $gte: today.format(),
        $lt: moment(today).add(1, "day").format(),
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
      attendances: attendances.map((a) => ({
        date: moment(a.timestamp).format("YYYY-MM-DD"),
        status: a.status,
        isExcused: a.isExcused,
        lateMinutes: a.lateMinutes,
        reason: a.reason,
      })),
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

// 인정결석 목록 조회 API 추가
app.get("/api/attendance/excused", verifyToken, async (req, res) => {
  try {
    const excusedAttendances = await Attendance.find({
      isExcused: true,
    })
      .sort({ timestamp: -1 })
      .limit(20); // 최근 20개만 조회

    // 학생 정보 조회를 위한 Promise.all 사용
    const excusedWithStudentInfo = await Promise.all(
      excusedAttendances.map(async (attendance) => {
        const student = await User.findOne({ studentId: attendance.studentId });
        return {
          studentId: attendance.studentId,
          studentName: student ? student.name : "알 수 없음",
          date: attendance.timestamp,
          reason: attendance.reason,
          excusedAt: attendance.excusedAt,
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

// Holiday 모델 수정
const HolidaySchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  reason: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
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

    const formattedDate = moment(date).startOf("day").toDate();

    // 이미 존재하는 휴일인지 확인
    const existingHoliday = await Holiday.findOne({
      date: formattedDate,
    });

    if (existingHoliday) {
      return res.status(400).json({
        success: false,
        message: "이미 등록된 휴일입니다.",
      });
    }

    const holiday = new Holiday({
      date: formattedDate,
      reason,
      createdBy: req.user.id,
    });

    await holiday.save();

    res.json({
      success: true,
      message: "휴일이 등록되었습니다.",
      holiday: {
        id: holiday._id,
        date: moment(holiday.date).format("YYYY-MM-DD"),
        reason: holiday.reason,
        createdBy: req.user.name || "관리자",
      },
    });
  } catch (error) {
    console.error("휴일 등록 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "휴일 등록 중 오류가 발생했습니다.",
    });
  }
});

// 휴일 목록 조회 API 수정
app.get("/api/holidays", verifyToken, async (req, res) => {
  try {
    const holidays = await Holiday.find()
      .sort({ date: 1 })
      .populate("createdBy", "name");

    console.log("Found holidays:", holidays); // 디버깅용 로그

    res.json({
      success: true,
      holidays: holidays.map((h) => ({
        id: h._id,
        date: moment(h.date).format("YYYY-MM-DD"),
        reason: h.reason,
        createdAt: moment(h.createdAt).format("YYYY-MM-DD HH:mm:ss"),
        createdBy: h.createdBy?.name || "관리자",
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

// 휴일 삭제 API
app.delete("/api/holidays/:id", verifyToken, isAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await Holiday.findByIdAndDelete(id);

    res.json({
      success: true,
      message: "휴일이 삭제되었습니다.",
    });
  } catch (error) {
    console.error("휴일 삭제 중 오류:", error);
    res.status(500).json({
      success: false,
      message: "휴일 삭제 중 오류가 발생했습니다.",
    });
  }
});

// 자동 결석 처리 함수 수정
async function handleAutoAbsent() {
  try {
    const now = moment().tz("Asia/Seoul");
    const today = now.startOf("day");

    // 주말인지 확인
    const isWeekend = now.day() === 0 || now.day() === 6;

    // 휴일인지 확인
    const isHoliday = await Holiday.findOne({
      date: today.toDate(),
    });

    // 주말이나 휴일이면 처리하지 않음
    if (isWeekend || isHoliday) {
      console.log("오늘은 휴일이므로 자동 결석 처리를 건너뜁니다.");
      return;
    }

    // 현재 시간이 9시 이후인지 확인
    const cutoffTime = now.clone().hour(9).minute(0).second(0);
    if (now.isBefore(cutoffTime)) {
      console.log("아직 자동 결석 처리 시간이 되지 않았습니다.");
      return;
    }

    // 자동 결석 처리 API 호출
    const response = await axios.post(
      "/api/attendance/auto-absent",
      {},
      {
        headers: {
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
      }
    );

    if (response.data.success) {
      showToast(
        `${response.data.count}명의 학생이 결석 처리되었습니다.`,
        "success"
      );
      await fetchAttendanceStats(); // 통계 새로고침
    }
  } catch (error) {
    console.error("자동 결석 처리 중 오류:", error);
    showToast(
      error.response?.data?.message || "자동 결�� 처리 중 오류가 발생했습니다.",
      "error"
    );
  }
}

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
