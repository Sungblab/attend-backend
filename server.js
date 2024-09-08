const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const moment = require("moment-timezone");
const moment1 = require("moment");
require("dotenv").config();

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

// Generate QR code data route
app.post("/api/generate-qr", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.body;
    const timestamp = new Date().toISOString(); // 현재 시간 사용

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

// 한국 시간으로 변환하는 함수
function toKoreanTime(date) {
  return moment(date).tz("Asia/Seoul");
}

// Attendance model
const AttendanceSchema = new mongoose.Schema({
  studentId: { type: String, required: true },
  timestamp: {
    type: Date,
    required: true,
    get: (v) => moment(v).tz("Asia/Seoul").format("YYYY-MM-DD HH:mm:ss"),
    set: (v) => moment.tz(v, "Asia/Seoul").utc().toDate(),
  },
  status: { type: String, enum: ["present", "late", "absent"], required: true },
  lateMinutes: { type: Number, default: 0 },
});

AttendanceSchema.set("toJSON", { getters: true });
const Attendance = mongoose.model("Attendance", AttendanceSchema);

// 출석 상태 결정 함수 수정
function determineAttendanceStatus(timestamp) {
  const koreanTime = toKoreanTime(timestamp);
  const currentDate = koreanTime.startOf("day");

  const normalAttendanceTime = process.env.NORMAL_ATTENDANCE_TIME || "08:03";
  const lateAttendanceTime = process.env.LATE_ATTENDANCE_TIME || "09:00";

  const [normalHour, normalMinute] = normalAttendanceTime
    .split(":")
    .map(Number);
  const [lateHour, lateMinute] = lateAttendanceTime.split(":").map(Number);

  const normalTime = moment(currentDate)
    .add(normalHour, "hours")
    .add(normalMinute, "minutes");
  const lateTime = moment(currentDate)
    .add(lateHour, "hours")
    .add(lateMinute, "minutes");

  if (koreanTime.isBefore(normalTime)) {
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
    const [studentId, timestampStr] = decrypted.toString().split("|");
    const timestamp = toKoreanTime(timestampStr).toDate();

    // Check for existing attendance on the same day
    const today = moment(timestamp).tz("Asia/Seoul").startOf("day");
    const tomorrow = moment(today).add(1, "days");

    const existingAttendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: today.toDate(),
        $lt: tomorrow.toDate(),
      },
    });

    if (existingAttendance) {
      return res
        .status(400)
        .json({ message: "이미 오늘 출석이 기록되었습니다." });
    }

    // 출석 상태 결정
    const { status, lateMinutes } = determineAttendanceStatus(timestamp);

    // 출석 기록 생성 및 저장
    const attendance = new Attendance({
      studentId,
      timestamp: timestamp,
      status,
      lateMinutes,
    });

    await attendance.save();

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

app.get("/api/attendance/stats", verifyToken, async (req, res) => {
  try {
    const { startDate, endDate, grade, classNum } = req.query;

    // 쿼리 조건 설정
    let matchCondition = {};
    if (startDate && endDate) {
      matchCondition.timestamp = {
        $gte: new Date(startDate),
        $lte: new Date(endDate),
      };
    }

    // 학생 필터링 조건
    let userMatchCondition = {};
    if (grade) userMatchCondition.grade = parseInt(grade);
    if (classNum) userMatchCondition.class = parseInt(classNum);

    // 학생 목록 가져오기
    const students = await User.find(userMatchCondition).select(
      "studentId name grade class number"
    );

    const today = moment().tz("Asia/Seoul").startOf("day");

    // 각 학생별 통계 계산
    const studentStats = await Promise.all(
      students.map(async (student) => {
        const attendances = await Attendance.find({
          ...matchCondition,
          studentId: student.studentId,
        });

        const presentCount = attendances.filter(
          (a) => a.status === "present"
        ).length;
        const lateCount = attendances.filter((a) => a.status === "late").length;
        const absentCount = attendances.filter(
          (a) => a.status === "absent"
        ).length;
        const totalLateMinutes = attendances.reduce(
          (sum, a) => sum + a.lateMinutes,
          0
        );
        const lastAttendance =
          attendances.length > 0
            ? moment(attendances[attendances.length - 1].timestamp).format(
                "YYYY-MM-DD HH:mm:ss"
              )
            : "N/A";

        // 오늘의 출석 상태 확인
        const todayAttendance = await Attendance.findOne({
          studentId: student.studentId,
          timestamp: {
            $gte: today.toDate(),
            $lt: moment(today).add(1, "days").toDate(),
          },
        });

        const todayStatus = todayAttendance ? todayAttendance.status : "미출석";

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
          lastAttendance,
          todayStatus, // 오늘의 출석 상태 추가
        };
      })
    );

    // 전체 통계 계산
    const overallStats = {
      totalStudents: studentStats.length,
      totalPresent: studentStats.reduce((sum, s) => sum + s.presentCount, 0),
      totalLate: studentStats.reduce((sum, s) => sum + s.lateCount, 0),
      totalAbsent: studentStats.reduce((sum, s) => sum + s.absentCount, 0),
      averageLateMinutes:
        studentStats.reduce((sum, s) => sum + s.totalLateMinutes, 0) /
        studentStats.length,
    };

    res.json({ studentStats, overallStats });
  } catch (error) {
    console.error("통계 조회 중 오류 발생:", error);
    res
      .status(500)
      .json({ message: "서버 오류가 발생했습니다.", error: error.message });
  }
});
