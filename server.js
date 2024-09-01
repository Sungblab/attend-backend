const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const crypto = require("crypto");
const cron = require("node-cron");
const ExcelJS = require("exceljs");
const moment = require("moment-timezone");

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
  timestamp: { type: Date, required: true },
  status: { type: String, enum: ["present", "late", "absent"], required: true },
  lateMinutes: { type: Number, default: 0 },
});

const Attendance = mongoose.model("Attendance", AttendanceSchema);

const DailyAttendanceSummarySchema = new mongoose.Schema({
  date: { type: Date, required: true, unique: true },
  totalStudents: { type: Number, required: true },
  presentCount: { type: Number, default: 0 },
  lateCount: { type: Number, default: 0 },
  absentCount: { type: Number, default: 0 },
  totalLateMinutes: { type: Number, default: 0 },
});

const DailyAttendanceSummary = mongoose.model(
  "DailyAttendanceSummary",
  DailyAttendanceSummarySchema
);

const ATTENDANCE_HOUR = 24;
const ATTENDANCE_MINUTE = 3;
const LATE_HOUR = 24;
const LATE_MINUTE = 25;

// Helper functions 추가
function getKoreanTime(date = new Date()) {
  return moment(date).tz("Asia/Seoul");
}

function determineAttendanceStatus(timestamp) {
  const koreanTime = getKoreanTime(timestamp);
  const attendanceTime = koreanTime.clone().set({
    hour: ATTENDANCE_HOUR,
    minute: ATTENDANCE_MINUTE,
    second: 0,
    millisecond: 0,
  });
  const lateTime = koreanTime
    .clone()
    .set({ hour: LATE_HOUR, minute: LATE_MINUTE, second: 0, millisecond: 0 });

  if (koreanTime.isBefore(attendanceTime)) {
    return { status: "present", lateMinutes: 0 };
  } else if (koreanTime.isBefore(lateTime)) {
    return {
      status: "late",
      lateMinutes: koreanTime.diff(attendanceTime, "minutes"),
    };
  } else {
    return { status: "absent", lateMinutes: 0 };
  }
}

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

// ATTENDANCE_HOUR와 ATTENDANCE_MINUTE 변수 확인
console.log(
  `출석 기준 시간: ${ATTENDANCE_HOUR}시 ${ATTENDANCE_MINUTE}분 (KST)`
);

// 대시보드 API 엔드포인트 수정
app.get("/api/dashboard", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, grade, class: classNumber } = req.query;

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "시작 날짜와 종료 날짜는 필수 입력 항목입니다." });
    }

    const start = getKoreanTime(startDate).startOf("day").toDate();
    const end = getKoreanTime(endDate).endOf("day").toDate();

    // 사용자 쿼리 구성
    const userQuery = { isApproved: true };
    if (grade) userQuery.grade = Number(grade);
    if (classNumber) userQuery.class = Number(classNumber);

    // 학생 조회
    const students = await User.find(userQuery).lean();

    // 출석 기록 조회
    const attendanceRecords = await Attendance.find({
      studentId: { $in: students.map((s) => s.studentId) },
      timestamp: { $gte: start, $lte: end },
    }).lean();

    // 일일 출석 요약 조회
    const dailySummaries = await DailyAttendanceSummary.find({
      date: { $gte: start, $lte: end },
    }).lean();

    // 학생별 출석 통계 계산
    const studentStats = students.map((student) => {
      const studentRecords = attendanceRecords.filter(
        (r) => r.studentId === student.studentId
      );
      const presentCount = studentRecords.filter(
        (r) => r.status === "present"
      ).length;
      const lateCount = studentRecords.filter(
        (r) => r.status === "late"
      ).length;
      const totalLateMinutes = studentRecords.reduce(
        (sum, r) => sum + (r.lateMinutes || 0),
        0
      );

      return {
        studentId: student.studentId,
        name: student.name,
        grade: student.grade,
        class: student.class,
        number: student.number,
        presentCount,
        lateCount,
        absentCount: dailySummaries.length - presentCount - lateCount,
        totalLateMinutes,
        attendanceRate: (
          ((presentCount + lateCount) / dailySummaries.length) *
          100
        ).toFixed(2),
        lateRate: ((lateCount / (presentCount + lateCount)) * 100).toFixed(2),
      };
    });

    // 전체 통계 계산
    const overallStats = {
      totalStudents: students.length,
      totalDays: dailySummaries.length,
      totalPresent: dailySummaries.reduce(
        (sum, day) => sum + day.presentCount,
        0
      ),
      totalLate: dailySummaries.reduce((sum, day) => sum + day.lateCount, 0),
      totalAbsent: dailySummaries.reduce(
        (sum, day) => sum + day.absentCount,
        0
      ),
      totalLateMinutes: dailySummaries.reduce(
        (sum, day) => sum + day.totalLateMinutes,
        0
      ),
      averageAttendanceRate: (
        studentStats.reduce((sum, s) => sum + parseFloat(s.attendanceRate), 0) /
        students.length
      ).toFixed(2),
      averageLateRate: (
        studentStats.reduce((sum, s) => sum + parseFloat(s.lateRate), 0) /
        students.length
      ).toFixed(2),
    };

    res.json({
      period: { startDate: start, endDate: end },
      overallStats,
      studentStats,
    });
  } catch (error) {
    console.error("대시보드 데이터 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

app.post("/api/attendance", verifyToken, async (req, res) => {
  try {
    const { studentId } = req.body;
    const timestamp = new Date();
    const { status, lateMinutes } = determineAttendanceStatus(timestamp);

    const attendance = new Attendance({
      studentId,
      timestamp,
      status,
      lateMinutes,
    });

    await attendance.save();

    res.status(201).json({
      message: `출석이 기록되었습니다. 상태: ${status}, 지각 시간: ${lateMinutes}분`,
      attendance,
    });
  } catch (error) {
    console.error("출석 기록 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
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
  records: [
    {
      studentId: { type: String, required: true },
      isLate: { type: Boolean, default: false },
      lateMinutes: { type: Number, default: 0 },
    },
  ],
});

const AttendanceHistory = mongoose.model(
  "AttendanceHistory",
  AttendanceHistorySchema
);

// 일일 출석 초기화를 위한 cron job
cron.schedule("0 0 * * *", async () => {
  try {
    const yesterday = getKoreanTime()
      .subtract(1, "day")
      .startOf("day")
      .toDate();
    const today = getKoreanTime().startOf("day").toDate();

    const totalStudents = await User.countDocuments({ isApproved: true });
    const yesterdayAttendance = await Attendance.find({
      timestamp: { $gte: yesterday, $lt: today },
    });

    const presentCount = yesterdayAttendance.filter(
      (a) => a.status === "present"
    ).length;
    const lateCount = yesterdayAttendance.filter(
      (a) => a.status === "late"
    ).length;
    const absentCount = totalStudents - presentCount - lateCount;
    const totalLateMinutes = yesterdayAttendance.reduce(
      (sum, a) => sum + (a.lateMinutes || 0),
      0
    );

    await DailyAttendanceSummary.create({
      date: yesterday,
      totalStudents,
      presentCount,
      lateCount,
      absentCount,
      totalLateMinutes,
    });

    console.log("일일 출석 요약이 생성되었습니다:", yesterday);
  } catch (error) {
    console.error("일일 출석 요약 생성 중 오류 발생:", error);
  }
});

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

// 엑셀 다운로드 라우트 수정
app.get("/api/download-excel", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate, grade, class: classNumber } = req.query;

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "시작 날짜와 종료 날짜는 필수 입력 항목입니다." });
    }

    const start = getKoreanTime(startDate).startOf("day").toDate();
    const end = getKoreanTime(endDate).endOf("day").toDate();

    const userQuery = { isApproved: true };
    if (grade) userQuery.grade = Number(grade);
    if (classNumber) userQuery.class = Number(classNumber);

    const students = await User.find(userQuery).lean();
    const attendanceRecords = await Attendance.find({
      studentId: { $in: students.map((s) => s.studentId) },
      timestamp: { $gte: start, $lte: end },
    }).lean();

    const dailySummaries = await DailyAttendanceSummary.find({
      date: { $gte: start, $lte: end },
    }).lean();

    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("출석 데이터");

    worksheet.columns = [
      { header: "학번", key: "studentId", width: 15 },
      { header: "이름", key: "name", width: 15 },
      { header: "학년", key: "grade", width: 10 },
      { header: "반", key: "class", width: 10 },
      { header: "번호", key: "number", width: 10 },
      { header: "출석 횟수", key: "presentCount", width: 15 },
      { header: "지각 횟수", key: "lateCount", width: 15 },
      { header: "결석 횟수", key: "absentCount", width: 15 },
      { header: "총 지각 시간(분)", key: "totalLateMinutes", width: 20 },
      { header: "출석률(%)", key: "attendanceRate", width: 15 },
      { header: "지각률(%)", key: "lateRate", width: 15 },
    ];

    students.forEach((student) => {
      const studentRecords = attendanceRecords.filter(
        (r) => r.studentId === student.studentId
      );
      const presentCount = studentRecords.filter(
        (r) => r.status === "present"
      ).length;
      const lateCount = studentRecords.filter(
        (r) => r.status === "late"
      ).length;
      const absentCount = dailySummaries.length - presentCount - lateCount;
      const totalLateMinutes = studentRecords.reduce(
        (sum, r) => sum + (r.lateMinutes || 0),
        0
      );

      worksheet.addRow({
        studentId: student.studentId,
        name: student.name,
        grade: student.grade,
        class: student.class,
        number: student.number,
        presentCount,
        lateCount,
        absentCount,
        totalLateMinutes,
        attendanceRate: (
          ((presentCount + lateCount) / dailySummaries.length) *
          100
        ).toFixed(2),
        lateRate: ((lateCount / (presentCount + lateCount)) * 100).toFixed(2),
      });
    });

    const fileName = `attendance_data_${moment(start).format(
      "YYYYMMDD"
    )}_${moment(end).format("YYYYMMDD")}.xlsx`;

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader("Content-Disposition", `attachment; filename=${fileName}`);

    await workbook.xlsx.write(res);
    res.end();

    console.log("Excel file generated and sent successfully");
  } catch (error) {
    console.error("엑셀 파일 생성 중 오류 발생:", error);
    res
      .status(500)
      .json({ message: "서버 오류가 발생했습니다.", error: error.message });
  }
});
