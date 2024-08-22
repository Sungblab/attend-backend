const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const dotenv = require("dotenv");
const cors = require("cors");
const crypto = require("crypto");
const cron = require("node-cron");
const ExcelJS = require("exceljs");
const moment = require("moment-timezone");
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
  lateReason: { type: String, default: null },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  approvalReason: String,
  approvalTimestamp: Date,
});

const Attendance = mongoose.model("Attendance", AttendanceSchema);

const ATTENDANCE_HOUR = 8;
const ATTENDANCE_MINUTE = 3;

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
    const kstNow = new Date(now.getTime() + 9 * 60 * 60 * 1000); // KST로 변환
    console.log(`현재 시간 (KST): ${kstNow.toISOString()}`);

    const today = new Date(
      kstNow.getFullYear(),
      kstNow.getMonth(),
      kstNow.getDate()
    );
    console.log(`오늘 날짜 (KST): ${today.toISOString()}`);

    // 같은 날 중복 출석 확인
    const existingAttendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: new Date(today.getTime() - 9 * 60 * 60 * 1000),
        $lt: new Date(today.getTime() + 15 * 60 * 60 * 1000),
      },
    });
    if (existingAttendance) {
      console.log(
        `중복 출석 시도 (KST): ${studentId}, ${kstNow.toISOString()}`
      );
      return res.status(400).json({ message: "이미 오늘 출석했습니다." });
    }

    const attendanceTime = new Date(today);
    attendanceTime.setHours(ATTENDANCE_HOUR, ATTENDANCE_MINUTE, 0, 0);
    console.log(`출석 기준 시간 (KST): ${attendanceTime.toISOString()}`);

    const absenceTime = new Date(today);
    absenceTime.setHours(9, 0, 0, 0);
    console.log(`결석 기준 시간 (KST): ${absenceTime.toISOString()}`);

    if (kstNow >= absenceTime) {
      console.log(`결석 처리 (KST): ${studentId}, ${kstNow.toISOString()}`);
      return res.status(400).json({ message: "결석 처리되었습니다." });
    }

    const isLate = kstNow > attendanceTime;
    const lateMinutes = isLate
      ? Math.floor((kstNow - attendanceTime) / 60000)
      : 0;

    const attendance = new Attendance({
      studentId,
      timestamp: now,
      isLate,
      lateMinutes,
    });

    await attendance.save();

    console.log(
      `출석 기록 (KST): 학생 ID ${studentId}, 시간 ${kstNow.toISOString()}, 지각 여부 ${isLate}, 지각 시간 ${lateMinutes}분`
    );

    const responseMessage = isLate
      ? `"${studentId}" "${student.name}" 출석 성공. ${lateMinutes}분 지각입니다.`
      : `"${studentId}" "${student.name}" 출석 성공.`;

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
console.log(
  `출석 기준 시간: ${ATTENDANCE_HOUR}시 ${ATTENDANCE_MINUTE}분 (KST)`
);

// 대시보드 API 엔드포인트 수정
app.get("/api/dashboard", verifyToken, isAdmin, async (req, res) => {
  try {
    const {
      startDate,
      endDate,
      grade,
      class: classNumber,
      period,
      attendanceStatus,
      lateCount,
      search,
      page = 1,
      limit = 20,
    } = req.query;

    console.log("Dashboard API called with params:", req.query);

    if (!startDate || !endDate) {
      return res
        .status(400)
        .json({ message: "시작 날짜와 종료 날짜는 필수 입력 항목입니다." });
    }

    const pageNum = Number(page);
    const limitNum = Number(limit);
    if (isNaN(pageNum) || isNaN(limitNum) || pageNum < 1 || limitNum < 1) {
      return res
        .status(400)
        .json({ message: "잘못된 페이지 또는 제한 값입니다." });
    }

    // KST 기준으로 날짜 변환
    const start = moment.tz(startDate, "Asia/Seoul").startOf("day").toDate();
    const end = moment.tz(endDate, "Asia/Seoul").endOf("day").toDate();

    console.log("Parsed date range (KST):", { start, end });

    if (!start || !end || isNaN(start.getTime()) || isNaN(end.getTime())) {
      return res.status(400).json({ message: "잘못된 날짜 형식입니다." });
    }

    // 사용자 쿼리 구성
    const userQuery = {};
    if (grade) {
      const gradeNum = Number(grade);
      if (isNaN(gradeNum)) {
        return res.status(400).json({ message: "잘못된 학년 값입니다." });
      }
      userQuery.grade = gradeNum;
    }
    if (classNumber) {
      const classNum = Number(classNumber);
      if (isNaN(classNum)) {
        return res.status(400).json({ message: "잘못된 반 값입니다." });
      }
      userQuery.class = classNum;
    }
    if (search) {
      userQuery.$or = [
        { name: { $regex: search, $options: "i" } },
        { studentId: { $regex: search, $options: "i" } },
      ];
    }

    console.log("User query:", userQuery);

    // 사용자 조회
    const allStudents = await User.find(userQuery).lean();
    console.log("Total students found:", allStudents.length);

    const paginatedStudents = allStudents.slice(
      (pageNum - 1) * limitNum,
      pageNum * limitNum
    );

    // 누적 출석 데이터 조회
    const userSummaries = await UserAttendanceSummary.find({
      studentId: { $in: allStudents.map((user) => user.studentId) },
    }).lean();

    console.log("User summaries found:", userSummaries.length);

    // 현재 기간의 출석 기록 조회 (KST 기준)
    const currentAttendance = await Attendance.find({
      studentId: { $in: allStudents.map((user) => user.studentId) },
      timestamp: {
        $gte: moment(start).tz("Asia/Seoul").startOf("day").toDate(),
        $lte: moment(end).tz("Asia/Seoul").endOf("day").toDate(),
      },
    }).lean();

    console.log("Current attendance records found:", currentAttendance.length);

    // AttendanceHistory에서 해당 기간의 기록 조회 (KST 기준)
    const attendanceHistory = await AttendanceHistory.find({
      date: {
        $gte: moment(start).tz("Asia/Seoul").startOf("day").toDate(),
        $lte: moment(end).tz("Asia/Seoul").endOf("day").toDate(),
      },
    }).lean();

    console.log("Attendance history records found:", attendanceHistory.length);

    // 모든 출석 기록 병합
    const allAttendanceRecords = [
      ...currentAttendance,
      ...attendanceHistory.flatMap((history) =>
        history.records.map((record) => ({
          ...record,
          timestamp: history.date,
        }))
      ),
    ];

    console.log("Total attendance records:", allAttendanceRecords.length);

    // 학생별 상세 정보 계산
    const studentDetails = calculateStudentDetails(
      allAttendanceRecords,
      paginatedStudents,
      start,
      end,
      userSummaries
    );

    // 전체 통계 계산
    const overallStats = calculateAdvancedStats(
      allAttendanceRecords,
      allStudents,
      start,
      end,
      userSummaries
    );

    // 필터링 적용
    let filteredStudentDetails = studentDetails;
    if (attendanceStatus) {
      filteredStudentDetails = filteredStudentDetails.filter((student) => {
        if (attendanceStatus === "present")
          return (
            student.periodAttendance > 0 && student.periodLateAttendance === 0
          );
        if (attendanceStatus === "late")
          return student.periodLateAttendance > 0;
        if (attendanceStatus === "absent")
          return student.periodAttendance === 0;
        return true;
      });
    }
    if (lateCount) {
      const lateCountNum = Number(lateCount);
      if (isNaN(lateCountNum)) {
        return res.status(400).json({ message: "잘못된 지각 횟수 값입니다." });
      }
      filteredStudentDetails = filteredStudentDetails.filter(
        (student) => student.periodLateAttendance >= lateCountNum
      );
    }

    // 최우수 출석 학생 찾기
    const bestAttendanceStudent = findBestAttendanceStudent(studentDetails);

    res.json({
      attendanceData: filteredStudentDetails,
      overallStats,
      bestAttendanceStudent,
      period: { startDate: start, endDate: end },
      pagination: {
        currentPage: pageNum,
        totalPages: Math.ceil(allStudents.length / limitNum),
        totalItems: allStudents.length,
      },
    });
  } catch (error) {
    console.error("대시보드 데이터 조회 중 오류 발생:", error);
    res.status(500).json({
      message: "서버 오류가 발생했습니다.",
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
  }
});

function calculateStudentDetails(
  attendanceRecords,
  students,
  startDate,
  endDate,
  userSummaries
) {
  const studentMap = new Map(
    students.map((student) => {
      const summary =
        userSummaries.find((s) => s.studentId === student.studentId) || {};
      return [
        student.studentId,
        {
          studentId: student.studentId,
          name: student.name,
          grade: student.grade,
          class: student.class,
          number: student.number,
          totalAttendance: summary.totalAttendance || 0,
          totalLateAttendance: summary.totalLateAttendance || 0,
          totalLateMinutes: summary.totalLateMinutes || 0,
          periodAttendance: 0,
          periodLateAttendance: 0,
          periodLateMinutes: 0,
          lastAttendanceTime: null,
          lastAttendanceStatus: "미출석",
        },
      ];
    })
  );

  attendanceRecords.forEach((record) => {
    const studentDetail = studentMap.get(record.studentId);
    if (studentDetail) {
      // KST로 변환하여 비교
      const recordDate = moment(record.timestamp).tz("Asia/Seoul");
      if (
        recordDate.isSameOrAfter(startDate) &&
        recordDate.isSameOrBefore(endDate)
      ) {
        studentDetail.periodAttendance++;
        if (record.isLate) {
          studentDetail.periodLateAttendance++;
          studentDetail.periodLateMinutes += record.lateMinutes || 0;
        }

        if (
          !studentDetail.lastAttendanceTime ||
          recordDate.isAfter(moment(studentDetail.lastAttendanceTime))
        ) {
          studentDetail.lastAttendanceTime = record.timestamp;
          studentDetail.lastAttendanceStatus = record.isLate ? "지각" : "정상";
        }
      }
    }
  });

  const workingDays = getWorkingDays(startDate, endDate);

  return Array.from(studentMap.values())
    .map((student) => ({
      ...student,
      attendanceRate: ((student.periodAttendance / workingDays) * 100).toFixed(
        2
      ),
      lateRate:
        student.periodAttendance > 0
          ? (
              (student.periodLateAttendance / student.periodAttendance) *
              100
            ).toFixed(2)
          : "0.00",
    }))
    .sort((a, b) => {
      if (a.grade !== b.grade) return a.grade - b.grade;
      if (a.class !== b.class) return a.class - b.class;
      return a.number - b.number;
    });
}

function calculateAdvancedStats(
  attendanceRecords,
  allStudents,
  startDate,
  endDate,
  userSummaries
) {
  const totalStudents = allStudents.length;
  const periodAttendance = attendanceRecords.length;
  const periodLateAttendance = attendanceRecords.filter(
    (record) => record.isLate
  ).length;
  const periodLateMinutes = attendanceRecords.reduce(
    (sum, record) => sum + (record.lateMinutes || 0),
    0
  );

  const totalAttendance = userSummaries.reduce(
    (sum, summary) => sum + summary.totalAttendance,
    0
  );
  const totalLateAttendance = userSummaries.reduce(
    (sum, summary) => sum + summary.totalLateAttendance,
    0
  );
  const totalLateMinutes = userSummaries.reduce(
    (sum, summary) => sum + summary.totalLateMinutes,
    0
  );

  const workingDays = getWorkingDays(startDate, endDate);

  return {
    totalStudents,
    periodAttendance,
    periodLateAttendance,
    periodLateMinutes,
    totalAttendance,
    totalLateAttendance,
    totalLateMinutes,
    averageAttendanceRate: (
      (periodAttendance / (totalStudents * workingDays)) *
      100
    ).toFixed(2),
    averageLateRate:
      periodAttendance > 0
        ? ((periodLateAttendance / periodAttendance) * 100).toFixed(2)
        : "0.00",
    averageLateMinutes:
      periodLateAttendance > 0
        ? (periodLateMinutes / periodLateAttendance).toFixed(2)
        : "0.00",
  };
}

function findBestAttendanceStudent(students) {
  return students.reduce((best, current) => {
    if (!best || current.periodAttendance > best.periodAttendance) {
      return current;
    } else if (
      current.periodAttendance === best.periodAttendance &&
      current.periodLateAttendance < best.periodLateAttendance
    ) {
      return current;
    }
    return best;
  }, null);
}

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

// 통합된 출석 API
app.get("/api/attendance", verifyToken, isAdmin, async (req, res) => {
  try {
    const { date } = req.query;

    if (date) {
      // 특정 날짜의 출석 데이터 조회
      const targetDate = new Date(date);
      const nextDate = new Date(targetDate);
      nextDate.setDate(nextDate.getDate() + 1);

      const attendanceRecords = await Attendance.find({
        timestamp: { $gte: targetDate, $lt: nextDate },
      }).populate("studentId", "name studentId grade class number");

      const allStudents = await User.find({ isApproved: true });

      const studentDetails = allStudents.map((student) => {
        const record = attendanceRecords.find(
          (r) => r.studentId.studentId === student.studentId
        );
        return {
          name: student.name,
          studentId: student.studentId,
          grade: student.grade,
          class: student.class,
          number: student.number,
          status: record ? (record.isLate ? "late" : "present") : "absent",
          lateMinutes: record ? record.lateMinutes : 0,
          timestamp: record ? record.timestamp : null,
        };
      });

      const totalAttendance = attendanceRecords.length;
      const onTimeAttendance = attendanceRecords.filter(
        (record) => !record.isLate
      ).length;
      const lateAttendance = attendanceRecords.filter(
        (record) => record.isLate
      ).length;
      const absentCount = allStudents.length - totalAttendance;

      res.json({
        date: targetDate,
        totalAttendance,
        onTimeAttendance,
        lateAttendance,
        absentCount,
        studentDetails,
      });
    } else {
      // 날짜가 제공되지 않은 경우 에러 응답
      res.status(400).json({ message: "날짜를 지정해주세요." });
    }
  } catch (error) {
    console.error("출석 데이터 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});

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
    console.error("Error fetching student info:", error);
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
    const historyRecords = yesterdayAttendances.map((attendance) => ({
      studentId: attendance.studentId,
      isLate: attendance.isLate,
      lateMinutes: attendance.lateMinutes,
    }));

    await AttendanceHistory.create({
      date: yesterday,
      records: historyRecords,
    });

    // 누적 데이터 (UserAttendanceSummary) 업데이트
    for (const attendance of yesterdayAttendances) {
      await UserAttendanceSummary.findOneAndUpdate(
        { studentId: attendance.studentId },
        {
          $inc: {
            totalAttendance: 1,
            totalLateAttendance: attendance.isLate ? 1 : 0,
            totalLateMinutes: attendance.lateMinutes,
          },
        },
        { upsert: true, new: true }
      );
    }

    // 새로운 날을 위해 Attendance 컬렉션 초기화
    await Attendance.deleteMany({});

    console.log("일일 출석 초기화 및 누적 데이터 업데이트 완료");
  } catch (error) {
    console.error("일일 출석 초기화 중 오류 발생:", error);
  }
});

// UserAttendanceSummary 모델 정의 (필요한 경우 추가)
const UserAttendanceSummarySchema = new mongoose.Schema({
  studentId: { type: String, required: true, unique: true },
  totalAttendance: { type: Number, default: 0 },
  totalLateAttendance: { type: Number, default: 0 },
  totalLateMinutes: { type: Number, default: 0 },
});

const UserAttendanceSummary = mongoose.model(
  "UserAttendanceSummary",
  UserAttendanceSummarySchema
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

app.get("/api/download-excel", verifyToken, isAdmin, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    // 출석 데이터 조회
    const attendanceData = await Attendance.find({
      timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
    }).populate("studentId", "name grade class number");

    // 엑셀 파일 생성
    const workbook = new ExcelJS.Workbook();
    const worksheet = workbook.addWorksheet("출석 데이터");

    worksheet.columns = [
      { header: "이름", key: "name", width: 15 },
      { header: "학년", key: "grade", width: 10 },
      { header: "반", key: "class", width: 10 },
      { header: "번호", key: "number", width: 10 },
      { header: "출석 시간", key: "timestamp", width: 20 },
      { header: "지각 여부", key: "isLate", width: 10 },
      { header: "지각 시간(분)", key: "lateMinutes", width: 15 },
    ];

    attendanceData.forEach((record) => {
      worksheet.addRow({
        name: record.studentId.name,
        grade: record.studentId.grade,
        class: record.studentId.class,
        number: record.studentId.number,
        timestamp: record.timestamp,
        isLate: record.isLate ? "지각" : "정상",
        lateMinutes: record.lateMinutes,
        lateReason: record.lateReason || "",
      });
    });

    res.setHeader(
      "Content-Type",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    );
    res.setHeader(
      "Content-Disposition",
      "attachment; filename=attendance_data.xlsx"
    );

    await workbook.xlsx.write(res);
    res.end();
  } catch (error) {
    console.error("엑셀 파일 생성 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
});
