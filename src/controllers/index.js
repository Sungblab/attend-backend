const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const ExcelJS = require("exceljs");
const moment = require("moment-timezone");
const { User, Attendance, AttendanceHistory } = require("../models");
const { constants } = require("../config");
const {
  getWorkingDays,
  calculateLateMinutes,
  encryptQRData,
  decryptQRData,
} = require("../utils");

// Auth controllers
exports.signup = async (req, res) => {
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
};

exports.login = async (req, res) => {
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
};

exports.changePassword = async (req, res) => {
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
};

// Attendance controllers
exports.recordAttendance = async (req, res) => {
  try {
    const { encryptedData } = req.body;
    const decrypted = decryptQRData(encryptedData);
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
    attendanceTime.setHours(
      constants.ATTENDANCE_HOUR,
      constants.ATTENDANCE_MINUTE,
      0,
      0
    );
    console.log(`출석 기준 시간 (KST): ${attendanceTime.toISOString()}`);

    const absenceTime = new Date(today);
    absenceTime.setHours(9, 0, 0, 0);
    console.log(`결석 기준 시간 (KST): ${absenceTime.toISOString()}`);

    if (kstNow >= absenceTime) {
      console.log(`결석 처리 (KST): ${studentId}, ${kstNow.toISOString()}`);
      return res.status(400).json({ message: "결석 처리되었습니다." });
    }

    const isLate = kstNow > attendanceTime;
    const dailyLateMinutes = isLate
      ? Math.floor((kstNow - attendanceTime) / 60000)
      : 0;

    const attendance = new Attendance({
      studentId,
      timestamp: now,
      isLate,
      dailyLateMinutes,
    });

    await attendance.save();

    console.log(
      `출석 기록 (KST): 학생 ID ${studentId}, 시간 ${kstNow.toISOString()}, 지각 여부 ${isLate}, 지각 시간 ${dailyLateMinutes}분`
    );

    const responseMessage = isLate
      ? `"${studentId}" "${student.name}" 출석 성공. ${dailyLateMinutes}분 지각입니다.`
      : `"${studentId}" "${student.name}" 출석 성공.`;

    res.status(201).json({
      message: responseMessage,
      isLate,
      dailyLateMinutes,
    });
  } catch (error) {
    console.error("출석 기록 중 오류 발생:", error);
    res
      .status(500)
      .json({ message: "서버 오류가 발생했습니다.", error: error.message });
  }
};

exports.getAttendance = async (req, res) => {
  try {
    const attendanceRecords = await Attendance.find()
      .sort({ timestamp: -1 })
      .populate("approvedBy", "name");
    res.json(attendanceRecords);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

exports.generateQR = async (req, res) => {
  try {
    const { studentId, timestamp } = req.body;
    const user = await User.findOne({ studentId });
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }

    const qrData = `${studentId}|${timestamp}`;
    const encryptedData = encryptQRData(qrData);

    res.json({ success: true, encryptedData: encryptedData });
  } catch (error) {
    console.error("QR 코드 생성 오류:", error);
    res.status(500).json({
      success: false,
      message: "서버 오류가 발생했습니다: " + error.message,
    });
  }
};

exports.modifyAttendance = async (req, res) => {
  try {
    const { studentId, date, status, lateReason } = req.body;

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
    attendance.lateReason = status === "late" ? lateReason : null;

    await attendance.save();

    res.json({ message: "출석 상태가 성공적으로 수정되었습니다.", attendance });
  } catch (error) {
    console.error("출석 수정 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

exports.approveAttendance = async (req, res) => {
  try {
    const { studentId, reason, date } = req.body;

    const approvalDate = date
      ? moment(date).tz("Asia/Seoul").startOf("day")
      : moment().tz("Asia/Seoul").startOf("day");

    const attendance = await Attendance.findOne({
      studentId,
      timestamp: {
        $gte: approvalDate.toDate(),
        $lt: moment(approvalDate).add(1, "days").toDate(),
      },
    });

    if (!attendance) {
      return res
        .status(404)
        .json({ message: "해당 날짜의 출석 기록을 찾을 수 없습니다." });
    }

    attendance.isLate = false;
    attendance.dailyLateMinutes = 0;
    attendance.lateReason = null;
    attendance.approvedBy = req.user.id;
    attendance.approvalReason = reason;
    attendance.approvalTimestamp = new Date();

    await attendance.save();

    const allAttendances = await Attendance.find({ studentId });
    const totalLateMinutes = allAttendances.reduce(
      (sum, record) => sum + (record.dailyLateMinutes || 0),
      0
    );

    await User.findOneAndUpdate(
      { studentId },
      { $set: { totalLateMinutes: totalLateMinutes } }
    );

    res.json({ message: "출결이 성공적으로 인정되었습니다." });
  } catch (error) {
    console.error("출결 인정 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

// Admin controllers
exports.getPendingUsers = async (req, res) => {
  try {
    const pendingUsers = await User.find({ isApproved: false });
    res.json(pendingUsers);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

exports.approveUser = async (req, res) => {
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
};

exports.setAdminStatus = async (req, res) => {
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
};

exports.setReaderStatus = async (req, res) => {
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
};

exports.resetPassword = async (req, res) => {
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
};

// Dashboard controller
exports.getDashboard = async (req, res) => {
  try {
    const {
      grade,
      class: classNumber,
      period,
      attendanceStatus,
      lateCount,
      search,
      page = 1,
      limit = 20,
    } = req.query;
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
    if (search) {
      userQuery.$or = [
        { name: { $regex: search, $options: "i" } },
        { studentId: { $regex: search, $options: "i" } },
      ];
    }

    const users = await User.find(userQuery)
      .sort({ grade: 1, class: 1, number: 1 })
      .skip((page - 1) * limit)
      .limit(Number(limit))
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

      let lastAttendanceTime = null;
      if (allUserAttendance.length > 0) {
        const latestAttendance = allUserAttendance.reduce((latest, current) =>
          latest.timestamp > current.timestamp ? latest : current
        );
        lastAttendanceTime = latestAttendance.timestamp
          ? latestAttendance.timestamp.toISOString()
          : null;
      }

      // 지각 기록 추가
      const lateRecords = allUserAttendance
        .filter((record) => record.isLate)
        .map((record) => ({
          date: record.timestamp,
          lateMinutes: record.lateMinutes,
        }));

      // 출석 날짜와 지각 날짜 추가
      const attendanceDates = allUserAttendance.map(
        (record) => record.timestamp
      );
      const lateDates = allUserAttendance
        .filter((record) => record.isLate)
        .map((record) => record.timestamp);

      return {
        name: user.name,
        studentId: user.studentId,
        grade: user.grade,
        class: user.class,
        number: user.number,
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
        lateRecords,
        attendanceDates,
        lateDates,
      };
    });

    // 전체 통계 계산
    const overallStats = calculateOverallStats(
      attendanceData,
      startDate,
      endDate
    );

    // 최우수 출석 학생 찾기
    const bestAttendanceStudent = findBestAttendanceStudent(attendanceData);

    // 필터링 적용
    let filteredAttendanceData = attendanceData;
    if (attendanceStatus) {
      filteredAttendanceData = filteredAttendanceData.filter((student) => {
        if (attendanceStatus === "present")
          return student.totalAttendance > 0 && student.lateAttendance === 0;
        if (attendanceStatus === "late") return student.lateAttendance > 0;
        if (attendanceStatus === "absent") return student.totalAttendance === 0;
      });
    }
    if (lateCount) {
      filteredAttendanceData = filteredAttendanceData.filter(
        (student) => student.lateAttendance >= Number(lateCount)
      );
    }

    // 전체 학생 수 계산 (페이지네이션을 위해)
    const totalStudents = await User.countDocuments(userQuery);

    res.json({
      attendanceData: filteredAttendanceData,
      overallStats,
      bestAttendanceStudent,
      period: { startDate, endDate },
      pagination: {
        currentPage: Number(page),
        totalPages: Math.ceil(totalStudents / limit),
        totalItems: totalStudents,
      },
    });
  } catch (error) {
    console.error("대시보드 데이터 조회 중 오류 발생:", error);
    res.status(500).json({ message: "서버 오류가 발생했습니다." });
  }
};

// Excel download controller
exports.downloadExcel = async (req, res) => {
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
      { header: "지각 사유", key: "lateReason", width: 30 },
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
};

// Utility functions
function findBestAttendanceStudent(attendanceData) {
  return attendanceData.reduce((best, current) => {
    if (!best || current.totalAttendance > best.totalAttendance) {
      return current;
    } else if (
      current.totalAttendance === best.totalAttendance &&
      current.lateAttendance < best.lateAttendance
    ) {
      return current;
    }
    return best;
  }, null);
}

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

  const workingDays = getWorkingDays(startDate, endDate);

  stats.averageAttendanceRate = (
    (stats.totalAttendance / (stats.totalStudents * workingDays)) *
    100
  ).toFixed(2);
  stats.averageLateRate =
    stats.totalAttendance > 0
      ? ((stats.totalLateAttendance / stats.totalAttendance) * 100).toFixed(2)
      : 0;
  stats.averageLateMinutes = (
    stats.totalLateMinutes / stats.totalLateAttendance || 0
  ).toFixed(2);

  return stats;
}
