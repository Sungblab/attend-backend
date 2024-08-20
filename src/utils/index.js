const crypto = require("crypto");
const ExcelJS = require("exceljs");
const {
  ENCRYPTION_KEY,
  ATTENDANCE_HOUR,
  ATTENDANCE_MINUTE,
} = require("../config");

const encrypt = (data) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let encrypted = cipher.update(data, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
};

const decrypt = (encryptedData) => {
  const [ivHex, encryptedHex] = encryptedData.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encryptedHex, "hex");
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    Buffer.from(ENCRYPTION_KEY),
    iv
  );
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
};

const getWorkingDays = (startDate, endDate) => {
  let count = 0;
  const curDate = new Date(startDate.getTime());
  while (curDate <= endDate) {
    const dayOfWeek = curDate.getDay();
    if (dayOfWeek !== 0 && dayOfWeek !== 6) count++;
    curDate.setDate(curDate.getDate() + 1);
  }
  return count;
};

const calculateOverallStats = (attendanceData, startDate, endDate) => {
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
};

const calculateLateMinutes = (timestamp) => {
  const attendanceTime = new Date(timestamp);
  const expectedTime = new Date(timestamp);
  expectedTime.setHours(ATTENDANCE_HOUR, ATTENDANCE_MINUTE, 0, 0);

  if (attendanceTime > expectedTime) {
    return Math.floor((attendanceTime - expectedTime) / 60000); // 분 단위로 반환
  }
  return 0;
};

const generateExcel = async (attendanceData) => {
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

  return workbook;
};

module.exports = {
  encrypt,
  decrypt,
  getWorkingDays,
  calculateOverallStats,
  calculateLateMinutes,
  generateExcel,
};
