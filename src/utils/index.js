const crypto = require("crypto");

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

const calculateLateMinutes = (
  timestamp,
  ATTENDANCE_HOUR,
  ATTENDANCE_MINUTE
) => {
  const attendanceTime = new Date(timestamp);
  const expectedTime = new Date(timestamp);
  expectedTime.setHours(ATTENDANCE_HOUR, ATTENDANCE_MINUTE, 0, 0);

  if (attendanceTime > expectedTime) {
    return Math.floor((attendanceTime - expectedTime) / 60000);
  }
  return 0;
};

const encryptQRData = (qrData) => {
  if (!process.env.ENCRYPTION_KEY || process.env.ENCRYPTION_KEY.length !== 32) {
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

  return iv.toString("hex") + ":" + encryptedData;
};

const decryptQRData = (encryptedData) => {
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
  return decrypted;
};

module.exports = {
  getWorkingDays,
  calculateLateMinutes,
  encryptQRData,
  decryptQRData,
};
