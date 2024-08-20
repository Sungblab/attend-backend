const cron = require("node-cron");
const { Attendance, AttendanceHistory } = require("../models");

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
    await AttendanceHistory.create({
      date: yesterday,
      records: yesterdayAttendances.map((a) => a._id),
    });

    // 어제의 출석 상태 초기화 (예: isLate 필드를 false로 설정)
    await Attendance.updateMany(
      { timestamp: { $gte: yesterday, $lt: today } },
      { $set: { isLate: false, dailyLateMinutes: 0 } }
    );

    console.log("일일 출석 초기화 완료");
  } catch (error) {
    console.error("일일 출석 초기화 중 오류 발생:", error);
  }
});
