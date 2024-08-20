const express = require("express");
const { verifyToken, isAdmin, isReader } = require("../middleware");
const {
  signup,
  login,
  changePassword,
  recordAttendance,
  getAttendance,
  generateQR,
  getPendingUsers,
  approveUser,
  setAdminStatus,
  setReaderStatus,
  getDashboard,
  modifyAttendance,
  resetPassword,
  downloadExcel,
  approveAttendance,
} = require("../controllers");

const router = express.Router();

// Auth routes
router.post("/signup", signup);
router.post("/login", login);
router.post("/change-password", verifyToken, changePassword);
router.post("/logout", verifyToken, (req, res) => {
  res.json({ success: true, message: "로그아웃되었습니다." });
});

// Attendance routes
router.post("/attendance", verifyToken, isReader, recordAttendance);
router.get("/attendance", verifyToken, isAdmin, getAttendance);
router.post("/generate-qr", verifyToken, generateQR);
router.post("/attendance/modify", verifyToken, isAdmin, modifyAttendance);
router.post("/attendance/approve", verifyToken, isAdmin, approveAttendance);

// Admin routes
router.get("/admin/pending-users", verifyToken, isAdmin, getPendingUsers);
router.post("/admin/approve-user", verifyToken, isAdmin, approveUser);
router.post("/admin/set-admin", verifyToken, isAdmin, setAdminStatus);
router.post("/admin/set-reader", verifyToken, isAdmin, setReaderStatus);
router.post("/admin/reset-password", verifyToken, isAdmin, resetPassword);
router.get("/admin/users", verifyToken, isAdmin, async (req, res) => {
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
router.delete(
  "/admin/users/:userId",
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

// Dashboard route
router.get("/dashboard", verifyToken, isAdmin, getDashboard);

// Excel download route
router.get("/download-excel", verifyToken, isAdmin, downloadExcel);

// Student info route
router.get("/student-info", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) {
      return res
        .status(404)
        .json({ success: false, message: "사용자를 찾을 수 없습니다." });
    }
    res.json({ success: true, studentId: user.studentId, name: user.name });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ success: false, message: "서버 오류가 발생했습니다." });
  }
});

module.exports = router;
