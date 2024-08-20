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
router.get("/admin/users", verifyToken, isAdmin, (req, res) => {
  // Implement getUsers logic here
});
router.delete("/admin/users/:userId", verifyToken, isAdmin, (req, res) => {
  // Implement deleteUser logic here
});

// Dashboard route
router.get("/dashboard", verifyToken, isAdmin, getDashboard);

// Excel download route
router.get("/download-excel", verifyToken, isAdmin, downloadExcel);

// Student info route
router.get("/student-info", verifyToken, (req, res) => {
  // Implement getStudentInfo logic here
});

module.exports = router;
