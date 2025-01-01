const winston = require("winston");
const moment = require("moment-timezone");

// 로그 레벨 정의
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3,
  debug: 4,
};

// 로그 레벨 색상 정의
const colors = {
  error: "red",
  warn: "yellow",
  info: "green",
  http: "magenta",
  debug: "blue",
};

// winston에 색상 추가
winston.addColors(colors);

// 로그 포맷 정의
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: () => moment().tz("Asia/Seoul").format("YYYY-MM-DD HH:mm:ss"),
  }),
  winston.format.printf(({ timestamp, level, message }) => {
    return `${timestamp} [${level.toUpperCase()}]: ${message}`;
  })
);

// 로거 생성
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  levels,
  format: logFormat,
  transports: [
    // 에러 로그는 error.log 파일에 저장
    new winston.transports.File({
      filename: "logs/error.log",
      level: "error",
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // 모든 로그는 combined.log 파일에 저장
    new winston.transports.File({
      filename: "logs/combined.log",
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
  ],
});

// 개발 환경에서는 콘솔에도 로그 출력
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize({ all: true }),
        logFormat
      ),
    })
  );
}

module.exports = logger;
