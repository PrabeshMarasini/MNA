#ifndef ERRORHANDLER_H
#define ERRORHANDLER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <QDateTime>
#include <QWidget>
#include <QMessageBox>
#include <QTextStream>
#include <QFile>
#include <QMutex>

/**
 * @brief Comprehensive error handling and logging system
 * 
 * This class provides centralized error handling, logging, and user notification
 * capabilities for the packet capture GUI application.
 */
class ErrorHandler : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Error severity levels
     */
    enum ErrorLevel {
        Debug = 0,      ///< Debug information
        Info,           ///< Informational messages
        Warning,        ///< Warning messages
        Error,          ///< Error messages
        Critical        ///< Critical errors
    };

    /**
     * @brief Error categories for classification
     */
    enum ErrorCategory {
        General = 0,            ///< General application errors
        NetworkInterface,       ///< Network interface related errors
        PacketCapture,         ///< Packet capture errors
        ProtocolAnalysis,      ///< Protocol analysis errors
        FileIO,                ///< File I/O errors
        Memory,                ///< Memory allocation errors
        Permission,            ///< Permission/privilege errors
        Configuration,         ///< Configuration errors
        UI                     ///< User interface errors
    };

    /**
     * @brief Error information structure
     */
    struct ErrorInfo {
        ErrorLevel level;
        ErrorCategory category;
        QString message;
        QString details;
        QString source;         ///< Source function/class
        QDateTime timestamp;
        QString context;        ///< Additional context information
        int errorCode;          ///< System error code (if applicable)
    };

    /**
     * @brief Get singleton instance
     */
    static ErrorHandler* instance();

    /**
     * @brief Initialize error handler with parent widget
     */
    void initialize(QWidget *parentWidget = nullptr);

    /**
     * @brief Set parent widget for dialogs
     */
    void setParentWidget(QWidget *parent) { m_parentWidget = parent; }

    /**
     * @brief Enable/disable logging to file
     */
    void setLoggingEnabled(bool enabled);

    /**
     * @brief Set log file path
     */
    void setLogFile(const QString &filePath);

    /**
     * @brief Set minimum log level
     */
    void setLogLevel(ErrorLevel level) { m_logLevel = level; }

    /**
     * @brief Enable/disable user notifications
     */
    void setUserNotificationsEnabled(bool enabled) { m_userNotificationsEnabled = enabled; }

    /**
     * @brief Enable/disable high-speed mode (minimal logging to prevent crashes)
     */
    void setHighSpeedMode(bool enabled) { m_highSpeedMode = enabled; }

    /**
     * @brief Log error with full information
     */
    void logError(ErrorLevel level, ErrorCategory category, const QString &message,
                  const QString &details = QString(), const QString &source = QString(),
                  const QString &context = QString(), int errorCode = 0);

    /**
     * @brief Convenience methods for different error levels
     */
    void logDebug(const QString &message, const QString &source = QString());
    void logInfo(const QString &message, const QString &source = QString());
    void logWarning(const QString &message, const QString &source = QString());
    void logError(const QString &message, const QString &source = QString());
    void logCritical(const QString &message, const QString &source = QString());

    /**
     * @brief Category-specific error logging
     */
    void logNetworkError(const QString &message, const QString &details = QString(), 
                        const QString &source = QString());
    void logCaptureError(const QString &message, const QString &details = QString(),
                        const QString &source = QString());
    void logProtocolError(const QString &message, const QString &details = QString(),
                         const QString &source = QString());
    void logPermissionError(const QString &message, const QString &details = QString(),
                           const QString &source = QString());
    void logMemoryError(const QString &message, const QString &details = QString(),
                       const QString &source = QString());

    /**
     * @brief Show error dialog to user
     */
    void showErrorDialog(const QString &title, const QString &message, 
                        const QString &details = QString());
    void showWarningDialog(const QString &title, const QString &message,
                          const QString &details = QString());
    void showInfoDialog(const QString &title, const QString &message);

    /**
     * @brief Show error dialog with recovery options
     */
    QMessageBox::StandardButton showErrorWithOptions(const QString &title, const QString &message,
                                                     QMessageBox::StandardButtons buttons = QMessageBox::Ok,
                                                     const QString &details = QString());

    /**
     * @brief Get recent errors
     */
    QList<ErrorInfo> getRecentErrors(int maxCount = 100) const;

    /**
     * @brief Get errors by category
     */
    QList<ErrorInfo> getErrorsByCategory(ErrorCategory category, int maxCount = 100) const;

    /**
     * @brief Get errors by level
     */
    QList<ErrorInfo> getErrorsByLevel(ErrorLevel level, int maxCount = 100) const;

    /**
     * @brief Clear error history
     */
    void clearErrorHistory();

    /**
     * @brief Generate error report
     */
    QString generateErrorReport() const;

    /**
     * @brief Save error report to file
     */
    bool saveErrorReport(const QString &filePath) const;

    /**
     * @brief Get error statistics
     */
    struct ErrorStats {
        int totalErrors;
        int criticalErrors;
        int errors;
        int warnings;
        int infoMessages;
        int debugMessages;
        QDateTime firstError;
        QDateTime lastError;
    };
    ErrorStats getErrorStatistics() const;

    /**
     * @brief Convert error category to string
     */
    QString errorCategoryToString(ErrorCategory category) const;

public slots:
    /**
     * @brief Handle Qt message output
     */
    void handleQtMessage(QtMsgType type, const QMessageLogContext &context, const QString &msg);

signals:
    /**
     * @brief Emitted when an error is logged
     */
    void errorLogged(const ErrorInfo &error);

    /**
     * @brief Emitted when a critical error occurs
     */
    void criticalErrorOccurred(const QString &message);

    /**
     * @brief Emitted when error statistics change
     */
    void errorStatsChanged();

private:
    explicit ErrorHandler(QObject *parent = nullptr);
    ~ErrorHandler();

    /**
     * @brief Write error to log file
     */
    void writeToLogFile(const ErrorInfo &error);

    /**
     * @brief Format error message for logging
     */
    QString formatErrorMessage(const ErrorInfo &error) const;

    /**
     * @brief Convert error level to string
     */
    QString errorLevelToString(ErrorLevel level) const;

    /**
     * @brief Should show user notification for this error
     */
    bool shouldShowUserNotification(const ErrorInfo &error) const;

    /**
     * @brief Create message box for error
     */
    QMessageBox* createMessageBox(const QString &title, const QString &message,
                                 QMessageBox::Icon icon, const QString &details = QString());

    static ErrorHandler* s_instance;
    
    QWidget *m_parentWidget;
    bool m_loggingEnabled;
    QString m_logFilePath;
    ErrorLevel m_logLevel;
    bool m_userNotificationsEnabled;
    bool m_highSpeedMode;
    
    QList<ErrorInfo> m_errorHistory;
    mutable QMutex m_mutex;
    
    QFile *m_logFile;
    QTextStream *m_logStream;
};

/**
 * @brief Convenience macros for error logging
 */
#define LOG_DEBUG(msg) ErrorHandler::instance()->logDebug(msg, Q_FUNC_INFO)
#define LOG_INFO(msg) ErrorHandler::instance()->logInfo(msg, Q_FUNC_INFO)
#define LOG_WARNING(msg) ErrorHandler::instance()->logWarning(msg, Q_FUNC_INFO)
#define LOG_ERROR(msg) ErrorHandler::instance()->logError(msg, Q_FUNC_INFO)
#define LOG_CRITICAL(msg) ErrorHandler::instance()->logCritical(msg, Q_FUNC_INFO)

#define LOG_NETWORK_ERROR(msg, details) ErrorHandler::instance()->logNetworkError(msg, details, Q_FUNC_INFO)
#define LOG_CAPTURE_ERROR(msg, details) ErrorHandler::instance()->logCaptureError(msg, details, Q_FUNC_INFO)
#define LOG_PROTOCOL_ERROR(msg, details) ErrorHandler::instance()->logProtocolError(msg, details, Q_FUNC_INFO)
#define LOG_PERMISSION_ERROR(msg, details) ErrorHandler::instance()->logPermissionError(msg, details, Q_FUNC_INFO)
#define LOG_MEMORY_ERROR(msg, details) ErrorHandler::instance()->logMemoryError(msg, details, Q_FUNC_INFO)

#endif // ERRORHANDLER_H