#include "ErrorHandler.h"
#include <QApplication>
#include <QStandardPaths>
#include <QDir>
#include <QDebug>
#include <QThread>
#include <QMutexLocker>
#include <ctime>

ErrorHandler* ErrorHandler::s_instance = nullptr;

ErrorHandler::ErrorHandler(QObject *parent)
    : QObject(parent)
    , m_parentWidget(nullptr)
    , m_loggingEnabled(true)
    , m_logLevel(Info)
    , m_userNotificationsEnabled(true)
    , m_highSpeedMode(false)
    , m_logFile(nullptr)
    , m_logStream(nullptr)
{
    // Set default log file path
    QString logDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    QDir().mkpath(logDir);
    m_logFilePath = logDir + "/packet_capture_gui.log";
    
    // Install Qt message handler
    qInstallMessageHandler([](QtMsgType type, const QMessageLogContext &context, const QString &msg) {
        if (ErrorHandler::s_instance) {
            ErrorHandler::s_instance->handleQtMessage(type, context, msg);
        }
    });
    
    qDebug() << "ErrorHandler: Initialized with log file:" << m_logFilePath;
}

ErrorHandler::~ErrorHandler()
{
    if (m_logStream) {
        delete m_logStream;
    }
    if (m_logFile) {
        m_logFile->close();
        delete m_logFile;
    }
}

ErrorHandler* ErrorHandler::instance()
{
    if (!s_instance) {
        s_instance = new ErrorHandler();
    }
    return s_instance;
}

void ErrorHandler::initialize(QWidget *parentWidget)
{
    m_parentWidget = parentWidget;
    setLoggingEnabled(true);
    
    logInfo("ErrorHandler initialized", "ErrorHandler::initialize");
}

void ErrorHandler::setLoggingEnabled(bool enabled)
{
    QMutexLocker locker(&m_mutex);
    
    m_loggingEnabled = enabled;
    
    if (enabled && !m_logFile) {
        m_logFile = new QFile(m_logFilePath);
        if (m_logFile->open(QIODevice::WriteOnly | QIODevice::Append)) {
            m_logStream = new QTextStream(m_logFile);
            // Qt6 uses UTF-8 by default, no need to set codec
            
            // Write session start marker
            *m_logStream << "\n=== SESSION START: " 
                        << QDateTime::currentDateTime().toString(Qt::ISODate) 
                        << " ===\n";
            m_logStream->flush();
        } else {
            qWarning() << "ErrorHandler: Failed to open log file:" << m_logFilePath;
            delete m_logFile;
            m_logFile = nullptr;
        }
    } else if (!enabled && m_logFile) {
        // Write session end marker
        if (m_logStream) {
            *m_logStream << "=== SESSION END: " 
                        << QDateTime::currentDateTime().toString(Qt::ISODate) 
                        << " ===\n\n";
            m_logStream->flush();
            delete m_logStream;
            m_logStream = nullptr;
        }
        
        m_logFile->close();
        delete m_logFile;
        m_logFile = nullptr;
    }
}

void ErrorHandler::setLogFile(const QString &filePath)
{
    QMutexLocker locker(&m_mutex);
    
    bool wasEnabled = m_loggingEnabled;
    if (wasEnabled) {
        setLoggingEnabled(false);
    }
    
    m_logFilePath = filePath;
    
    if (wasEnabled) {
        setLoggingEnabled(true);
    }
}

void ErrorHandler::logError(ErrorLevel level, ErrorCategory category, const QString &message,
                           const QString &details, const QString &source,
                           const QString &context, int errorCode)
{
    if (level < m_logLevel) {
        return;
    }
    
    // In high-speed mode, only log critical errors and avoid complex operations
    if (m_highSpeedMode && level < Critical) {
        return;
    }
    
    ErrorInfo error;
    error.level = level;
    error.category = category;
    error.message = message;
    error.details = details;
    error.source = source;
    
    // Ultra-safe timestamp creation - avoid all Qt datetime operations during high-speed processing
    // Use a simple invalid timestamp that will be handled safely in formatErrorMessage
    error.timestamp = QDateTime(); // Invalid timestamp - will be handled safely
    
    error.context = context;
    error.errorCode = errorCode;
    
    QMutexLocker locker(&m_mutex);
    
    // Add to error history
    m_errorHistory.append(error);
    
    // Limit history size
    if (m_errorHistory.size() > 10000) {
        m_errorHistory.removeFirst();
    }
    
    locker.unlock();
    
    // Write to log file
    if (m_loggingEnabled) {
        writeToLogFile(error);
    }
    
    // Show user notification if appropriate
    if (shouldShowUserNotification(error)) {
        QMetaObject::invokeMethod(this, [this, error]() {
            QString title = QString("%1 - %2")
                           .arg(errorLevelToString(error.level))
                           .arg(errorCategoryToString(error.category));
            
            switch (error.level) {
                case Critical:
                case Error:
                    showErrorDialog(title, error.message, error.details);
                    break;
                case Warning:
                    showWarningDialog(title, error.message, error.details);
                    break;
                case Info:
                    if (error.category == Permission || error.category == NetworkInterface) {
                        showInfoDialog(title, error.message);
                    }
                    break;
                default:
                    break;
            }
        }, Qt::QueuedConnection);
    }
    
    // Emit signals
    emit errorLogged(error);
    
    if (level == Critical) {
        emit criticalErrorOccurred(message);
    }
    
    emit errorStatsChanged();
}

void ErrorHandler::logDebug(const QString &message, const QString &source)
{
    logError(Debug, General, message, QString(), source);
}

void ErrorHandler::logInfo(const QString &message, const QString &source)
{
    logError(Info, General, message, QString(), source);
}

void ErrorHandler::logWarning(const QString &message, const QString &source)
{
    logError(Warning, General, message, QString(), source);
}

void ErrorHandler::logError(const QString &message, const QString &source)
{
    logError(Error, General, message, QString(), source);
}

void ErrorHandler::logCritical(const QString &message, const QString &source)
{
    logError(Critical, General, message, QString(), source);
}

void ErrorHandler::logNetworkError(const QString &message, const QString &details, const QString &source)
{
    logError(Error, NetworkInterface, message, details, source);
}

void ErrorHandler::logCaptureError(const QString &message, const QString &details, const QString &source)
{
    logError(Error, PacketCapture, message, details, source);
}

void ErrorHandler::logProtocolError(const QString &message, const QString &details, const QString &source)
{
    logError(Warning, ProtocolAnalysis, message, details, source);
}

void ErrorHandler::logPermissionError(const QString &message, const QString &details, const QString &source)
{
    logError(Error, Permission, message, details, source);
}

void ErrorHandler::logMemoryError(const QString &message, const QString &details, const QString &source)
{
    logError(Critical, Memory, message, details, source);
}

void ErrorHandler::showErrorDialog(const QString &title, const QString &message, const QString &details)
{
    if (!m_userNotificationsEnabled) return;
    
    QMessageBox *msgBox = createMessageBox(title, message, QMessageBox::Critical, details);
    msgBox->exec();
    delete msgBox;
}

void ErrorHandler::showWarningDialog(const QString &title, const QString &message, const QString &details)
{
    if (!m_userNotificationsEnabled) return;
    
    QMessageBox *msgBox = createMessageBox(title, message, QMessageBox::Warning, details);
    msgBox->exec();
    delete msgBox;
}

void ErrorHandler::showInfoDialog(const QString &title, const QString &message)
{
    if (!m_userNotificationsEnabled) return;
    
    QMessageBox *msgBox = createMessageBox(title, message, QMessageBox::Information);
    msgBox->exec();
    delete msgBox;
}

QMessageBox::StandardButton ErrorHandler::showErrorWithOptions(const QString &title, const QString &message,
                                                               QMessageBox::StandardButtons buttons,
                                                               const QString &details)
{
    if (!m_userNotificationsEnabled) return QMessageBox::Ok;
    
    QMessageBox *msgBox = createMessageBox(title, message, QMessageBox::Critical, details);
    msgBox->setStandardButtons(buttons);
    
    QMessageBox::StandardButton result = static_cast<QMessageBox::StandardButton>(msgBox->exec());
    delete msgBox;
    
    return result;
}

QList<ErrorHandler::ErrorInfo> ErrorHandler::getRecentErrors(int maxCount) const
{
    QMutexLocker locker(&m_mutex);
    
    if (m_errorHistory.size() <= maxCount) {
        return m_errorHistory;
    }
    
    return m_errorHistory.mid(m_errorHistory.size() - maxCount);
}

QList<ErrorHandler::ErrorInfo> ErrorHandler::getErrorsByCategory(ErrorCategory category, int maxCount) const
{
    QMutexLocker locker(&m_mutex);
    
    QList<ErrorInfo> filtered;
    for (const ErrorInfo &error : m_errorHistory) {
        if (error.category == category) {
            filtered.append(error);
            if (filtered.size() >= maxCount) {
                break;
            }
        }
    }
    
    return filtered;
}

QList<ErrorHandler::ErrorInfo> ErrorHandler::getErrorsByLevel(ErrorLevel level, int maxCount) const
{
    QMutexLocker locker(&m_mutex);
    
    QList<ErrorInfo> filtered;
    for (const ErrorInfo &error : m_errorHistory) {
        if (error.level == level) {
            filtered.append(error);
            if (filtered.size() >= maxCount) {
                break;
            }
        }
    }
    
    return filtered;
}

void ErrorHandler::clearErrorHistory()
{
    QMutexLocker locker(&m_mutex);
    m_errorHistory.clear();
    emit errorStatsChanged();
}

QString ErrorHandler::generateErrorReport() const
{
    QMutexLocker locker(&m_mutex);
    
    QString report;
    QTextStream stream(&report);
    
    stream << "=== PACKET CAPTURE GUI ERROR REPORT ===\n";
    stream << "Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
    stream << "Application: " << QApplication::applicationName() << " " 
           << QApplication::applicationVersion() << "\n";
    stream << "Qt Version: " << qVersion() << "\n";
    stream << "\n";
    
    // Statistics
    ErrorStats stats = getErrorStatistics();
    stream << "ERROR STATISTICS:\n";
    stream << "  Total Errors: " << stats.totalErrors << "\n";
    stream << "  Critical: " << stats.criticalErrors << "\n";
    stream << "  Errors: " << stats.errors << "\n";
    stream << "  Warnings: " << stats.warnings << "\n";
    stream << "  Info: " << stats.infoMessages << "\n";
    stream << "  Debug: " << stats.debugMessages << "\n";
    
    if (stats.totalErrors > 0) {
        stream << "  First Error: " << stats.firstError.toString(Qt::ISODate) << "\n";
        stream << "  Last Error: " << stats.lastError.toString(Qt::ISODate) << "\n";
    }
    stream << "\n";
    
    // Recent errors by category
    QMap<ErrorCategory, int> categoryCount;
    for (const ErrorInfo &error : m_errorHistory) {
        categoryCount[error.category]++;
    }
    
    stream << "ERRORS BY CATEGORY:\n";
    for (auto it = categoryCount.begin(); it != categoryCount.end(); ++it) {
        stream << "  " << errorCategoryToString(it.key()) << ": " << it.value() << "\n";
    }
    stream << "\n";
    
    // Recent errors (last 50)
    QList<ErrorInfo> recentErrors = getRecentErrors(50);
    if (!recentErrors.isEmpty()) {
        stream << "RECENT ERRORS (Last " << recentErrors.size() << "):\n";
        for (const ErrorInfo &error : recentErrors) {
            stream << formatErrorMessage(error) << "\n";
        }
    }
    
    stream << "\n=== END OF REPORT ===\n";
    
    return report;
}

bool ErrorHandler::saveErrorReport(const QString &filePath) const
{
    QFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Text)) {
        return false;
    }
    
    QTextStream out(&file);
    // Qt6 uses UTF-8 by default, no need to set codec
    out << generateErrorReport();
    
    return true;
}

ErrorHandler::ErrorStats ErrorHandler::getErrorStatistics() const
{
    ErrorStats stats = {};
    
    if (m_errorHistory.isEmpty()) {
        return stats;
    }
    
    stats.totalErrors = m_errorHistory.size();
    stats.firstError = m_errorHistory.first().timestamp;
    stats.lastError = m_errorHistory.last().timestamp;
    
    for (const ErrorInfo &error : m_errorHistory) {
        switch (error.level) {
            case Critical:
                stats.criticalErrors++;
                break;
            case Error:
                stats.errors++;
                break;
            case Warning:
                stats.warnings++;
                break;
            case Info:
                stats.infoMessages++;
                break;
            case Debug:
                stats.debugMessages++;
                break;
        }
    }
    
    return stats;
}

void ErrorHandler::handleQtMessage(QtMsgType type, const QMessageLogContext &context, const QString &msg)
{
    ErrorLevel level;
    switch (type) {
        case QtDebugMsg:
            level = Debug;
            break;
        case QtInfoMsg:
            level = Info;
            break;
        case QtWarningMsg:
            level = Warning;
            break;
        case QtCriticalMsg:
            level = Error;
            break;
        case QtFatalMsg:
            level = Critical;
            break;
    }
    
    QString source = QString("%1:%2").arg(context.file ? context.file : "unknown")
                                    .arg(context.line);
    
    logError(level, General, msg, QString(), source, context.function ? context.function : "");
}

void ErrorHandler::writeToLogFile(const ErrorInfo &error)
{
    // Thread-safe logging with mutex protection
    QMutexLocker locker(&m_mutex);
    
    if (!m_logStream) return;
    
    try {
        QString message = formatErrorMessage(error);
        *m_logStream << message << "\n";
        m_logStream->flush();
    } catch (...) {
        // If logging fails, try a simple fallback
        try {
            *m_logStream << "ERROR: Failed to format log message\n";
            m_logStream->flush();
        } catch (...) {
            // If even the fallback fails, just ignore to prevent crash
        }
    }
}

QString ErrorHandler::formatErrorMessage(const ErrorInfo &error) const
{
    // Ultra-safe timestamp handling - avoid all datetime/locale operations during crashes
    QString timestampStr;
    if (error.timestamp.isValid()) {
        try {
            timestampStr = error.timestamp.toString(Qt::ISODate);
        } catch (...) {
            // If Qt datetime fails, use simple counter
            static int errorCounter = 0;
            timestampStr = QString("ERR_%1").arg(++errorCounter);
        }
    } else {
        // Use simple counter to completely avoid locale/timezone issues
        static int errorCounter = 0;
        timestampStr = QString("ERR_%1").arg(++errorCounter);
    }
    
    // Safely handle string formatting to prevent crashes
    QString formatted;
    try {
        formatted = QString("[%1] [%2] [%3] %4")
                   .arg(timestampStr)
                   .arg(errorLevelToString(error.level))
                   .arg(errorCategoryToString(error.category))
                   .arg(error.message);
    } catch (...) {
        // Fallback formatting if QString operations fail
        formatted = QString("ERROR: Failed to format error message - ") + error.message;
    }
    
    // Safely append additional information
    try {
        if (!error.details.isEmpty()) {
            formatted += QString(" - Details: %1").arg(error.details);
        }
        
        if (!error.source.isEmpty()) {
            formatted += QString(" - Source: %1").arg(error.source);
        }
        
        if (!error.context.isEmpty()) {
            formatted += QString(" - Context: %1").arg(error.context);
        }
        
        if (error.errorCode != 0) {
            formatted += QString(" - Code: %1").arg(error.errorCode);
        }
    } catch (...) {
        // If appending fails, just use what we have
        formatted += " [Additional details truncated due to formatting error]";
    }
    
    return formatted;
}

QString ErrorHandler::errorLevelToString(ErrorLevel level) const
{
    switch (level) {
        case Debug: return "DEBUG";
        case Info: return "INFO";
        case Warning: return "WARNING";
        case Error: return "ERROR";
        case Critical: return "CRITICAL";
        default: return "UNKNOWN";
    }
}

QString ErrorHandler::errorCategoryToString(ErrorCategory category) const
{
    switch (category) {
        case General: return "General";
        case NetworkInterface: return "Network";
        case PacketCapture: return "Capture";
        case ProtocolAnalysis: return "Protocol";
        case FileIO: return "FileIO";
        case Memory: return "Memory";
        case Permission: return "Permission";
        case Configuration: return "Config";
        case UI: return "UI";
        default: return "Unknown";
    }
}

bool ErrorHandler::shouldShowUserNotification(const ErrorInfo &error) const
{
    if (!m_userNotificationsEnabled) return false;
    
    // Always show critical errors and permission errors
    if (error.level == Critical || error.category == Permission) {
        return true;
    }
    
    // Show network and capture errors
    if ((error.category == NetworkInterface || error.category == PacketCapture) && 
        error.level >= Warning) {
        return true;
    }
    
    // Show memory errors
    if (error.category == Memory && error.level >= Error) {
        return true;
    }
    
    return false;
}

QMessageBox* ErrorHandler::createMessageBox(const QString &title, const QString &message,
                                           QMessageBox::Icon icon, const QString &details)
{
    QMessageBox *msgBox = new QMessageBox(m_parentWidget);
    msgBox->setWindowTitle(title);
    msgBox->setText(message);
    msgBox->setIcon(icon);
    
    if (!details.isEmpty()) {
        msgBox->setDetailedText(details);
    }
    
    // Set appropriate button
    switch (icon) {
        case QMessageBox::Critical:
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->setDefaultButton(QMessageBox::Ok);
            break;
        case QMessageBox::Warning:
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->setDefaultButton(QMessageBox::Ok);
            break;
        case QMessageBox::Information:
            msgBox->setStandardButtons(QMessageBox::Ok);
            msgBox->setDefaultButton(QMessageBox::Ok);
            break;
        default:
            msgBox->setStandardButtons(QMessageBox::Ok);
            break;
    }
    
    return msgBox;
}