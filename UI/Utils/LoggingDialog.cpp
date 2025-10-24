#include "LoggingDialog.h"
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QMessageBox>
#include <QInputDialog>
#include <QTextCursor>
#include <QTextCharFormat>
#include <QStandardPaths>
#include <QDateTime>

LoggingDialog::LoggingDialog(QWidget *parent)
    : QDialog(parent)
    , m_autoRefreshTimer(new QTimer(this))
    , m_currentLevelFilter(ErrorHandler::Debug)
    , m_currentCategoryFilter(ErrorHandler::General)
    , m_autoRefreshEnabled(false)
{
    setWindowTitle("Application Logs");
    setMinimumSize(800, 600);
    
    setupUI();
    
    // Connect to error handler
    connect(ErrorHandler::instance(), &ErrorHandler::errorLogged,
            this, &LoggingDialog::onNewErrorLogged);
    
    // Setup auto refresh timer
    connect(m_autoRefreshTimer, &QTimer::timeout, this, &LoggingDialog::onAutoRefreshTimer);
    m_autoRefreshTimer->setInterval(2000); // 2 seconds
    
    // Initial load
    refreshLogs();
}

LoggingDialog::~LoggingDialog()
{
    if (m_autoRefreshEnabled) {
        m_autoRefreshTimer->stop();
    }
}

void LoggingDialog::refreshLogs()
{
    m_progressBar->setVisible(true);
    m_progressBar->setRange(0, 0); // Indeterminate progress
    
    // Get recent errors from ErrorHandler
    m_currentLogs = ErrorHandler::instance()->getRecentErrors(1000);
    
    updateLogDisplay();
    
    m_statusLabel->setText(QString("Loaded %1 log entries").arg(m_currentLogs.size()));
    m_progressBar->setVisible(false);
}

void LoggingDialog::clearLogs()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        "Clear Logs",
        "This will clear the log display but not the log files. Continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        m_logDisplay->clear();
        m_currentLogs.clear();
        m_statusLabel->setText("Logs cleared");
    }
}

void LoggingDialog::saveLogs()
{
    QString defaultPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString fileName = QFileDialog::getSaveFileName(this,
        "Save Logs",
        defaultPath + QString("/packet_capture_logs_%1.txt")
                     .arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        "Text Files (*.txt);;All Files (*)");
    
    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream out(&file);
            // Qt6 uses UTF-8 by default, no need to set codec
            
            out << "=== PACKET CAPTURE GUI LOGS ===\n";
            out << "Generated: " << QDateTime::currentDateTime().toString(Qt::ISODate) << "\n";
            out << "Total Entries: " << m_currentLogs.size() << "\n\n";
            
            for (const ErrorHandler::ErrorInfo &error : m_currentLogs) {
                out << formatLogEntry(error) << "\n";
            }
            
            QMessageBox::information(this, "Logs Saved",
                QString("Logs saved to:\n%1").arg(fileName));
            m_statusLabel->setText("Logs saved successfully");
        } else {
            QMessageBox::warning(this, "Save Failed",
                "Failed to save log file.");
        }
    }
}

void LoggingDialog::exportReport()
{
    QString defaultPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString fileName = QFileDialog::getSaveFileName(this,
        "Export Error Report",
        defaultPath + QString("/error_report_%1.txt")
                     .arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        "Text Files (*.txt);;All Files (*)");
    
    if (!fileName.isEmpty()) {
        if (ErrorHandler::instance()->saveErrorReport(fileName)) {
            QMessageBox::information(this, "Report Exported",
                QString("Error report exported to:\n%1").arg(fileName));
            m_statusLabel->setText("Error report exported successfully");
        } else {
            QMessageBox::warning(this, "Export Failed",
                "Failed to export error report.");
        }
    }
}

void LoggingDialog::onFilterChanged()
{
    // Update current filters
    m_currentLevelFilter = static_cast<ErrorHandler::ErrorLevel>(m_levelFilter->currentData().toInt());
    m_currentCategoryFilter = static_cast<ErrorHandler::ErrorCategory>(m_categoryFilter->currentData().toInt());
    
    applyFilters();
}

void LoggingDialog::onAutoRefreshToggled(bool enabled)
{
    m_autoRefreshEnabled = enabled;
    
    if (enabled) {
        m_autoRefreshTimer->start();
        m_statusLabel->setText("Auto refresh enabled");
    } else {
        m_autoRefreshTimer->stop();
        m_statusLabel->setText("Auto refresh disabled");
    }
}

void LoggingDialog::onNewErrorLogged(const ErrorHandler::ErrorInfo &error)
{
    if (m_autoRefreshEnabled) {
        // Add new error to current logs
        m_currentLogs.append(error);
        
        // Limit log size
        if (m_currentLogs.size() > 1000) {
            m_currentLogs.removeFirst();
        }
        
        // Update display if the error matches current filters
        if ((error.level >= m_currentLevelFilter) &&
            (m_currentCategoryFilter == ErrorHandler::General || error.category == m_currentCategoryFilter)) {
            
            QString formattedEntry = formatLogEntry(error);
            
            // Add to display with appropriate color
            QTextCursor cursor = m_logDisplay->textCursor();
            cursor.movePosition(QTextCursor::End);
            
            QTextCharFormat format;
            format.setForeground(QColor(getLogLevelColor(error.level)));
            cursor.setCharFormat(format);
            cursor.insertText(formattedEntry + "\n");
            
            // Auto-scroll to bottom
            m_logDisplay->ensureCursorVisible();
        }
    }
}

void LoggingDialog::onAutoRefreshTimer()
{
    if (m_autoRefreshEnabled) {
        refreshLogs();
    }
}

void LoggingDialog::onCopyToClipboard()
{
    QString selectedText = m_logDisplay->textCursor().selectedText();
    if (selectedText.isEmpty()) {
        selectedText = m_logDisplay->toPlainText();
    }
    
    QApplication::clipboard()->setText(selectedText);
    m_statusLabel->setText("Copied to clipboard");
}

void LoggingDialog::onFindText()
{
    bool ok;
    QString searchText = QInputDialog::getText(this, "Find Text",
        "Enter text to search for:", QLineEdit::Normal, "", &ok);
    
    if (ok && !searchText.isEmpty()) {
        QTextCursor cursor = m_logDisplay->textCursor();
        cursor = m_logDisplay->document()->find(searchText, cursor);
        
        if (!cursor.isNull()) {
            m_logDisplay->setTextCursor(cursor);
            m_statusLabel->setText(QString("Found: %1").arg(searchText));
        } else {
            m_statusLabel->setText(QString("Not found: %1").arg(searchText));
        }
    }
}

void LoggingDialog::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Filter controls
    m_filterLayout = new QHBoxLayout;
    
    m_filterLayout->addWidget(new QLabel("Level:"));
    m_levelFilter = new QComboBox;
    m_levelFilter->addItem("All", -1);
    m_levelFilter->addItem("Debug", ErrorHandler::Debug);
    m_levelFilter->addItem("Info", ErrorHandler::Info);
    m_levelFilter->addItem("Warning", ErrorHandler::Warning);
    m_levelFilter->addItem("Error", ErrorHandler::Error);
    m_levelFilter->addItem("Critical", ErrorHandler::Critical);
    m_levelFilter->setCurrentIndex(0); // All
    connect(m_levelFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LoggingDialog::onFilterChanged);
    m_filterLayout->addWidget(m_levelFilter);
    
    m_filterLayout->addWidget(new QLabel("Category:"));
    m_categoryFilter = new QComboBox;
    m_categoryFilter->addItem("All", -1);
    m_categoryFilter->addItem("General", ErrorHandler::General);
    m_categoryFilter->addItem("Network", ErrorHandler::NetworkInterface);
    m_categoryFilter->addItem("Capture", ErrorHandler::PacketCapture);
    m_categoryFilter->addItem("Protocol", ErrorHandler::ProtocolAnalysis);
    m_categoryFilter->addItem("File I/O", ErrorHandler::FileIO);
    m_categoryFilter->addItem("Memory", ErrorHandler::Memory);
    m_categoryFilter->addItem("Permission", ErrorHandler::Permission);
    m_categoryFilter->addItem("Config", ErrorHandler::Configuration);
    m_categoryFilter->addItem("UI", ErrorHandler::UI);
    m_categoryFilter->setCurrentIndex(0); // All
    connect(m_categoryFilter, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &LoggingDialog::onFilterChanged);
    m_filterLayout->addWidget(m_categoryFilter);
    
    m_filterLayout->addStretch();
    
    m_autoRefreshCheckBox = new QCheckBox("Auto Refresh");
    connect(m_autoRefreshCheckBox, &QCheckBox::toggled,
            this, &LoggingDialog::onAutoRefreshToggled);
    m_filterLayout->addWidget(m_autoRefreshCheckBox);
    
    m_mainLayout->addLayout(m_filterLayout);
    
    // Log display
    m_logDisplay = new QTextEdit;
    m_logDisplay->setReadOnly(true);
    m_logDisplay->setFont(QFont("Courier", 9));
    m_logDisplay->setLineWrapMode(QTextEdit::NoWrap);
    m_mainLayout->addWidget(m_logDisplay);
    
    // Control buttons
    m_controlLayout = new QHBoxLayout;
    
    m_refreshButton = new QPushButton("Refresh");
    connect(m_refreshButton, &QPushButton::clicked, this, &LoggingDialog::refreshLogs);
    m_controlLayout->addWidget(m_refreshButton);
    
    m_clearButton = new QPushButton("Clear Display");
    connect(m_clearButton, &QPushButton::clicked, this, &LoggingDialog::clearLogs);
    m_controlLayout->addWidget(m_clearButton);
    
    m_saveButton = new QPushButton("Save Logs");
    connect(m_saveButton, &QPushButton::clicked, this, &LoggingDialog::saveLogs);
    m_controlLayout->addWidget(m_saveButton);
    
    m_exportButton = new QPushButton("Export Report");
    connect(m_exportButton, &QPushButton::clicked, this, &LoggingDialog::exportReport);
    m_controlLayout->addWidget(m_exportButton);
    
    m_controlLayout->addStretch();
    
    m_copyButton = new QPushButton("Copy");
    connect(m_copyButton, &QPushButton::clicked, this, &LoggingDialog::onCopyToClipboard);
    m_controlLayout->addWidget(m_copyButton);
    
    m_findButton = new QPushButton("Find");
    connect(m_findButton, &QPushButton::clicked, this, &LoggingDialog::onFindText);
    m_controlLayout->addWidget(m_findButton);
    
    m_closeButton = new QPushButton("Close");
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::accept);
    m_controlLayout->addWidget(m_closeButton);
    
    m_mainLayout->addLayout(m_controlLayout);
    
    // Status bar
    QHBoxLayout *statusLayout = new QHBoxLayout;
    m_statusLabel = new QLabel("Ready");
    statusLayout->addWidget(m_statusLabel);
    
    statusLayout->addStretch();
    
    m_progressBar = new QProgressBar;
    m_progressBar->setVisible(false);
    m_progressBar->setMaximumWidth(200);
    statusLayout->addWidget(m_progressBar);
    
    m_mainLayout->addLayout(statusLayout);
}

void LoggingDialog::updateLogDisplay()
{
    m_logDisplay->clear();
    
    QTextCursor cursor = m_logDisplay->textCursor();
    
    for (const ErrorHandler::ErrorInfo &error : m_currentLogs) {
        // Apply filters
        if (m_currentLevelFilter != ErrorHandler::Debug && error.level < m_currentLevelFilter) {
            continue;
        }
        
        if (m_currentCategoryFilter != ErrorHandler::General && error.category != m_currentCategoryFilter) {
            continue;
        }
        
        // Format and add entry
        QString formattedEntry = formatLogEntry(error);
        
        QTextCharFormat format;
        format.setForeground(QColor(getLogLevelColor(error.level)));
        cursor.setCharFormat(format);
        cursor.insertText(formattedEntry + "\n");
    }
    
    // Scroll to bottom
    cursor.movePosition(QTextCursor::End);
    m_logDisplay->setTextCursor(cursor);
}

void LoggingDialog::applyFilters()
{
    updateLogDisplay();
    
    int visibleCount = 0;
    for (const ErrorHandler::ErrorInfo &error : m_currentLogs) {
        if ((m_currentLevelFilter == ErrorHandler::Debug || error.level >= m_currentLevelFilter) &&
            (m_currentCategoryFilter == ErrorHandler::General || error.category == m_currentCategoryFilter)) {
            visibleCount++;
        }
    }
    
    m_statusLabel->setText(QString("Showing %1 of %2 entries").arg(visibleCount).arg(m_currentLogs.size()));
}

QString LoggingDialog::formatLogEntry(const ErrorHandler::ErrorInfo &error) const
{
    QString levelStr;
    switch (error.level) {
        case ErrorHandler::Debug: levelStr = "DEBUG"; break;
        case ErrorHandler::Info: levelStr = "INFO"; break;
        case ErrorHandler::Warning: levelStr = "WARN"; break;
        case ErrorHandler::Error: levelStr = "ERROR"; break;
        case ErrorHandler::Critical: levelStr = "CRIT"; break;
    }
    
    QString categoryStr;
    switch (error.category) {
        case ErrorHandler::General: categoryStr = "General"; break;
        case ErrorHandler::NetworkInterface: categoryStr = "Network"; break;
        case ErrorHandler::PacketCapture: categoryStr = "Capture"; break;
        case ErrorHandler::ProtocolAnalysis: categoryStr = "Protocol"; break;
        case ErrorHandler::FileIO: categoryStr = "FileIO"; break;
        case ErrorHandler::Memory: categoryStr = "Memory"; break;
        case ErrorHandler::Permission: categoryStr = "Permission"; break;
        case ErrorHandler::Configuration: categoryStr = "Config"; break;
        case ErrorHandler::UI: categoryStr = "UI"; break;
    }
    
    QString formatted = QString("[%1] [%2] [%3] %4")
                       .arg(error.timestamp.toString("hh:mm:ss.zzz"))
                       .arg(levelStr)
                       .arg(categoryStr)
                       .arg(error.message);
    
    if (!error.details.isEmpty()) {
        formatted += QString(" - %1").arg(error.details);
    }
    
    if (!error.source.isEmpty()) {
        formatted += QString(" (%1)").arg(error.source);
    }
    
    return formatted;
}

QString LoggingDialog::getLogLevelColor(ErrorHandler::ErrorLevel level) const
{
    switch (level) {
        case ErrorHandler::Debug: return "#808080";    // Gray
        case ErrorHandler::Info: return "#000000";     // Black
        case ErrorHandler::Warning: return "#FF8C00";  // Orange
        case ErrorHandler::Error: return "#FF0000";    // Red
        case ErrorHandler::Critical: return "#8B0000"; // Dark Red
        default: return "#000000";
    }
}