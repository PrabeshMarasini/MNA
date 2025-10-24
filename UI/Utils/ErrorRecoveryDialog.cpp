#include "ErrorRecoveryDialog.h"
#include <QApplication>
#include <QMessageBox>
#include <QCloseEvent>
#include <QDesktopServices>
#include <QUrl>
#include <QProcess>
#include <QStandardPaths>
#include <QDir>
#include <QStyle>

ErrorRecoveryDialog::ErrorRecoveryDialog(const ErrorHandler::ErrorInfo &error, QWidget *parent)
    : QDialog(parent)
    , m_errorInfo(error)
    , m_title(QString("%1 Error").arg(ErrorHandler::instance()->errorCategoryToString(error.category)))
    , m_message(error.message)
    , m_details(error.details)
    , m_defaultAction(Retry)
    , m_autoRecoveryTimeout(0)
    , m_remainingTime(0)
    , m_autoRecoveryTimer(new QTimer(this))
    , m_progressTimer(new QTimer(this))
    , m_detailsVisible(false)
{
    // Determine available actions based on error type
    switch (error.category) {
        case ErrorHandler::NetworkInterface:
            m_availableActions << Retry << Reset << IgnoreError << ReportAndContinue;
            break;
        case ErrorHandler::PacketCapture:
            m_availableActions << Retry << Reset << IgnoreError;
            break;
        case ErrorHandler::Memory:
            m_availableActions << Reset << Restart << SafeShutdown;
            m_defaultAction = Reset;
            break;
        case ErrorHandler::Permission:
            m_availableActions << Restart << IgnoreError << ReportAndContinue;
            break;
        default:
            m_availableActions << Retry << IgnoreError << ReportAndContinue;
            break;
    }

    setupUI();
    
    // Set auto recovery for certain error types
    if (error.level <= ErrorHandler::Warning) {
        setAutoRecoveryTimeout(10); // 10 seconds for warnings
    }
}

ErrorRecoveryDialog::ErrorRecoveryDialog(const QString &title, const QString &message,
                                       const QString &details, const QList<RecoveryAction> &availableActions,
                                       QWidget *parent)
    : QDialog(parent)
    , m_title(title)
    , m_message(message)
    , m_details(details)
    , m_availableActions(availableActions)
    , m_defaultAction(Retry)
    , m_autoRecoveryTimeout(0)
    , m_remainingTime(0)
    , m_autoRecoveryTimer(new QTimer(this))
    , m_progressTimer(new QTimer(this))
    , m_detailsVisible(false)
{
    setupUI();
}

void ErrorRecoveryDialog::setAutoRecoveryTimeout(int seconds)
{
    m_autoRecoveryTimeout = seconds;
    m_remainingTime = seconds;
    
    if (seconds > 0) {
        m_autoRecoveryProgress->setVisible(true);
        m_autoRecoveryLabel->setVisible(true);
        m_autoRecoveryProgress->setMaximum(seconds);
        m_autoRecoveryProgress->setValue(seconds);
        
        connect(m_autoRecoveryTimer, &QTimer::timeout, this, &ErrorRecoveryDialog::onAutoRecoveryTimeout);
        connect(m_progressTimer, &QTimer::timeout, this, &ErrorRecoveryDialog::onAutoRecoveryProgress);
        
        m_autoRecoveryTimer->setSingleShot(true);
        m_autoRecoveryTimer->start(seconds * 1000);
        
        m_progressTimer->start(1000); // Update every second
        
        updateAutoRecoveryProgress();
    } else {
        m_autoRecoveryProgress->setVisible(false);
        m_autoRecoveryLabel->setVisible(false);
    }
}

void ErrorRecoveryDialog::setShowDetails(bool show)
{
    m_detailsVisible = show;
    m_detailsText->setVisible(show);
    
    if (show) {
        m_detailsButton->setText("Hide Details");
        resize(width(), sizeHint().height());
    } else {
        m_detailsButton->setText("Show Details");
        resize(width(), minimumSizeHint().height());
    }
}

void ErrorRecoveryDialog::attemptAutoRecovery()
{
    if (performRecoveryAction(m_defaultAction)) {
        m_result.action = m_defaultAction;
        m_result.successful = true;
        m_result.message = "Auto recovery successful";
        accept();
    } else {
        // Auto recovery failed, let user choose
        m_autoRecoveryTimer->stop();
        m_progressTimer->stop();
        m_autoRecoveryProgress->setVisible(false);
        m_autoRecoveryLabel->setText("Auto recovery failed. Please choose an action:");
    }
}

void ErrorRecoveryDialog::closeEvent(QCloseEvent *event)
{
    m_result.action = NoAction;
    m_result.successful = false;
    m_result.message = "Dialog closed without action";
    m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
    
    event->accept();
}

void ErrorRecoveryDialog::onRetryClicked()
{
    if (performRecoveryAction(Retry)) {
        m_result.action = Retry;
        m_result.successful = true;
        m_result.message = "Retry successful";
        m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
        accept();
    } else {
        QMessageBox::warning(this, "Retry Failed", "The retry operation failed. Please try another option.");
    }
}

void ErrorRecoveryDialog::onResetClicked()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Reset",
        "This will reset the current operation and may lose unsaved data. Continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        if (performRecoveryAction(Reset)) {
            m_result.action = Reset;
            m_result.successful = true;
            m_result.message = "Reset successful";
            m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
            accept();
        } else {
            QMessageBox::warning(this, "Reset Failed", "The reset operation failed.");
        }
    }
}

void ErrorRecoveryDialog::onRestartClicked()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Restart",
        "This will restart the application. Any unsaved data will be lost. Continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        m_result.action = Restart;
        m_result.successful = true;
        m_result.message = "Application restart initiated";
        m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
        accept();
        
        // Restart application
        QProcess::startDetached(QApplication::applicationFilePath(), QApplication::arguments());
        QApplication::quit();
    }
}

void ErrorRecoveryDialog::onIgnoreClicked()
{
    m_result.action = IgnoreError;
    m_result.successful = true;
    m_result.message = "Error ignored";
    m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
    accept();
}

void ErrorRecoveryDialog::onReportClicked()
{
    // Generate error report
    QString reportPath = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + 
                        "/packet_capture_error_report.txt";
    
    if (ErrorHandler::instance()->saveErrorReport(reportPath)) {
        QMessageBox::information(this, "Report Generated", 
            QString("Error report saved to:\n%1\n\nYou can send this file to support.").arg(reportPath));
    } else {
        QMessageBox::warning(this, "Report Failed", "Failed to generate error report.");
    }
    
    m_result.action = ReportAndContinue;
    m_result.successful = true;
    m_result.message = "Error reported";
    m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
    accept();
}

void ErrorRecoveryDialog::onShutdownClicked()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this, "Confirm Shutdown",
        "This will safely shut down the application. Continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        m_result.action = SafeShutdown;
        m_result.successful = true;
        m_result.message = "Safe shutdown initiated";
        m_result.preventFutureDialogs = m_preventFutureCheckBox->isChecked();
        accept();
        
        QApplication::quit();
    }
}

void ErrorRecoveryDialog::onDetailsToggled(bool show)
{
    setShowDetails(!m_detailsVisible);
}

void ErrorRecoveryDialog::onAutoRecoveryTimeout()
{
    attemptAutoRecovery();
}

void ErrorRecoveryDialog::onAutoRecoveryProgress()
{
    m_remainingTime--;
    updateAutoRecoveryProgress();
    
    if (m_remainingTime <= 0) {
        m_progressTimer->stop();
    }
}

void ErrorRecoveryDialog::setupUI()
{
    setWindowTitle(m_title);
    setModal(true);
    setMinimumWidth(400);
    
    m_result.action = NoAction;
    m_result.successful = false;
    m_result.preventFutureDialogs = false;
    
    m_mainLayout = new QVBoxLayout(this);
    
    // Header with icon and message
    QHBoxLayout *headerLayout = new QHBoxLayout;
    
    m_iconLabel = new QLabel;
    m_iconLabel->setPixmap(style()->standardIcon(QStyle::SP_MessageBoxCritical).pixmap(48, 48));
    m_iconLabel->setAlignment(Qt::AlignTop);
    headerLayout->addWidget(m_iconLabel);
    
    m_messageLabel = new QLabel(m_message);
    m_messageLabel->setWordWrap(true);
    m_messageLabel->setStyleSheet("font-weight: bold; font-size: 12px;");
    headerLayout->addWidget(m_messageLabel, 1);
    
    m_mainLayout->addLayout(headerLayout);
    
    // Auto recovery progress
    m_autoRecoveryLabel = new QLabel;
    m_autoRecoveryLabel->setVisible(false);
    m_mainLayout->addWidget(m_autoRecoveryLabel);
    
    m_autoRecoveryProgress = new QProgressBar;
    m_autoRecoveryProgress->setVisible(false);
    m_mainLayout->addWidget(m_autoRecoveryProgress);
    
    // Details text (initially hidden)
    m_detailsText = new QTextEdit;
    m_detailsText->setPlainText(m_details);
    m_detailsText->setMaximumHeight(150);
    m_detailsText->setReadOnly(true);
    m_detailsText->setVisible(false);
    m_mainLayout->addWidget(m_detailsText);
    
    // Options
    m_preventFutureCheckBox = new QCheckBox("Don't show this dialog again for similar errors");
    m_mainLayout->addWidget(m_preventFutureCheckBox);
    
    setupButtons();
}

void ErrorRecoveryDialog::setupButtons()
{
    // Action buttons
    QHBoxLayout *actionLayout = new QHBoxLayout;
    
    for (RecoveryAction action : m_availableActions) {
        QPushButton *button = nullptr;
        
        switch (action) {
            case Retry:
                m_retryButton = new QPushButton("Retry");
                m_retryButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
                connect(m_retryButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onRetryClicked);
                button = m_retryButton;
                break;
                
            case Reset:
                m_resetButton = new QPushButton("Reset");
                m_resetButton->setIcon(style()->standardIcon(QStyle::SP_DialogResetButton));
                connect(m_resetButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onResetClicked);
                button = m_resetButton;
                break;
                
            case Restart:
                m_restartButton = new QPushButton("Restart App");
                m_restartButton->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
                connect(m_restartButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onRestartClicked);
                button = m_restartButton;
                break;
                
            case IgnoreError:
                m_ignoreButton = new QPushButton("Ignore");
                m_ignoreButton->setIcon(style()->standardIcon(QStyle::SP_DialogCancelButton));
                connect(m_ignoreButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onIgnoreClicked);
                button = m_ignoreButton;
                break;
                
            case ReportAndContinue:
                m_reportButton = new QPushButton("Report && Continue");
                m_reportButton->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
                connect(m_reportButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onReportClicked);
                button = m_reportButton;
                break;
                
            case SafeShutdown:
                m_shutdownButton = new QPushButton("Safe Shutdown");
                m_shutdownButton->setIcon(style()->standardIcon(QStyle::SP_TitleBarCloseButton));
                connect(m_shutdownButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onShutdownClicked);
                button = m_shutdownButton;
                break;
                
            default:
                break;
        }
        
        if (button) {
            button->setToolTip(getActionDescription(action));
            actionLayout->addWidget(button);
            
            // Set default button
            if (action == m_defaultAction) {
                button->setDefault(true);
                button->setFocus();
            }
        }
    }
    
    m_mainLayout->addLayout(actionLayout);
    
    // Bottom buttons
    QHBoxLayout *bottomLayout = new QHBoxLayout;
    
    if (!m_details.isEmpty()) {
        m_detailsButton = new QPushButton("Show Details");
        connect(m_detailsButton, &QPushButton::clicked, this, &ErrorRecoveryDialog::onDetailsToggled);
        bottomLayout->addWidget(m_detailsButton);
    }
    
    bottomLayout->addStretch();
    
    m_cancelButton = new QPushButton("Cancel");
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    bottomLayout->addWidget(m_cancelButton);
    
    m_mainLayout->addLayout(bottomLayout);
}

void ErrorRecoveryDialog::updateAutoRecoveryProgress()
{
    if (m_autoRecoveryTimeout > 0) {
        m_autoRecoveryProgress->setValue(m_remainingTime);
        m_autoRecoveryLabel->setText(QString("Attempting automatic recovery in %1 seconds...")
                                    .arg(m_remainingTime));
    }
}

QString ErrorRecoveryDialog::getActionDescription(RecoveryAction action) const
{
    switch (action) {
        case Retry:
            return "Retry the failed operation";
        case Reset:
            return "Reset the current operation to initial state";
        case Restart:
            return "Restart the entire application";
        case IgnoreError:
            return "Ignore this error and continue";
        case ReportAndContinue:
            return "Generate error report and continue";
        case SafeShutdown:
            return "Safely shut down the application";
        default:
            return "No action";
    }
}

QIcon ErrorRecoveryDialog::getActionIcon(RecoveryAction action) const
{
    switch (action) {
        case Retry:
            return style()->standardIcon(QStyle::SP_BrowserReload);
        case Reset:
            return style()->standardIcon(QStyle::SP_DialogResetButton);
        case Restart:
            return style()->standardIcon(QStyle::SP_ComputerIcon);
        case IgnoreError:
            return style()->standardIcon(QStyle::SP_DialogCancelButton);
        case ReportAndContinue:
            return style()->standardIcon(QStyle::SP_FileDialogDetailedView);
        case SafeShutdown:
            return style()->standardIcon(QStyle::SP_TitleBarCloseButton);
        default:
            return QIcon();
    }
}

bool ErrorRecoveryDialog::performRecoveryAction(RecoveryAction action)
{
    try {
        switch (action) {
            case Retry:
                // Application-specific retry logic would go here
                // For now, we'll simulate success for demonstration
                return true;
                
            case Reset:
                // Application-specific reset logic would go here
                // This might involve resetting components to initial state
                return true;
                
            case IgnoreError:
                // Always succeeds
                return true;
                
            case ReportAndContinue:
                // Generate and save error report
                return ErrorHandler::instance()->saveErrorReport(
                    QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + 
                    "/error_report.txt");
                
            default:
                return false;
        }
    } catch (...) {
        return false;
    }
}