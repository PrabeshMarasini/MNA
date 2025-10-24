#include "ApplicationManager.h"
#include "SettingsManager.h"
#include "ErrorHandler.h"
#include "MemoryManager.h"
#include "LoggingDialog.h"
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QDialog>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QSysInfo>
#include <QStandardPaths>
#include <QDir>
#include <QProcess>
#include <QDesktopServices>
#include <QUrl>

ApplicationManager* ApplicationManager::s_instance = nullptr;

ApplicationManager::ApplicationManager(QObject *parent)
    : QObject(parent)
    , m_application(nullptr)
    , m_currentState(Initializing)
    , m_shutdownReason(User_Request)
    , m_startTime(QDateTime::currentDateTime())
    , m_maintenanceTimer(new QTimer(this))
    , m_systemTray(nullptr)
    , m_trayMenu(nullptr)
    , m_systemTrayEnabled(false)
    , m_shutdownRequested(false)
    , m_forceShutdown(false)
    , m_applicationName("Packet Capture GUI")
    , m_applicationVersion("1.0.0")
    , m_organizationName("PacketCapture")
{
    // Setup maintenance timer (every 5 minutes)
    m_maintenanceTimer->setInterval(300000);
    connect(m_maintenanceTimer, &QTimer::timeout, this, &ApplicationManager::onMaintenanceTimer);
}

ApplicationManager::~ApplicationManager()
{
    cleanup();
}

ApplicationManager* ApplicationManager::instance()
{
    if (!s_instance) {
        s_instance = new ApplicationManager();
    }
    return s_instance;
}

bool ApplicationManager::initialize(QApplication *app)
{
    if (!app) {
        LOG_CRITICAL("ApplicationManager: Null application pointer provided");
        return false;
    }
    
    m_application = app;
    
    try {
        LOG_INFO("ApplicationManager: Starting application initialization");
        
        // Set application properties
        m_application->setApplicationName(m_applicationName);
        m_application->setApplicationVersion(m_applicationVersion);
        m_application->setOrganizationName(m_organizationName);
        m_application->setOrganizationDomain("packetcapture.org");
        
        // Connect application signals
        connect(m_application, &QApplication::aboutToQuit, this, &ApplicationManager::onAboutToQuit);
        
        // Initialize core systems
        if (!initializeCoreSystems()) {
            LOG_CRITICAL("ApplicationManager: Failed to initialize core systems");
            setState(Error_State);
            return false;
        }
        
        // Initialize UI systems
        if (!initializeUI()) {
            LOG_CRITICAL("ApplicationManager: Failed to initialize UI systems");
            setState(Error_State);
            return false;
        }
        
        // Setup system tray if available
        if (QSystemTrayIcon::isSystemTrayAvailable()) {
            setupSystemTray();
        }
        
        // Restore application state
        restoreApplicationState();
        
        // Start maintenance timer
        m_maintenanceTimer->start();
        
        setState(Running);
        
        LOG_INFO("ApplicationManager: Application initialization completed successfully");
        emit applicationReady();
        
        return true;
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("ApplicationManager: Exception during initialization: %1").arg(e.what()));
        setState(Error_State);
        return false;
    } catch (...) {
        LOG_CRITICAL("ApplicationManager: Unknown exception during initialization");
        setState(Error_State);
        return false;
    }
}

void ApplicationManager::requestShutdown(ShutdownReason reason)
{
    if (m_shutdownRequested) {
        LOG_WARNING("ApplicationManager: Shutdown already requested");
        return;
    }
    
    m_shutdownRequested = true;
    m_shutdownReason = reason;
    
    LOG_INFO(QString("ApplicationManager: Shutdown requested, reason: %1").arg(static_cast<int>(reason)));
    
    setState(Shutting_Down);
    emit shutdownRequested(reason);
    
    // Save application state
    saveApplicationState();
    
    // Perform graceful shutdown
    QTimer::singleShot(100, [this]() {
        if (m_application) {
            m_application->quit();
        }
    });
}

void ApplicationManager::forceShutdown(ShutdownReason reason)
{
    m_forceShutdown = true;
    m_shutdownReason = reason;
    
    LOG_CRITICAL(QString("ApplicationManager: Force shutdown requested, reason: %1").arg(static_cast<int>(reason)));
    
    setState(Shutting_Down);
    emit applicationShuttingDown(reason);
    
    // Immediate shutdown
    if (m_application) {
        m_application->exit(1);
    }
}

void ApplicationManager::setSystemTrayEnabled(bool enabled)
{
    if (m_systemTrayEnabled == enabled) return;
    
    m_systemTrayEnabled = enabled;
    
    if (enabled && QSystemTrayIcon::isSystemTrayAvailable()) {
        setupSystemTray();
    } else if (m_systemTray) {
        m_systemTray->hide();
        delete m_systemTray;
        m_systemTray = nullptr;
        delete m_trayMenu;
        m_trayMenu = nullptr;
    }
    
    // Save setting
    SettingsManager::instance()->setCustomSetting("system_tray_enabled", enabled);
}

bool ApplicationManager::isSystemTrayAvailable() const
{
    return QSystemTrayIcon::isSystemTrayAvailable();
}

void ApplicationManager::showApplication()
{
    // This would be implemented to show the main window
    // For now, we'll emit a signal that the main window can connect to
    LOG_INFO("ApplicationManager: Show application requested");
}

void ApplicationManager::hideApplication()
{
    // This would be implemented to hide the main window to system tray
    LOG_INFO("ApplicationManager: Hide application requested");
}

qint64 ApplicationManager::getUptime() const
{
    return m_startTime.secsTo(QDateTime::currentDateTime());
}

QString ApplicationManager::getVersionInfo() const
{
    return QString("%1 v%2").arg(m_applicationName).arg(m_applicationVersion);
}

QString ApplicationManager::getSystemInfo() const
{
    QString info;
    info += QString("Application: %1\n").arg(getVersionInfo());
    info += QString("Qt Version: %1\n").arg(qVersion());
    info += QString("System: %1\n").arg(QSysInfo::prettyProductName());
    info += QString("Architecture: %1\n").arg(QSysInfo::currentCpuArchitecture());
    info += QString("Kernel: %1 %2\n").arg(QSysInfo::kernelType()).arg(QSysInfo::kernelVersion());
    info += QString("Uptime: %1 seconds\n").arg(getUptime());
    
    return info;
}

void ApplicationManager::checkForUpdates()
{
    // Placeholder for update checking functionality
    LOG_INFO("ApplicationManager: Checking for updates...");
    
    // In a real implementation, this would check for updates from a server
    QMessageBox::information(nullptr, "Update Check", 
        "Update checking is not implemented in this version.");
}

void ApplicationManager::onAboutToQuit()
{
    LOG_INFO("ApplicationManager: Application about to quit");
    
    if (!m_shutdownRequested) {
        m_shutdownRequested = true;
        m_shutdownReason = User_Request;
    }
    
    setState(Shutting_Down);
    emit applicationShuttingDown(m_shutdownReason);
    
    // Save application state
    saveApplicationState();
    
    // Cleanup
    cleanup();
}

void ApplicationManager::onCriticalError(const QString &error)
{
    LOG_CRITICAL("ApplicationManager: Critical error received: " + error);
    
    setState(Error_State);
    
    // Show critical error dialog
    QMessageBox::critical(nullptr, "Critical Error", 
        QString("A critical error has occurred:\n\n%1\n\nThe application will now shut down.").arg(error));
    
    forceShutdown(Critical_Error);
}

void ApplicationManager::onMemoryPressure()
{
    LOG_WARNING("ApplicationManager: Memory pressure detected");
    
    // Perform emergency cleanup
    performMaintenance();
    
    // If memory pressure is still critical, consider shutdown
    if (MemoryManager::instance()->getMemoryPressure() >= MemoryManager::Critical) {
        QMessageBox::StandardButton reply = QMessageBox::question(nullptr,
            "Critical Memory Situation",
            "Critical memory situation detected. The application may become unstable.\n\n"
            "Do you want to shut down the application safely?",
            QMessageBox::Yes | QMessageBox::No);
        
        if (reply == QMessageBox::Yes) {
            requestShutdown(Memory_Pressure);
        }
    }
}

void ApplicationManager::performMaintenance()
{
    LOG_INFO("ApplicationManager: Performing maintenance");
    
    try {
        // Trigger memory cleanup
        MemoryManager::instance()->performCleanup();
        
        // Save settings
        SettingsManager::instance()->saveSettings();
        
        // Process pending events
        if (m_application) {
            m_application->processEvents();
        }
        
        emit maintenancePerformed();
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("ApplicationManager: Exception during maintenance: %1").arg(e.what()));
    }
}

void ApplicationManager::onSystemTrayActivated(QSystemTrayIcon::ActivationReason reason)
{
    switch (reason) {
        case QSystemTrayIcon::Trigger:
        case QSystemTrayIcon::DoubleClick:
            showApplication();
            break;
        default:
            break;
    }
}

void ApplicationManager::onMaintenanceTimer()
{
    performMaintenance();
}

void ApplicationManager::showAboutDialog()
{
    QDialog aboutDialog;
    aboutDialog.setWindowTitle("About " + m_applicationName);
    aboutDialog.setFixedSize(400, 300);
    
    QVBoxLayout *layout = new QVBoxLayout(&aboutDialog);
    
    QLabel *titleLabel = new QLabel(getVersionInfo());
    titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; margin: 10px;");
    titleLabel->setAlignment(Qt::AlignCenter);
    layout->addWidget(titleLabel);
    
    QTextEdit *infoText = new QTextEdit;
    infoText->setReadOnly(true);
    infoText->setPlainText(
        "Packet Capture GUI\n\n"
        "A comprehensive network packet capture and analysis tool.\n\n"
        "Features:\n"
        "• Real-time packet capture\n"
        "• Protocol analysis\n"
        "• Hexadecimal packet view\n"
        "• Comprehensive error handling\n"
        "• Performance monitoring\n\n"
        + getSystemInfo()
    );
    layout->addWidget(infoText);
    
    QPushButton *closeButton = new QPushButton("Close");
    connect(closeButton, &QPushButton::clicked, &aboutDialog, &QDialog::accept);
    layout->addWidget(closeButton);
    
    aboutDialog.exec();
}

void ApplicationManager::showSettingsDialog()
{
    // Placeholder for settings dialog
    QMessageBox::information(nullptr, "Settings", 
        "Settings dialog is not implemented yet.");
}

void ApplicationManager::showLogsDialog()
{
    LoggingDialog *logsDialog = new LoggingDialog();
    logsDialog->setAttribute(Qt::WA_DeleteOnClose);
    logsDialog->show();
}

bool ApplicationManager::initializeCoreSystems()
{
    try {
        // Initialize error handler
        ErrorHandler::instance()->initialize();
        connect(ErrorHandler::instance(), &ErrorHandler::criticalErrorOccurred,
                this, &ApplicationManager::onCriticalError);
        
        // Initialize memory manager
        MemoryManager::instance()->initialize();
        connect(MemoryManager::instance(), &MemoryManager::criticalMemoryWarning,
                this, &ApplicationManager::onMemoryPressure);
        
        // Initialize settings manager
        SettingsManager::instance()->initialize();
        
        LOG_INFO("ApplicationManager: Core systems initialized successfully");
        return true;
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("ApplicationManager: Exception initializing core systems: %1").arg(e.what()));
        return false;
    }
}

bool ApplicationManager::initializeUI()
{
    try {
        // Set application icon
        // m_application->setWindowIcon(QIcon(":/icons/app_icon.png"));
        
        // Set application style
        m_application->setStyle("Fusion");
        
        LOG_INFO("ApplicationManager: UI systems initialized successfully");
        return true;
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("ApplicationManager: Exception initializing UI systems: %1").arg(e.what()));
        return false;
    }
}

void ApplicationManager::setupSystemTray()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        LOG_WARNING("ApplicationManager: System tray is not available");
        return;
    }
    
    if (m_systemTray) {
        delete m_systemTray;
        delete m_trayMenu;
    }
    
    m_systemTray = new QSystemTrayIcon(this);
    // m_systemTray->setIcon(QIcon(":/icons/tray_icon.png"));
    m_systemTray->setToolTip(m_applicationName);
    
    connect(m_systemTray, &QSystemTrayIcon::activated,
            this, &ApplicationManager::onSystemTrayActivated);
    
    createTrayMenu();
    
    m_systemTray->show();
    m_systemTrayEnabled = true;
    
    LOG_INFO("ApplicationManager: System tray initialized");
}

void ApplicationManager::cleanup()
{
    LOG_INFO("ApplicationManager: Starting cleanup");
    
    try {
        // Stop maintenance timer
        if (m_maintenanceTimer) {
            m_maintenanceTimer->stop();
        }
        
        // Hide system tray
        if (m_systemTray) {
            m_systemTray->hide();
        }
        
        // Save final settings
        if (SettingsManager::instance()) {
            SettingsManager::instance()->saveSettings();
        }
        
        LOG_INFO("ApplicationManager: Cleanup completed");
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("ApplicationManager: Exception during cleanup: %1").arg(e.what()));
    }
}

void ApplicationManager::setState(ApplicationState newState)
{
    if (m_currentState == newState) return;
    
    ApplicationState oldState = m_currentState;
    m_currentState = newState;
    
    LOG_INFO(QString("ApplicationManager: State changed from %1 to %2")
             .arg(static_cast<int>(oldState))
             .arg(static_cast<int>(newState)));
    
    emit stateChanged(newState, oldState);
}

void ApplicationManager::createTrayMenu()
{
    if (!m_systemTray) return;
    
    m_trayMenu = new QMenu();
    
    QAction *showAction = m_trayMenu->addAction("Show");
    connect(showAction, &QAction::triggered, this, &ApplicationManager::showApplication);
    
    QAction *hideAction = m_trayMenu->addAction("Hide");
    connect(hideAction, &QAction::triggered, this, &ApplicationManager::hideApplication);
    
    m_trayMenu->addSeparator();
    
    QAction *settingsAction = m_trayMenu->addAction("Settings");
    connect(settingsAction, &QAction::triggered, this, &ApplicationManager::showSettingsDialog);
    
    QAction *logsAction = m_trayMenu->addAction("View Logs");
    connect(logsAction, &QAction::triggered, this, &ApplicationManager::showLogsDialog);
    
    QAction *aboutAction = m_trayMenu->addAction("About");
    connect(aboutAction, &QAction::triggered, this, &ApplicationManager::showAboutDialog);
    
    m_trayMenu->addSeparator();
    
    QAction *quitAction = m_trayMenu->addAction("Quit");
    connect(quitAction, &QAction::triggered, [this]() {
        requestShutdown(User_Request);
    });
    
    m_systemTray->setContextMenu(m_trayMenu);
}

void ApplicationManager::saveApplicationState()
{
    try {
        LOG_INFO("ApplicationManager: Saving application state");
        
        // Save uptime
        SettingsManager::instance()->setCustomSetting("last_uptime", getUptime());
        
        // Save shutdown reason
        SettingsManager::instance()->setCustomSetting("last_shutdown_reason", static_cast<int>(m_shutdownReason));
        
        // Save timestamp
        SettingsManager::instance()->setCustomSetting("last_shutdown_time", QDateTime::currentDateTime());
        
        // Force save
        SettingsManager::instance()->saveSettings();
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("ApplicationManager: Exception saving application state: %1").arg(e.what()));
    }
}

void ApplicationManager::restoreApplicationState()
{
    try {
        LOG_INFO("ApplicationManager: Restoring application state");
        
        // Check if this is a recovery from crash
        QVariant lastShutdownReason = SettingsManager::instance()->getCustomSetting("last_shutdown_reason");
        if (lastShutdownReason.isValid()) {
            int reason = lastShutdownReason.toInt();
            if (reason == Critical_Error) {
                LOG_WARNING("ApplicationManager: Previous session ended with critical error");
                
                QMessageBox::information(nullptr, "Recovery", 
                    "The application was recovered from an unexpected shutdown.\n"
                    "Settings have been restored to the last known good state.");
            }
        }
        
        // Restore system tray setting
        bool systemTrayEnabled = SettingsManager::instance()->getCustomSetting("system_tray_enabled", false).toBool();
        setSystemTrayEnabled(systemTrayEnabled);
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("ApplicationManager: Exception restoring application state: %1").arg(e.what()));
    }
}