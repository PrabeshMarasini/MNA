#ifndef APPLICATIONMANAGER_H
#define APPLICATIONMANAGER_H

#include <QObject>
#include <QApplication>
#include <QTimer>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QDateTime>

/**
 * @brief Application lifecycle and management system
 * 
 * This class manages the complete application lifecycle including initialization,
 * shutdown, system tray integration, and application-wide coordination.
 */
class ApplicationManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Application states
     */
    enum ApplicationState {
        Initializing = 0,   ///< Application is starting up
        Running,            ///< Application is running normally
        Shutting_Down,      ///< Application is shutting down
        Error_State         ///< Application encountered a critical error
    };

    /**
     * @brief Shutdown reasons
     */
    enum ShutdownReason {
        User_Request = 0,   ///< User requested shutdown
        Critical_Error,     ///< Critical error occurred
        System_Shutdown,    ///< System is shutting down
        Memory_Pressure,    ///< Critical memory situation
        Auto_Shutdown      ///< Automatic shutdown (timeout, etc.)
    };

    /**
     * @brief Get singleton instance
     */
    static ApplicationManager* instance();

    /**
     * @brief Initialize application manager
     */
    bool initialize(QApplication *app);

    /**
     * @brief Get current application state
     */
    ApplicationState getState() const { return m_currentState; }

    /**
     * @brief Check if application is ready
     */
    bool isReady() const { return m_currentState == Running; }

    /**
     * @brief Request graceful shutdown
     */
    void requestShutdown(ShutdownReason reason = User_Request);

    /**
     * @brief Force immediate shutdown
     */
    void forceShutdown(ShutdownReason reason = Critical_Error);

    /**
     * @brief Set system tray enabled
     */
    void setSystemTrayEnabled(bool enabled);

    /**
     * @brief Check if system tray is available
     */
    bool isSystemTrayAvailable() const;

    /**
     * @brief Show application (restore from tray)
     */
    void showApplication();

    /**
     * @brief Hide application (minimize to tray)
     */
    void hideApplication();

    /**
     * @brief Get application uptime in seconds
     */
    qint64 getUptime() const;

    /**
     * @brief Get application version information
     */
    QString getVersionInfo() const;

    /**
     * @brief Get system information
     */
    QString getSystemInfo() const;

    /**
     * @brief Check for application updates
     */
    void checkForUpdates();

public slots:
    /**
     * @brief Handle application about to quit
     */
    void onAboutToQuit();

    /**
     * @brief Handle critical error
     */
    void onCriticalError(const QString &error);

    /**
     * @brief Handle memory pressure
     */
    void onMemoryPressure();

    /**
     * @brief Perform periodic maintenance
     */
    void performMaintenance();

signals:
    /**
     * @brief Emitted when application state changes
     */
    void stateChanged(ApplicationState newState, ApplicationState oldState);

    /**
     * @brief Emitted when shutdown is requested
     */
    void shutdownRequested(ShutdownReason reason);

    /**
     * @brief Emitted when application is ready
     */
    void applicationReady();

    /**
     * @brief Emitted when application is about to shutdown
     */
    void applicationShuttingDown(ShutdownReason reason);

    /**
     * @brief Emitted when maintenance is performed
     */
    void maintenancePerformed();

private slots:
    void onSystemTrayActivated(QSystemTrayIcon::ActivationReason reason);
    void onMaintenanceTimer();
    void showAboutDialog();
    void showSettingsDialog();
    void showLogsDialog();

private:
    explicit ApplicationManager(QObject *parent = nullptr);
    ~ApplicationManager();

    /**
     * @brief Initialize core systems
     */
    bool initializeCoreSystems();

    /**
     * @brief Initialize UI systems
     */
    bool initializeUI();

    /**
     * @brief Setup system tray
     */
    void setupSystemTray();

    /**
     * @brief Cleanup all systems
     */
    void cleanup();

    /**
     * @brief Set application state
     */
    void setState(ApplicationState newState);

    /**
     * @brief Create system tray menu
     */
    void createTrayMenu();

    /**
     * @brief Save application state before shutdown
     */
    void saveApplicationState();

    /**
     * @brief Restore application state
     */
    void restoreApplicationState();

    static ApplicationManager* s_instance;

    // Core components
    QApplication* m_application;
    ApplicationState m_currentState;
    ShutdownReason m_shutdownReason;
    
    // Timing
    QDateTime m_startTime;
    QTimer* m_maintenanceTimer;
    
    // System tray
    QSystemTrayIcon* m_systemTray;
    QMenu* m_trayMenu;
    bool m_systemTrayEnabled;
    
    // Shutdown handling
    bool m_shutdownRequested;
    bool m_forceShutdown;
    
    // Application info
    QString m_applicationName;
    QString m_applicationVersion;
    QString m_organizationName;
};

#endif // APPLICATIONMANAGER_H