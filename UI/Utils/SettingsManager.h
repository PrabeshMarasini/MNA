#ifndef SETTINGSMANAGER_H
#define SETTINGSMANAGER_H

#include <QObject>
#include <QSettings>
#include <QSize>
#include <QPoint>
#include <QByteArray>
#include <QStringList>
#include <QVariant>

/**
 * @brief Application settings management system
 * 
 * This class provides centralized management of application settings,
 * including window layout, user preferences, and interface configurations.
 */
class SettingsManager : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Settings categories for organization
     */
    enum SettingsCategory {
        General = 0,        ///< General application settings
        Window,             ///< Window layout and geometry
        Interface,          ///< Network interface preferences
        Capture,            ///< Packet capture settings
        Display,            ///< Display and UI preferences
        Performance,        ///< Performance-related settings
        Advanced           ///< Advanced/debug settings
    };

    /**
     * @brief Get singleton instance
     */
    static SettingsManager* instance();

    /**
     * @brief Initialize settings manager
     */
    void initialize();

    /**
     * @brief Save all settings
     */
    void saveSettings();

    /**
     * @brief Load all settings
     */
    void loadSettings();

    /**
     * @brief Reset settings to defaults
     */
    void resetToDefaults();

    /**
     * @brief Export settings to file
     */
    bool exportSettings(const QString &filePath);

    /**
     * @brief Import settings from file
     */
    bool importSettings(const QString &filePath);

    // Window settings
    void saveWindowGeometry(const QByteArray &geometry);
    QByteArray getWindowGeometry() const;
    
    void saveWindowState(const QByteArray &state);
    QByteArray getWindowState() const;
    
    void saveSplitterState(const QString &splitterName, const QByteArray &state);
    QByteArray getSplitterState(const QString &splitterName) const;

    // Interface settings
    void setLastUsedInterface(const QString &interface);
    QString getLastUsedInterface() const;
    
    void setInterfaceHistory(const QStringList &interfaces);
    QStringList getInterfaceHistory() const;
    
    void addToInterfaceHistory(const QString &interface);

    // Capture settings
    void setCaptureFilter(const QString &filter);
    QString getCaptureFilter() const;
    
    void setAutoStartCapture(bool autoStart);
    bool getAutoStartCapture() const;
    
    void setMaxPackets(int maxPackets);
    int getMaxPackets() const;
    
    void setCaptureTimeout(int timeoutSeconds);
    int getCaptureTimeout() const;

    // Display settings
    void setPacketTableColumns(const QStringList &columns);
    QStringList getPacketTableColumns() const;
    
    void setPacketTableColumnWidths(const QList<int> &widths);
    QList<int> getPacketTableColumnWidths() const;
    
    void setHexViewFont(const QString &fontFamily, int fontSize);
    QString getHexViewFontFamily() const;
    int getHexViewFontSize() const;
    
    void setProtocolTreeExpanded(bool expanded);
    bool getProtocolTreeExpanded() const;

    // Performance settings
    void setMemoryLimit(int limitMB);
    int getMemoryLimit() const;
    
    void setUpdateInterval(int intervalMs);
    int getUpdateInterval() const;
    
    void setEnableLogging(bool enabled);
    bool getEnableLogging() const;
    
    void setLogLevel(int level);
    int getLogLevel() const;

    // Advanced settings
    void setDebugMode(bool enabled);
    bool getDebugMode() const;
    
    void setDeveloperMode(bool enabled);
    bool getDeveloperMode() const;
    
    void setCustomSetting(const QString &key, const QVariant &value);
    QVariant getCustomSetting(const QString &key, const QVariant &defaultValue = QVariant()) const;

    // Recent files and sessions
    void addRecentFile(const QString &filePath);
    QStringList getRecentFiles() const;
    void clearRecentFiles();
    
    void saveSession(const QString &sessionName);
    bool loadSession(const QString &sessionName);
    QStringList getAvailableSessions() const;
    void deleteSession(const QString &sessionName);

signals:
    /**
     * @brief Emitted when settings are loaded
     */
    void settingsLoaded();

    /**
     * @brief Emitted when settings are saved
     */
    void settingsSaved();

    /**
     * @brief Emitted when a setting changes
     */
    void settingChanged(const QString &key, const QVariant &value);

    /**
     * @brief Emitted when settings are reset
     */
    void settingsReset();

private:
    explicit SettingsManager(QObject *parent = nullptr);
    ~SettingsManager();

    /**
     * @brief Set default values for all settings
     */
    void setDefaults();

    /**
     * @brief Get settings key with category prefix
     */
    QString getCategoryKey(SettingsCategory category, const QString &key) const;

    /**
     * @brief Get category name string
     */
    QString getCategoryName(SettingsCategory category) const;

    static SettingsManager* s_instance;
    QSettings* m_settings;
    
    // Default values
    struct DefaultValues {
        // Window defaults
        QSize defaultWindowSize;
        QPoint defaultWindowPosition;
        
        // Interface defaults
        QString defaultInterface;
        int maxInterfaceHistory;
        
        // Capture defaults
        QString defaultFilter;
        bool defaultAutoStart;
        int defaultMaxPackets;
        int defaultCaptureTimeout;
        
        // Display defaults
        QStringList defaultColumns;
        QString defaultFontFamily;
        int defaultFontSize;
        bool defaultTreeExpanded;
        
        // Performance defaults
        int defaultMemoryLimit;
        int defaultUpdateInterval;
        bool defaultLoggingEnabled;
        int defaultLogLevel;
        
        // Advanced defaults
        bool defaultDebugMode;
        bool defaultDeveloperMode;
        
        // Recent files
        int maxRecentFiles;
    } m_defaults;
};

#endif // SETTINGSMANAGER_H