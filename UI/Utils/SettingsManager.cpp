#include "SettingsManager.h"
#include "ErrorHandler.h"
#include <QApplication>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QDebug>

SettingsManager* SettingsManager::s_instance = nullptr;

SettingsManager::SettingsManager(QObject *parent)
    : QObject(parent)
    , m_settings(nullptr)
{
    // Initialize settings with application-specific location
    QString settingsPath = QStandardPaths::writableLocation(QStandardPaths::AppConfigLocation);
    QDir().mkpath(settingsPath);
    
    m_settings = new QSettings(settingsPath + "/packet_capture_gui.ini", QSettings::IniFormat, this);
    
    setDefaults();
    
    LOG_INFO("SettingsManager: Initialized with settings file: " + m_settings->fileName());
}

SettingsManager::~SettingsManager()
{
    if (m_settings) {
        saveSettings();
    }
}

SettingsManager* SettingsManager::instance()
{
    if (!s_instance) {
        s_instance = new SettingsManager();
    }
    return s_instance;
}

void SettingsManager::initialize()
{
    loadSettings();
    LOG_INFO("SettingsManager: Initialized and settings loaded");
}

void SettingsManager::saveSettings()
{
    if (!m_settings) return;
    
    try {
        m_settings->sync();
        
        if (m_settings->status() == QSettings::NoError) {
            LOG_INFO("Settings saved successfully");
            emit settingsSaved();
        } else {
            LOG_ERROR("Failed to save settings: " + QString::number(m_settings->status()));
        }
    } catch (const std::exception &e) {
        LOG_ERROR(QString("Exception while saving settings: %1").arg(e.what()));
    }
}

void SettingsManager::loadSettings()
{
    if (!m_settings) return;
    
    try {
        // Settings are automatically loaded when accessed
        LOG_INFO("Settings loaded successfully");
        emit settingsLoaded();
    } catch (const std::exception &e) {
        LOG_ERROR(QString("Exception while loading settings: %1").arg(e.what()));
    }
}

void SettingsManager::resetToDefaults()
{
    if (!m_settings) return;
    
    try {
        m_settings->clear();
        setDefaults();
        saveSettings();
        
        LOG_INFO("Settings reset to defaults");
        emit settingsReset();
    } catch (const std::exception &e) {
        LOG_ERROR(QString("Exception while resetting settings: %1").arg(e.what()));
    }
}

bool SettingsManager::exportSettings(const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::WriteOnly)) {
            LOG_ERROR("Failed to open export file: " + filePath);
            return false;
        }
        
        // Create JSON object with all settings
        QJsonObject json;
        
        // Export all settings groups
        QStringList groups = m_settings->childGroups();
        for (const QString &group : groups) {
            m_settings->beginGroup(group);
            
            QJsonObject groupObj;
            QStringList keys = m_settings->childKeys();
            for (const QString &key : keys) {
                groupObj[key] = QJsonValue::fromVariant(m_settings->value(key));
            }
            json[group] = groupObj;
            
            m_settings->endGroup();
        }
        
        // Export root level settings
        QStringList rootKeys = m_settings->childKeys();
        for (const QString &key : rootKeys) {
            json[key] = QJsonValue::fromVariant(m_settings->value(key));
        }
        
        QJsonDocument doc(json);
        file.write(doc.toJson());
        
        LOG_INFO("Settings exported to: " + filePath);
        return true;
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("Exception while exporting settings: %1").arg(e.what()));
        return false;
    }
}

bool SettingsManager::importSettings(const QString &filePath)
{
    try {
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            LOG_ERROR("Failed to open import file: " + filePath);
            return false;
        }
        
        QByteArray data = file.readAll();
        QJsonParseError error;
        QJsonDocument doc = QJsonDocument::fromJson(data, &error);
        
        if (error.error != QJsonParseError::NoError) {
            LOG_ERROR("JSON parse error: " + error.errorString());
            return false;
        }
        
        QJsonObject json = doc.object();
        
        // Clear existing settings
        m_settings->clear();
        
        // Import settings
        for (auto it = json.begin(); it != json.end(); ++it) {
            if (it.value().isObject()) {
                // Group settings
                QJsonObject groupObj = it.value().toObject();
                m_settings->beginGroup(it.key());
                
                for (auto groupIt = groupObj.begin(); groupIt != groupObj.end(); ++groupIt) {
                    m_settings->setValue(groupIt.key(), groupIt.value().toVariant());
                }
                
                m_settings->endGroup();
            } else {
                // Root level setting
                m_settings->setValue(it.key(), it.value().toVariant());
            }
        }
        
        saveSettings();
        
        LOG_INFO("Settings imported from: " + filePath);
        return true;
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("Exception while importing settings: %1").arg(e.what()));
        return false;
    }
}

// Window settings
void SettingsManager::saveWindowGeometry(const QByteArray &geometry)
{
    m_settings->setValue(getCategoryKey(Window, "geometry"), geometry);
    emit settingChanged("window/geometry", geometry);
}

QByteArray SettingsManager::getWindowGeometry() const
{
    return m_settings->value(getCategoryKey(Window, "geometry")).toByteArray();
}

void SettingsManager::saveWindowState(const QByteArray &state)
{
    m_settings->setValue(getCategoryKey(Window, "state"), state);
    emit settingChanged("window/state", state);
}

QByteArray SettingsManager::getWindowState() const
{
    return m_settings->value(getCategoryKey(Window, "state")).toByteArray();
}

void SettingsManager::saveSplitterState(const QString &splitterName, const QByteArray &state)
{
    m_settings->setValue(getCategoryKey(Window, "splitter_" + splitterName), state);
    emit settingChanged("window/splitter_" + splitterName, state);
}

QByteArray SettingsManager::getSplitterState(const QString &splitterName) const
{
    return m_settings->value(getCategoryKey(Window, "splitter_" + splitterName)).toByteArray();
}

// Interface settings
void SettingsManager::setLastUsedInterface(const QString &interface)
{
    m_settings->setValue(getCategoryKey(Interface, "last_used"), interface);
    emit settingChanged("interface/last_used", interface);
}

QString SettingsManager::getLastUsedInterface() const
{
    return m_settings->value(getCategoryKey(Interface, "last_used"), m_defaults.defaultInterface).toString();
}

void SettingsManager::setInterfaceHistory(const QStringList &interfaces)
{
    m_settings->setValue(getCategoryKey(Interface, "history"), interfaces);
    emit settingChanged("interface/history", interfaces);
}

QStringList SettingsManager::getInterfaceHistory() const
{
    return m_settings->value(getCategoryKey(Interface, "history")).toStringList();
}

void SettingsManager::addToInterfaceHistory(const QString &interface)
{
    QStringList history = getInterfaceHistory();
    
    // Remove if already exists
    history.removeAll(interface);
    
    // Add to front
    history.prepend(interface);
    
    // Limit size
    while (history.size() > m_defaults.maxInterfaceHistory) {
        history.removeLast();
    }
    
    setInterfaceHistory(history);
}

// Capture settings
void SettingsManager::setCaptureFilter(const QString &filter)
{
    m_settings->setValue(getCategoryKey(Capture, "filter"), filter);
    emit settingChanged("capture/filter", filter);
}

QString SettingsManager::getCaptureFilter() const
{
    return m_settings->value(getCategoryKey(Capture, "filter"), m_defaults.defaultFilter).toString();
}

void SettingsManager::setAutoStartCapture(bool autoStart)
{
    m_settings->setValue(getCategoryKey(Capture, "auto_start"), autoStart);
    emit settingChanged("capture/auto_start", autoStart);
}

bool SettingsManager::getAutoStartCapture() const
{
    return m_settings->value(getCategoryKey(Capture, "auto_start"), m_defaults.defaultAutoStart).toBool();
}

void SettingsManager::setMaxPackets(int maxPackets)
{
    m_settings->setValue(getCategoryKey(Capture, "max_packets"), maxPackets);
    emit settingChanged("capture/max_packets", maxPackets);
}

int SettingsManager::getMaxPackets() const
{
    return m_settings->value(getCategoryKey(Capture, "max_packets"), m_defaults.defaultMaxPackets).toInt();
}

void SettingsManager::setCaptureTimeout(int timeoutSeconds)
{
    m_settings->setValue(getCategoryKey(Capture, "timeout"), timeoutSeconds);
    emit settingChanged("capture/timeout", timeoutSeconds);
}

int SettingsManager::getCaptureTimeout() const
{
    return m_settings->value(getCategoryKey(Capture, "timeout"), m_defaults.defaultCaptureTimeout).toInt();
}

// Display settings
void SettingsManager::setPacketTableColumns(const QStringList &columns)
{
    m_settings->setValue(getCategoryKey(Display, "table_columns"), columns);
    emit settingChanged("display/table_columns", columns);
}

QStringList SettingsManager::getPacketTableColumns() const
{
    return m_settings->value(getCategoryKey(Display, "table_columns"), m_defaults.defaultColumns).toStringList();
}

void SettingsManager::setPacketTableColumnWidths(const QList<int> &widths)
{
    QVariantList variantWidths;
    for (int width : widths) {
        variantWidths.append(width);
    }
    m_settings->setValue(getCategoryKey(Display, "column_widths"), variantWidths);
    emit settingChanged("display/column_widths", variantWidths);
}

QList<int> SettingsManager::getPacketTableColumnWidths() const
{
    QVariantList variantWidths = m_settings->value(getCategoryKey(Display, "column_widths")).toList();
    QList<int> widths;
    for (const QVariant &variant : variantWidths) {
        widths.append(variant.toInt());
    }
    return widths;
}

void SettingsManager::setHexViewFont(const QString &fontFamily, int fontSize)
{
    m_settings->setValue(getCategoryKey(Display, "hex_font_family"), fontFamily);
    m_settings->setValue(getCategoryKey(Display, "hex_font_size"), fontSize);
    emit settingChanged("display/hex_font_family", fontFamily);
    emit settingChanged("display/hex_font_size", fontSize);
}

QString SettingsManager::getHexViewFontFamily() const
{
    return m_settings->value(getCategoryKey(Display, "hex_font_family"), m_defaults.defaultFontFamily).toString();
}

int SettingsManager::getHexViewFontSize() const
{
    return m_settings->value(getCategoryKey(Display, "hex_font_size"), m_defaults.defaultFontSize).toInt();
}

void SettingsManager::setProtocolTreeExpanded(bool expanded)
{
    m_settings->setValue(getCategoryKey(Display, "tree_expanded"), expanded);
    emit settingChanged("display/tree_expanded", expanded);
}

bool SettingsManager::getProtocolTreeExpanded() const
{
    return m_settings->value(getCategoryKey(Display, "tree_expanded"), m_defaults.defaultTreeExpanded).toBool();
}

// Performance settings
void SettingsManager::setMemoryLimit(int limitMB)
{
    m_settings->setValue(getCategoryKey(Performance, "memory_limit"), limitMB);
    emit settingChanged("performance/memory_limit", limitMB);
}

int SettingsManager::getMemoryLimit() const
{
    return m_settings->value(getCategoryKey(Performance, "memory_limit"), m_defaults.defaultMemoryLimit).toInt();
}

void SettingsManager::setUpdateInterval(int intervalMs)
{
    m_settings->setValue(getCategoryKey(Performance, "update_interval"), intervalMs);
    emit settingChanged("performance/update_interval", intervalMs);
}

int SettingsManager::getUpdateInterval() const
{
    return m_settings->value(getCategoryKey(Performance, "update_interval"), m_defaults.defaultUpdateInterval).toInt();
}

void SettingsManager::setEnableLogging(bool enabled)
{
    m_settings->setValue(getCategoryKey(Performance, "logging_enabled"), enabled);
    emit settingChanged("performance/logging_enabled", enabled);
}

bool SettingsManager::getEnableLogging() const
{
    return m_settings->value(getCategoryKey(Performance, "logging_enabled"), m_defaults.defaultLoggingEnabled).toBool();
}

void SettingsManager::setLogLevel(int level)
{
    m_settings->setValue(getCategoryKey(Performance, "log_level"), level);
    emit settingChanged("performance/log_level", level);
}

int SettingsManager::getLogLevel() const
{
    return m_settings->value(getCategoryKey(Performance, "log_level"), m_defaults.defaultLogLevel).toInt();
}

// Advanced settings
void SettingsManager::setDebugMode(bool enabled)
{
    m_settings->setValue(getCategoryKey(Advanced, "debug_mode"), enabled);
    emit settingChanged("advanced/debug_mode", enabled);
}

bool SettingsManager::getDebugMode() const
{
    return m_settings->value(getCategoryKey(Advanced, "debug_mode"), m_defaults.defaultDebugMode).toBool();
}

void SettingsManager::setDeveloperMode(bool enabled)
{
    m_settings->setValue(getCategoryKey(Advanced, "developer_mode"), enabled);
    emit settingChanged("advanced/developer_mode", enabled);
}

bool SettingsManager::getDeveloperMode() const
{
    return m_settings->value(getCategoryKey(Advanced, "developer_mode"), m_defaults.defaultDeveloperMode).toBool();
}

void SettingsManager::setCustomSetting(const QString &key, const QVariant &value)
{
    m_settings->setValue(getCategoryKey(Advanced, "custom_" + key), value);
    emit settingChanged("advanced/custom_" + key, value);
}

QVariant SettingsManager::getCustomSetting(const QString &key, const QVariant &defaultValue) const
{
    return m_settings->value(getCategoryKey(Advanced, "custom_" + key), defaultValue);
}

// Recent files and sessions
void SettingsManager::addRecentFile(const QString &filePath)
{
    QStringList recentFiles = getRecentFiles();
    
    // Remove if already exists
    recentFiles.removeAll(filePath);
    
    // Add to front
    recentFiles.prepend(filePath);
    
    // Limit size
    while (recentFiles.size() > m_defaults.maxRecentFiles) {
        recentFiles.removeLast();
    }
    
    m_settings->setValue(getCategoryKey(General, "recent_files"), recentFiles);
    emit settingChanged("general/recent_files", recentFiles);
}

QStringList SettingsManager::getRecentFiles() const
{
    return m_settings->value(getCategoryKey(General, "recent_files")).toStringList();
}

void SettingsManager::clearRecentFiles()
{
    m_settings->setValue(getCategoryKey(General, "recent_files"), QStringList());
    emit settingChanged("general/recent_files", QStringList());
}

void SettingsManager::saveSession(const QString &sessionName)
{
    m_settings->beginGroup("sessions");
    m_settings->beginGroup(sessionName);
    
    // Save current window state
    m_settings->setValue("window_geometry", getWindowGeometry());
    m_settings->setValue("window_state", getWindowState());
    m_settings->setValue("last_interface", getLastUsedInterface());
    m_settings->setValue("capture_filter", getCaptureFilter());
    
    m_settings->endGroup();
    m_settings->endGroup();
    
    LOG_INFO("Session saved: " + sessionName);
}

bool SettingsManager::loadSession(const QString &sessionName)
{
    m_settings->beginGroup("sessions");
    
    if (!m_settings->childGroups().contains(sessionName)) {
        m_settings->endGroup();
        LOG_WARNING("Session not found: " + sessionName);
        return false;
    }
    
    m_settings->beginGroup(sessionName);
    
    // Load session settings
    QByteArray geometry = m_settings->value("window_geometry").toByteArray();
    QByteArray state = m_settings->value("window_state").toByteArray();
    QString interface = m_settings->value("last_interface").toString();
    QString filter = m_settings->value("capture_filter").toString();
    
    m_settings->endGroup();
    m_settings->endGroup();
    
    // Apply session settings
    if (!geometry.isEmpty()) saveWindowGeometry(geometry);
    if (!state.isEmpty()) saveWindowState(state);
    if (!interface.isEmpty()) setLastUsedInterface(interface);
    if (!filter.isEmpty()) setCaptureFilter(filter);
    
    LOG_INFO("Session loaded: " + sessionName);
    return true;
}

QStringList SettingsManager::getAvailableSessions() const
{
    m_settings->beginGroup("sessions");
    QStringList sessions = m_settings->childGroups();
    m_settings->endGroup();
    return sessions;
}

void SettingsManager::deleteSession(const QString &sessionName)
{
    m_settings->beginGroup("sessions");
    m_settings->remove(sessionName);
    m_settings->endGroup();
    
    LOG_INFO("Session deleted: " + sessionName);
}

void SettingsManager::setDefaults()
{
    // Window defaults
    m_defaults.defaultWindowSize = QSize(1200, 800);
    m_defaults.defaultWindowPosition = QPoint(100, 100);
    
    // Interface defaults
    m_defaults.defaultInterface = "";
    m_defaults.maxInterfaceHistory = 10;
    
    // Capture defaults
    m_defaults.defaultFilter = "";
    m_defaults.defaultAutoStart = false;
    m_defaults.defaultMaxPackets = 10000;
    m_defaults.defaultCaptureTimeout = 0; // No timeout
    
    // Display defaults
    m_defaults.defaultColumns = QStringList() << "No." << "Time" << "Source" << "Destination" << "Protocol" << "Length" << "Info";
    m_defaults.defaultFontFamily = "Courier";
    m_defaults.defaultFontSize = 9;
    m_defaults.defaultTreeExpanded = true;
    
    // Performance defaults
    m_defaults.defaultMemoryLimit = 512; // 512 MB
    m_defaults.defaultUpdateInterval = 100; // 100 ms
    m_defaults.defaultLoggingEnabled = true;
    m_defaults.defaultLogLevel = 1; // Info level
    
    // Advanced defaults
    m_defaults.defaultDebugMode = false;
    m_defaults.defaultDeveloperMode = false;
    
    // Recent files
    m_defaults.maxRecentFiles = 10;
}

QString SettingsManager::getCategoryKey(SettingsCategory category, const QString &key) const
{
    return getCategoryName(category) + "/" + key;
}

QString SettingsManager::getCategoryName(SettingsCategory category) const
{
    switch (category) {
        case General: return "general";
        case Window: return "window";
        case Interface: return "interface";
        case Capture: return "capture";
        case Display: return "display";
        case Performance: return "performance";
        case Advanced: return "advanced";
        default: return "general";
    }
}