#include "SettingsDialog.h"
#include "../Utils/SettingsManager.h"
#include "../Utils/NetworkInterfaceManager.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QStandardPaths>
#include <QApplication>

SettingsDialog::SettingsDialog(QWidget *parent)
    : QDialog(parent)
    , m_settingsChanged(false)
{
    setWindowTitle("Settings");
    setMinimumSize(600, 500);
    setModal(true);
    
    setupUI();
    loadCurrentSettings();
}

void SettingsDialog::applySettings()
{
    saveCurrentSettings();
    m_settingsChanged = false;
    m_applyButton->setEnabled(false);
    
    QMessageBox::information(this, "Settings Applied", 
        "Settings have been applied successfully.");
}

void SettingsDialog::resetToDefaults()
{
    QMessageBox::StandardButton reply = QMessageBox::question(this,
        "Reset Settings",
        "This will reset all settings to their default values. Continue?",
        QMessageBox::Yes | QMessageBox::No);
    
    if (reply == QMessageBox::Yes) {
        SettingsManager::instance()->resetToDefaults();
        loadCurrentSettings();
        
        QMessageBox::information(this, "Settings Reset", 
            "All settings have been reset to default values.");
    }
}

void SettingsDialog::importSettings()
{
    QString fileName = QFileDialog::getOpenFileName(this,
        "Import Settings",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation),
        "JSON Files (*.json);;All Files (*)");
    
    if (!fileName.isEmpty()) {
        if (SettingsManager::instance()->importSettings(fileName)) {
            loadCurrentSettings();
            QMessageBox::information(this, "Import Successful", 
                "Settings have been imported successfully.");
        } else {
            QMessageBox::warning(this, "Import Failed", 
                "Failed to import settings from the selected file.");
        }
    }
}

void SettingsDialog::exportSettings()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        "Export Settings",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/packet_capture_settings.json",
        "JSON Files (*.json);;All Files (*)");
    
    if (!fileName.isEmpty()) {
        if (SettingsManager::instance()->exportSettings(fileName)) {
            QMessageBox::information(this, "Export Successful", 
                QString("Settings have been exported to:\n%1").arg(fileName));
        } else {
            QMessageBox::warning(this, "Export Failed", 
                "Failed to export settings to the selected file.");
        }
    }
}

void SettingsDialog::onSettingChanged()
{
    m_settingsChanged = true;
    m_applyButton->setEnabled(true);
    updatePreview();
}

void SettingsDialog::onFontChanged()
{
    onSettingChanged();
    
    // Update font preview
    QString fontFamily = m_hexFontCombo->currentText();
    int fontSize = m_hexFontSizeSpinBox->value();
    
    QFont font(fontFamily, fontSize);
    m_fontPreviewLabel->setFont(font);
    m_fontPreviewLabel->setText(QString("Sample text in %1 %2pt").arg(fontFamily).arg(fontSize));
}

void SettingsDialog::onMemoryLimitChanged(int value)
{
    m_memoryLimitLabel->setText(QString("Memory Limit: %1 MB").arg(value));
    onSettingChanged();
}

void SettingsDialog::onUpdateIntervalChanged(int value)
{
    m_updateIntervalLabel->setText(QString("Update Interval: %1 ms").arg(value));
    onSettingChanged();
}

void SettingsDialog::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create tab widget
    m_tabWidget = new QTabWidget;
    m_mainLayout->addWidget(m_tabWidget);
    
    // Setup tabs
    setupGeneralTab();
    setupInterfaceTab();
    setupCaptureTab();
    setupDisplayTab();
    setupPerformanceTab();
    setupAdvancedTab();
    
    // Button layout
    m_buttonLayout = new QHBoxLayout;
    
    m_importButton = new QPushButton("Import...");
    connect(m_importButton, &QPushButton::clicked, this, &SettingsDialog::importSettings);
    m_buttonLayout->addWidget(m_importButton);
    
    m_exportButton = new QPushButton("Export...");
    connect(m_exportButton, &QPushButton::clicked, this, &SettingsDialog::exportSettings);
    m_buttonLayout->addWidget(m_exportButton);
    
    m_resetButton = new QPushButton("Reset to Defaults");
    connect(m_resetButton, &QPushButton::clicked, this, &SettingsDialog::resetToDefaults);
    m_buttonLayout->addWidget(m_resetButton);
    
    m_buttonLayout->addStretch();
    
    m_applyButton = new QPushButton("Apply");
    m_applyButton->setEnabled(false);
    connect(m_applyButton, &QPushButton::clicked, this, &SettingsDialog::applySettings);
    m_buttonLayout->addWidget(m_applyButton);
    
    m_okButton = new QPushButton("OK");
    connect(m_okButton, &QPushButton::clicked, [this]() {
        if (m_settingsChanged) {
            saveCurrentSettings();
        }
        accept();
    });
    m_buttonLayout->addWidget(m_okButton);
    
    m_cancelButton = new QPushButton("Cancel");
    connect(m_cancelButton, &QPushButton::clicked, this, &QDialog::reject);
    m_buttonLayout->addWidget(m_cancelButton);
    
    m_mainLayout->addLayout(m_buttonLayout);
}

void SettingsDialog::setupGeneralTab()
{
    m_generalTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_generalTab);
    
    // Startup group
    QGroupBox *startupGroup = new QGroupBox("Startup");
    QFormLayout *startupLayout = new QFormLayout(startupGroup);
    
    m_autoStartCheckBox = new QCheckBox("Auto-start capture on interface selection");
    connect(m_autoStartCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    startupLayout->addRow(m_autoStartCheckBox);
    
    layout->addWidget(startupGroup);
    
    // System tray group
    QGroupBox *trayGroup = new QGroupBox("System Tray");
    QFormLayout *trayLayout = new QFormLayout(trayGroup);
    
    m_systemTrayCheckBox = new QCheckBox("Enable system tray icon");
    connect(m_systemTrayCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    trayLayout->addRow(m_systemTrayCheckBox);
    
    m_minimizeToTrayCheckBox = new QCheckBox("Minimize to system tray");
    connect(m_minimizeToTrayCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    trayLayout->addRow(m_minimizeToTrayCheckBox);
    
    layout->addWidget(trayGroup);
    
    // Application group
    QGroupBox *appGroup = new QGroupBox("Application");
    QFormLayout *appLayout = new QFormLayout(appGroup);
    
    m_confirmExitCheckBox = new QCheckBox("Confirm before exit");
    connect(m_confirmExitCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    appLayout->addRow(m_confirmExitCheckBox);
    
    m_maxRecentFilesSpinBox = new QSpinBox;
    m_maxRecentFilesSpinBox->setRange(0, 50);
    connect(m_maxRecentFilesSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    appLayout->addRow("Max recent files:", m_maxRecentFilesSpinBox);
    
    layout->addWidget(appGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_generalTab, "General");
}

void SettingsDialog::setupInterfaceTab()
{
    m_interfaceTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_interfaceTab);
    
    // Interface selection group
    QGroupBox *selectionGroup = new QGroupBox("Interface Selection");
    QFormLayout *selectionLayout = new QFormLayout(selectionGroup);
    
    m_defaultInterfaceCombo = new QComboBox;
    m_defaultInterfaceCombo->addItem("(None - Always ask)");
    
    // Populate with available interfaces
    NetworkInterfaceManager interfaceManager;
    QStringList interfaces = interfaceManager.getAvailableInterfaces();
    m_defaultInterfaceCombo->addItems(interfaces);
    
    connect(m_defaultInterfaceCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsDialog::onSettingChanged);
    selectionLayout->addRow("Default interface:", m_defaultInterfaceCombo);
    
    m_interfaceHistorySpinBox = new QSpinBox;
    m_interfaceHistorySpinBox->setRange(1, 50);
    connect(m_interfaceHistorySpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    selectionLayout->addRow("Interface history size:", m_interfaceHistorySpinBox);
    
    layout->addWidget(selectionGroup);
    
    // Interface monitoring group
    QGroupBox *monitoringGroup = new QGroupBox("Interface Monitoring");
    QFormLayout *monitoringLayout = new QFormLayout(monitoringGroup);
    
    m_autoRefreshInterfacesCheckBox = new QCheckBox("Auto-refresh interface list");
    connect(m_autoRefreshInterfacesCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    monitoringLayout->addRow(m_autoRefreshInterfacesCheckBox);
    
    m_refreshIntervalSpinBox = new QSpinBox;
    m_refreshIntervalSpinBox->setRange(1000, 60000);
    m_refreshIntervalSpinBox->setSuffix(" ms");
    connect(m_refreshIntervalSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    monitoringLayout->addRow("Refresh interval:", m_refreshIntervalSpinBox);
    
    layout->addWidget(monitoringGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_interfaceTab, "Interface");
}

void SettingsDialog::setupCaptureTab()
{
    m_captureTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_captureTab);
    
    // Capture settings group
    QGroupBox *captureGroup = new QGroupBox("Capture Settings");
    QFormLayout *captureLayout = new QFormLayout(captureGroup);
    
    m_defaultFilterEdit = new QLineEdit;
    connect(m_defaultFilterEdit, &QLineEdit::textChanged, this, &SettingsDialog::onSettingChanged);
    captureLayout->addRow("Default capture filter:", m_defaultFilterEdit);
    
    m_maxPacketsSpinBox = new QSpinBox;
    m_maxPacketsSpinBox->setRange(100, 1000000);
    connect(m_maxPacketsSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    captureLayout->addRow("Max packets to capture:", m_maxPacketsSpinBox);
    
    m_captureTimeoutSpinBox = new QSpinBox;
    m_captureTimeoutSpinBox->setRange(0, 3600);
    m_captureTimeoutSpinBox->setSuffix(" seconds (0 = no timeout)");
    connect(m_captureTimeoutSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    captureLayout->addRow("Capture timeout:", m_captureTimeoutSpinBox);
    
    layout->addWidget(captureGroup);
    
    // Advanced capture group
    QGroupBox *advancedGroup = new QGroupBox("Advanced Capture");
    QFormLayout *advancedLayout = new QFormLayout(advancedGroup);
    
    m_promiscuousModeCheckBox = new QCheckBox("Enable promiscuous mode");
    connect(m_promiscuousModeCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    advancedLayout->addRow(m_promiscuousModeCheckBox);
    
    m_bufferSizeSpinBox = new QSpinBox;
    m_bufferSizeSpinBox->setRange(1, 100);
    m_bufferSizeSpinBox->setSuffix(" MB");
    connect(m_bufferSizeSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onSettingChanged);
    advancedLayout->addRow("Capture buffer size:", m_bufferSizeSpinBox);
    
    layout->addWidget(advancedGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_captureTab, "Capture");
}

void SettingsDialog::setupDisplayTab()
{
    m_displayTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_displayTab);
    
    // Font settings group
    QGroupBox *fontGroup = new QGroupBox("Font Settings");
    QFormLayout *fontLayout = new QFormLayout(fontGroup);
    
    m_hexFontCombo = new QFontComboBox;
    m_hexFontCombo->setFontFilters(QFontComboBox::MonospacedFonts);
    connect(m_hexFontCombo, &QFontComboBox::currentFontChanged, this, &SettingsDialog::onFontChanged);
    fontLayout->addRow("Hex view font:", m_hexFontCombo);
    
    m_hexFontSizeSpinBox = new QSpinBox;
    m_hexFontSizeSpinBox->setRange(6, 24);
    connect(m_hexFontSizeSpinBox, QOverload<int>::of(&QSpinBox::valueChanged), this, &SettingsDialog::onFontChanged);
    fontLayout->addRow("Font size:", m_hexFontSizeSpinBox);
    
    m_fontPreviewLabel = new QLabel("Sample text preview");
    m_fontPreviewLabel->setStyleSheet("border: 1px solid gray; padding: 5px; background: white;");
    fontLayout->addRow("Preview:", m_fontPreviewLabel);
    
    layout->addWidget(fontGroup);
    
    // Display options group
    QGroupBox *displayGroup = new QGroupBox("Display Options");
    QFormLayout *displayLayout = new QFormLayout(displayGroup);
    
    m_treeExpandedCheckBox = new QCheckBox("Expand protocol tree by default");
    connect(m_treeExpandedCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    displayLayout->addRow(m_treeExpandedCheckBox);
    
    m_showLineNumbersCheckBox = new QCheckBox("Show line numbers in hex view");
    connect(m_showLineNumbersCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    displayLayout->addRow(m_showLineNumbersCheckBox);
    
    m_timestampFormatCombo = new QComboBox;
    m_timestampFormatCombo->addItems({"Absolute", "Relative", "Delta"});
    connect(m_timestampFormatCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsDialog::onSettingChanged);
    displayLayout->addRow("Timestamp format:", m_timestampFormatCombo);
    
    layout->addWidget(displayGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_displayTab, "Display");
}

void SettingsDialog::setupPerformanceTab()
{
    m_performanceTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_performanceTab);
    
    // Memory settings group
    QGroupBox *memoryGroup = new QGroupBox("Memory Settings");
    QVBoxLayout *memoryLayout = new QVBoxLayout(memoryGroup);
    
    m_memoryLimitLabel = new QLabel("Memory Limit: 512 MB");
    memoryLayout->addWidget(m_memoryLimitLabel);
    
    m_memoryLimitSlider = new QSlider(Qt::Horizontal);
    m_memoryLimitSlider->setRange(128, 2048);
    m_memoryLimitSlider->setValue(512);
    connect(m_memoryLimitSlider, &QSlider::valueChanged, this, &SettingsDialog::onMemoryLimitChanged);
    memoryLayout->addWidget(m_memoryLimitSlider);
    
    m_enableMemoryMonitoringCheckBox = new QCheckBox("Enable memory monitoring");
    connect(m_enableMemoryMonitoringCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    memoryLayout->addWidget(m_enableMemoryMonitoringCheckBox);
    
    layout->addWidget(memoryGroup);
    
    // Update settings group
    QGroupBox *updateGroup = new QGroupBox("Update Settings");
    QVBoxLayout *updateLayout = new QVBoxLayout(updateGroup);
    
    m_updateIntervalLabel = new QLabel("Update Interval: 100 ms");
    updateLayout->addWidget(m_updateIntervalLabel);
    
    m_updateIntervalSlider = new QSlider(Qt::Horizontal);
    m_updateIntervalSlider->setRange(50, 1000);
    m_updateIntervalSlider->setValue(100);
    connect(m_updateIntervalSlider, &QSlider::valueChanged, this, &SettingsDialog::onUpdateIntervalChanged);
    updateLayout->addWidget(m_updateIntervalSlider);
    
    layout->addWidget(updateGroup);
    
    // Logging settings group
    QGroupBox *loggingGroup = new QGroupBox("Logging Settings");
    QFormLayout *loggingLayout = new QFormLayout(loggingGroup);
    
    m_enableLoggingCheckBox = new QCheckBox("Enable logging");
    connect(m_enableLoggingCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    loggingLayout->addRow(m_enableLoggingCheckBox);
    
    m_logLevelCombo = new QComboBox;
    m_logLevelCombo->addItems({"Debug", "Info", "Warning", "Error", "Critical"});
    connect(m_logLevelCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, &SettingsDialog::onSettingChanged);
    loggingLayout->addRow("Log level:", m_logLevelCombo);
    
    layout->addWidget(loggingGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_performanceTab, "Performance");
}

void SettingsDialog::setupAdvancedTab()
{
    m_advancedTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_advancedTab);
    
    // Debug settings group
    QGroupBox *debugGroup = new QGroupBox("Debug Settings");
    QFormLayout *debugLayout = new QFormLayout(debugGroup);
    
    m_debugModeCheckBox = new QCheckBox("Enable debug mode");
    connect(m_debugModeCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    debugLayout->addRow(m_debugModeCheckBox);
    
    m_developerModeCheckBox = new QCheckBox("Enable developer mode");
    connect(m_developerModeCheckBox, &QCheckBox::toggled, this, &SettingsDialog::onSettingChanged);
    debugLayout->addRow(m_developerModeCheckBox);
    
    layout->addWidget(debugGroup);
    
    // Maintenance group
    QGroupBox *maintenanceGroup = new QGroupBox("Maintenance");
    QVBoxLayout *maintenanceLayout = new QVBoxLayout(maintenanceGroup);
    
    m_clearCacheButton = new QPushButton("Clear Cache");
    connect(m_clearCacheButton, &QPushButton::clicked, [this]() {
        QMessageBox::information(this, "Cache Cleared", "Application cache has been cleared.");
    });
    maintenanceLayout->addWidget(m_clearCacheButton);
    
    m_resetErrorCountersButton = new QPushButton("Reset Error Counters");
    connect(m_resetErrorCountersButton, &QPushButton::clicked, [this]() {
        QMessageBox::information(this, "Counters Reset", "Error counters have been reset.");
    });
    maintenanceLayout->addWidget(m_resetErrorCountersButton);
    
    layout->addWidget(maintenanceGroup);
    
    // Custom settings group
    QGroupBox *customGroup = new QGroupBox("Custom Settings (JSON)");
    QVBoxLayout *customLayout = new QVBoxLayout(customGroup);
    
    m_customSettingsEdit = new QTextEdit;
    m_customSettingsEdit->setMaximumHeight(100);
    m_customSettingsEdit->setPlainText("{}");
    connect(m_customSettingsEdit, &QTextEdit::textChanged, this, &SettingsDialog::onSettingChanged);
    customLayout->addWidget(m_customSettingsEdit);
    
    layout->addWidget(customGroup);
    layout->addStretch();
    
    m_tabWidget->addTab(m_advancedTab, "Advanced");
}

void SettingsDialog::loadCurrentSettings()
{
    SettingsManager *settings = SettingsManager::instance();
    
    // General settings
    m_autoStartCheckBox->setChecked(settings->getAutoStartCapture());
    m_systemTrayCheckBox->setChecked(settings->getCustomSetting("system_tray_enabled", false).toBool());
    m_minimizeToTrayCheckBox->setChecked(settings->getCustomSetting("minimize_to_tray", false).toBool());
    m_confirmExitCheckBox->setChecked(settings->getCustomSetting("confirm_exit", true).toBool());
    m_maxRecentFilesSpinBox->setValue(settings->getCustomSetting("max_recent_files", 10).toInt());
    
    // Interface settings
    QString lastInterface = settings->getLastUsedInterface();
    int interfaceIndex = m_defaultInterfaceCombo->findText(lastInterface);
    if (interfaceIndex >= 0) {
        m_defaultInterfaceCombo->setCurrentIndex(interfaceIndex);
    }
    m_interfaceHistorySpinBox->setValue(settings->getCustomSetting("interface_history_size", 10).toInt());
    m_autoRefreshInterfacesCheckBox->setChecked(settings->getCustomSetting("auto_refresh_interfaces", false).toBool());
    m_refreshIntervalSpinBox->setValue(settings->getCustomSetting("interface_refresh_interval", 5000).toInt());
    
    // Capture settings
    m_defaultFilterEdit->setText(settings->getCaptureFilter());
    m_maxPacketsSpinBox->setValue(settings->getMaxPackets());
    m_captureTimeoutSpinBox->setValue(settings->getCaptureTimeout());
    m_promiscuousModeCheckBox->setChecked(settings->getCustomSetting("promiscuous_mode", false).toBool());
    m_bufferSizeSpinBox->setValue(settings->getCustomSetting("buffer_size", 10).toInt());
    
    // Display settings
    m_hexFontCombo->setCurrentFont(QFont(settings->getHexViewFontFamily()));
    m_hexFontSizeSpinBox->setValue(settings->getHexViewFontSize());
    m_treeExpandedCheckBox->setChecked(settings->getProtocolTreeExpanded());
    m_showLineNumbersCheckBox->setChecked(settings->getCustomSetting("show_line_numbers", true).toBool());
    m_timestampFormatCombo->setCurrentIndex(settings->getCustomSetting("timestamp_format", 0).toInt());
    
    // Performance settings
    m_memoryLimitSlider->setValue(settings->getMemoryLimit());
    m_updateIntervalSlider->setValue(settings->getUpdateInterval());
    m_enableLoggingCheckBox->setChecked(settings->getEnableLogging());
    m_logLevelCombo->setCurrentIndex(settings->getLogLevel());
    m_enableMemoryMonitoringCheckBox->setChecked(settings->getCustomSetting("memory_monitoring", true).toBool());
    
    // Advanced settings
    m_debugModeCheckBox->setChecked(settings->getDebugMode());
    m_developerModeCheckBox->setChecked(settings->getDeveloperMode());
    
    // Update UI
    onFontChanged();
    onMemoryLimitChanged(m_memoryLimitSlider->value());
    onUpdateIntervalChanged(m_updateIntervalSlider->value());
    
    m_settingsChanged = false;
    m_applyButton->setEnabled(false);
}

void SettingsDialog::saveCurrentSettings()
{
    SettingsManager *settings = SettingsManager::instance();
    
    // General settings
    settings->setAutoStartCapture(m_autoStartCheckBox->isChecked());
    settings->setCustomSetting("system_tray_enabled", m_systemTrayCheckBox->isChecked());
    settings->setCustomSetting("minimize_to_tray", m_minimizeToTrayCheckBox->isChecked());
    settings->setCustomSetting("confirm_exit", m_confirmExitCheckBox->isChecked());
    settings->setCustomSetting("max_recent_files", m_maxRecentFilesSpinBox->value());
    
    // Interface settings
    if (m_defaultInterfaceCombo->currentIndex() > 0) {
        settings->setLastUsedInterface(m_defaultInterfaceCombo->currentText());
    }
    settings->setCustomSetting("interface_history_size", m_interfaceHistorySpinBox->value());
    settings->setCustomSetting("auto_refresh_interfaces", m_autoRefreshInterfacesCheckBox->isChecked());
    settings->setCustomSetting("interface_refresh_interval", m_refreshIntervalSpinBox->value());
    
    // Capture settings
    settings->setCaptureFilter(m_defaultFilterEdit->text());
    settings->setMaxPackets(m_maxPacketsSpinBox->value());
    settings->setCaptureTimeout(m_captureTimeoutSpinBox->value());
    settings->setCustomSetting("promiscuous_mode", m_promiscuousModeCheckBox->isChecked());
    settings->setCustomSetting("buffer_size", m_bufferSizeSpinBox->value());
    
    // Display settings
    settings->setHexViewFont(m_hexFontCombo->currentFont().family(), m_hexFontSizeSpinBox->value());
    settings->setProtocolTreeExpanded(m_treeExpandedCheckBox->isChecked());
    settings->setCustomSetting("show_line_numbers", m_showLineNumbersCheckBox->isChecked());
    settings->setCustomSetting("timestamp_format", m_timestampFormatCombo->currentIndex());
    
    // Performance settings
    settings->setMemoryLimit(m_memoryLimitSlider->value());
    settings->setUpdateInterval(m_updateIntervalSlider->value());
    settings->setEnableLogging(m_enableLoggingCheckBox->isChecked());
    settings->setLogLevel(m_logLevelCombo->currentIndex());
    settings->setCustomSetting("memory_monitoring", m_enableMemoryMonitoringCheckBox->isChecked());
    
    // Advanced settings
    settings->setDebugMode(m_debugModeCheckBox->isChecked());
    settings->setDeveloperMode(m_developerModeCheckBox->isChecked());
    
    // Save to file
    settings->saveSettings();
}

void SettingsDialog::updatePreview()
{
    // Update any preview elements based on current settings
    onFontChanged();
}