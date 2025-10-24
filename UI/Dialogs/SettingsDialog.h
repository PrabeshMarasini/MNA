#ifndef SETTINGSDIALOG_H
#define SETTINGSDIALOG_H

#include <QDialog>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QPushButton>
#include <QCheckBox>
#include <QSpinBox>
#include <QComboBox>
#include <QLineEdit>
#include <QFontComboBox>
#include <QSlider>
#include <QTextEdit>

/**
 * @brief Settings configuration dialog
 * 
 * This dialog provides a comprehensive interface for configuring
 * all application settings across different categories.
 */
class SettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SettingsDialog(QWidget *parent = nullptr);

public slots:
    void applySettings();
    void resetToDefaults();
    void importSettings();
    void exportSettings();

private slots:
    void onSettingChanged();
    void onFontChanged();
    void onMemoryLimitChanged(int value);
    void onUpdateIntervalChanged(int value);

private:
    void setupUI();
    void setupGeneralTab();
    void setupInterfaceTab();
    void setupCaptureTab();
    void setupDisplayTab();
    void setupPerformanceTab();
    void setupAdvancedTab();
    
    void loadCurrentSettings();
    void saveCurrentSettings();
    void updatePreview();

    // UI components
    QVBoxLayout *m_mainLayout;
    QTabWidget *m_tabWidget;
    
    // General tab
    QWidget *m_generalTab;
    QCheckBox *m_autoStartCheckBox;
    QCheckBox *m_systemTrayCheckBox;
    QCheckBox *m_minimizeToTrayCheckBox;
    QCheckBox *m_confirmExitCheckBox;
    QSpinBox *m_maxRecentFilesSpinBox;
    
    // Interface tab
    QWidget *m_interfaceTab;
    QComboBox *m_defaultInterfaceCombo;
    QSpinBox *m_interfaceHistorySpinBox;
    QCheckBox *m_autoRefreshInterfacesCheckBox;
    QSpinBox *m_refreshIntervalSpinBox;
    
    // Capture tab
    QWidget *m_captureTab;
    QLineEdit *m_defaultFilterEdit;
    QSpinBox *m_maxPacketsSpinBox;
    QSpinBox *m_captureTimeoutSpinBox;
    QCheckBox *m_promiscuousModeCheckBox;
    QSpinBox *m_bufferSizeSpinBox;
    
    // Display tab
    QWidget *m_displayTab;
    QFontComboBox *m_hexFontCombo;
    QSpinBox *m_hexFontSizeSpinBox;
    QCheckBox *m_treeExpandedCheckBox;
    QCheckBox *m_showLineNumbersCheckBox;
    QComboBox *m_timestampFormatCombo;
    QLabel *m_fontPreviewLabel;
    
    // Performance tab
    QWidget *m_performanceTab;
    QSlider *m_memoryLimitSlider;
    QLabel *m_memoryLimitLabel;
    QSlider *m_updateIntervalSlider;
    QLabel *m_updateIntervalLabel;
    QCheckBox *m_enableLoggingCheckBox;
    QComboBox *m_logLevelCombo;
    QCheckBox *m_enableMemoryMonitoringCheckBox;
    
    // Advanced tab
    QWidget *m_advancedTab;
    QCheckBox *m_debugModeCheckBox;
    QCheckBox *m_developerModeCheckBox;
    QTextEdit *m_customSettingsEdit;
    QPushButton *m_clearCacheButton;
    QPushButton *m_resetErrorCountersButton;
    
    // Buttons
    QHBoxLayout *m_buttonLayout;
    QPushButton *m_applyButton;
    QPushButton *m_resetButton;
    QPushButton *m_importButton;
    QPushButton *m_exportButton;
    QPushButton *m_okButton;
    QPushButton *m_cancelButton;
    
    // State tracking
    bool m_settingsChanged;
};

#endif // SETTINGSDIALOG_H