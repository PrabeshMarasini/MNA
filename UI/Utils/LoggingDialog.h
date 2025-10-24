#ifndef LOGGINGDIALOG_H
#define LOGGINGDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTextEdit>
#include <QPushButton>
#include <QComboBox>
#include <QCheckBox>
#include <QLabel>
#include <QTimer>
#include <QProgressBar>
#include "ErrorHandler.h"

/**
 * @brief Dialog for viewing and managing application logs
 * 
 * This dialog provides a comprehensive interface for viewing error logs,
 * filtering by severity and category, and managing log files.
 */
class LoggingDialog : public QDialog
{
    Q_OBJECT

public:
    explicit LoggingDialog(QWidget *parent = nullptr);
    ~LoggingDialog();

public slots:
    /**
     * @brief Refresh log display
     */
    void refreshLogs();

    /**
     * @brief Clear log display
     */
    void clearLogs();

    /**
     * @brief Save logs to file
     */
    void saveLogs();

    /**
     * @brief Export error report
     */
    void exportReport();

private slots:
    void onFilterChanged();
    void onAutoRefreshToggled(bool enabled);
    void onNewErrorLogged(const ErrorHandler::ErrorInfo &error);
    void onAutoRefreshTimer();
    void onCopyToClipboard();
    void onFindText();

private:
    void setupUI();
    void updateLogDisplay();
    void applyFilters();
    QString formatLogEntry(const ErrorHandler::ErrorInfo &error) const;
    QString getLogLevelColor(ErrorHandler::ErrorLevel level) const;

    // UI components
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_controlLayout;
    QHBoxLayout *m_filterLayout;
    
    QTextEdit *m_logDisplay;
    
    // Controls
    QPushButton *m_refreshButton;
    QPushButton *m_clearButton;
    QPushButton *m_saveButton;
    QPushButton *m_exportButton;
    QPushButton *m_copyButton;
    QPushButton *m_findButton;
    QPushButton *m_closeButton;
    
    // Filters
    QComboBox *m_levelFilter;
    QComboBox *m_categoryFilter;
    QCheckBox *m_autoRefreshCheckBox;
    
    // Status
    QLabel *m_statusLabel;
    QProgressBar *m_progressBar;
    
    // Auto refresh
    QTimer *m_autoRefreshTimer;
    
    // Current filters
    ErrorHandler::ErrorLevel m_currentLevelFilter;
    ErrorHandler::ErrorCategory m_currentCategoryFilter;
    bool m_autoRefreshEnabled;
    
    // Log data
    QList<ErrorHandler::ErrorInfo> m_currentLogs;
};

#endif // LOGGINGDIALOG_H