#ifndef ERRORRECOVERYDIALOG_H
#define ERRORRECOVERYDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QCheckBox>
#include <QProgressBar>
#include <QTimer>
#include "ErrorHandler.h"

/**
 * @brief Error recovery dialog with automated recovery options
 * 
 * This dialog provides users with recovery options when errors occur,
 * including automated recovery attempts and manual intervention options.
 */
class ErrorRecoveryDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Recovery actions that can be performed
     */
    enum RecoveryAction {
        NoAction = 0,           ///< No recovery action
        Retry,                  ///< Retry the failed operation
        Reset,                  ///< Reset the component/system
        Restart,                ///< Restart the application
        IgnoreError,            ///< Ignore the error and continue
        ReportAndContinue,      ///< Report error and continue
        SafeShutdown           ///< Perform safe shutdown
    };

    /**
     * @brief Recovery result
     */
    struct RecoveryResult {
        RecoveryAction action;
        bool successful;
        QString message;
        bool preventFutureDialogs;
    };

    /**
     * @brief Create error recovery dialog
     */
    explicit ErrorRecoveryDialog(const ErrorHandler::ErrorInfo &error, 
                                QWidget *parent = nullptr);

    /**
     * @brief Create recovery dialog with custom options
     */
    explicit ErrorRecoveryDialog(const QString &title, 
                                const QString &message,
                                const QString &details,
                                const QList<RecoveryAction> &availableActions,
                                QWidget *parent = nullptr);

    /**
     * @brief Get the recovery result
     */
    RecoveryResult getRecoveryResult() const { return m_result; }

    /**
     * @brief Set automatic recovery timeout (0 to disable)
     */
    void setAutoRecoveryTimeout(int seconds);

    /**
     * @brief Set default recovery action for timeout
     */
    void setDefaultAction(RecoveryAction action) { m_defaultAction = action; }

    /**
     * @brief Enable/disable detailed error information
     */
    void setShowDetails(bool show);

public slots:
    /**
     * @brief Attempt automatic recovery
     */
    void attemptAutoRecovery();

protected:
    void closeEvent(QCloseEvent *event) override;

private slots:
    void onRetryClicked();
    void onResetClicked();
    void onRestartClicked();
    void onIgnoreClicked();
    void onReportClicked();
    void onShutdownClicked();
    void onDetailsToggled(bool show);
    void onAutoRecoveryTimeout();
    void onAutoRecoveryProgress();

private:
    void setupUI();
    void setupButtons();
    void updateAutoRecoveryProgress();
    QString getActionDescription(RecoveryAction action) const;
    QIcon getActionIcon(RecoveryAction action) const;
    bool performRecoveryAction(RecoveryAction action);

    // Error information
    ErrorHandler::ErrorInfo m_errorInfo;
    QString m_title;
    QString m_message;
    QString m_details;
    QList<RecoveryAction> m_availableActions;

    // Recovery result
    RecoveryResult m_result;
    RecoveryAction m_defaultAction;

    // Auto recovery
    int m_autoRecoveryTimeout;
    int m_remainingTime;
    QTimer *m_autoRecoveryTimer;
    QTimer *m_progressTimer;

    // UI components
    QVBoxLayout *m_mainLayout;
    QLabel *m_iconLabel;
    QLabel *m_messageLabel;
    QTextEdit *m_detailsText;
    QCheckBox *m_preventFutureCheckBox;
    QProgressBar *m_autoRecoveryProgress;
    QLabel *m_autoRecoveryLabel;
    
    // Action buttons
    QPushButton *m_retryButton;
    QPushButton *m_resetButton;
    QPushButton *m_restartButton;
    QPushButton *m_ignoreButton;
    QPushButton *m_reportButton;
    QPushButton *m_shutdownButton;
    QPushButton *m_detailsButton;
    QPushButton *m_cancelButton;

    bool m_detailsVisible;
};

#endif // ERRORRECOVERYDIALOG_H