#ifndef DNSLOOKUPWIDGET_H
#define DNSLOOKUPWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QProgressBar>
#include <QComboBox>
#include <QGroupBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QThread>
#include <QMutex>

extern "C" {
    #include "../src/dns/dns.h"
}

class DnsLookupWorker : public QObject {
    Q_OBJECT

public:
    explicit DnsLookupWorker(QObject *parent = nullptr);

public slots:
    void performLookup(const QString &target, const QString &recordType);
    void performReverseLookup(const QString &ipAddress);

signals:
    void lookupCompleted(const DnsLookupResult &result);
    void reverseLookupCompleted(const QString &ipAddress, const QString &hostname);
    void lookupFailed(const QString &error);

private:
    QMutex m_mutex;
};

class DnsLookupWidget : public QWidget {
    Q_OBJECT

public:
    explicit DnsLookupWidget(QWidget *parent = nullptr);
    ~DnsLookupWidget();

private slots:
    void onLookupClicked();
    void onClearClicked();
    void onLookupCompleted(const DnsLookupResult &result);
    void onReverseLookupCompleted(const QString &ipAddress, const QString &hostname);
    void onLookupFailed(const QString &error);
    void onResultTableItemClicked(int row, int column);
    void onTargetChanged();

private:
    void setupUI();
    void updateResults(const DnsLookupResult &result);
    void addResultToTable(const QString &type, const QString &data, const QString &extra = "");
    void clearResults();
    void setLookupInProgress(bool inProgress);
    bool isValidInput(const QString &input);
    QString formatQueryTime(double timeMs);

    // UI Components
    QVBoxLayout *m_mainLayout;
    QGroupBox *m_inputGroup;
    QHBoxLayout *m_inputLayout;
    QLineEdit *m_targetEdit;
    QComboBox *m_recordTypeCombo;
    QPushButton *m_lookupButton;
    QPushButton *m_clearButton;
    QProgressBar *m_progressBar;

    QGroupBox *m_resultsGroup;
    QVBoxLayout *m_resultsLayout;
    QLabel *m_statusLabel;
    QTableWidget *m_resultsTable;
    
    QGroupBox *m_detailsGroup;
    QVBoxLayout *m_detailsLayout;
    QLabel *m_queryTimeLabel;
    QLabel *m_dnsServerLabel;
    QLabel *m_recordCountLabel;

    // Worker thread
    QThread *m_workerThread;
    DnsLookupWorker *m_worker;

    // State
    QString m_currentTarget;
    bool m_lookupInProgress;
};

#endif // DNSLOOKUPWIDGET_H