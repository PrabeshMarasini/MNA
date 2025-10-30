#ifndef LATENCYTESTWIDGET_H
#define LATENCYTESTWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QThread>
#include <QTimer>
#include <QProcess>

class LatencyTestWorker;

class LatencyTestWidget : public QWidget
{
    Q_OBJECT

public:
    explicit LatencyTestWidget(QWidget *parent = nullptr);
    ~LatencyTestWidget();

private slots:
    void startLatencyTest();
    void cancelLatencyTest();
    void onDnsLatencyResult(double latency);
    void onUdpLatencyResult(double latency);
    void onHttpsLatencyResult(double latency);
    void onTestCompleted();
    void onTestError(const QString &error);

private:
    void setupUI();
    void updateButtonStates();
    void resetResults();
    QString getLatencyStatusText(double latency, const QString &type);
    QString getLatencyColor(double latency, const QString &type);

    // UI Components
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_buttonLayout;
    QHBoxLayout *m_resultsLayout;
    
    QPushButton *m_startButton;
    QPushButton *m_cancelButton;
    
    QProgressBar *m_progressBar;
    
    QLabel *m_dnsLabel;
    QLabel *m_udpLabel;
    QLabel *m_httpsLabel;
    QLabel *m_dnsLatencyLabel;
    QLabel *m_udpLatencyLabel;
    QLabel *m_httpsLatencyLabel;
    
    // Worker thread
    QThread *m_workerThread;
    LatencyTestWorker *m_worker;
    
    bool m_testInProgress;
};

// Worker class for running latency tests in background
class LatencyTestWorker : public QObject
{
    Q_OBJECT

public:
    explicit LatencyTestWorker(QObject *parent = nullptr);

public slots:
    void runLatencyTest();
    void cancelTest();

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);

signals:
    void dnsLatencyResult(double latency);
    void udpLatencyResult(double latency);
    void httpsLatencyResult(double latency);
    void testCompleted();
    void testError(const QString &error);

private:
    void runDnsTest();
    void runUdpTest();
    void runHttpsTest();
    void parseLatencyOutput(const QString &output);
    
    bool m_cancelled;
    QProcess *m_process;
    int m_currentTest; // 0=DNS, 1=UDP, 2=HTTPS
    double m_dnsLatency;
    double m_udpLatency;
    double m_httpsLatency;
};

#endif // LATENCYTESTWIDGET_H