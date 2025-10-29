#ifndef SPEEDTESTWIDGET_H
#define SPEEDTESTWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QThread>
#include <QTimer>
#include <QProcess>

class SpeedTestWorker;

class SpeedTestWidget : public QWidget
{
    Q_OBJECT

public:
    explicit SpeedTestWidget(QWidget *parent = nullptr);
    ~SpeedTestWidget();

private slots:
    void startSpeedTest();
    void cancelSpeedTest();
    void onDownloadSpeedResult(double speed);
    void onUploadSpeedResult(double speed);
    void onTestCompleted();
    void onTestError(const QString &error);

private:
    void setupUI();
    void updateButtonStates();
    void resetResults();

    // UI Components
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_buttonLayout;
    QHBoxLayout *m_resultsLayout;
    
    QPushButton *m_startButton;
    QPushButton *m_cancelButton;
    
    QProgressBar *m_progressBar;
    
    QLabel *m_downloadLabel;
    QLabel *m_uploadLabel;
    QLabel *m_downloadSpeedLabel;
    QLabel *m_uploadSpeedLabel;
    
    // Worker thread
    QThread *m_workerThread;
    SpeedTestWorker *m_worker;
    
    bool m_testInProgress;
};

// Worker class for running speed tests in background
class SpeedTestWorker : public QObject
{
    Q_OBJECT

public:
    explicit SpeedTestWorker(QObject *parent = nullptr);

public slots:
    void runSpeedTest();
    void cancelTest();

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);

signals:
    void downloadSpeedResult(double speed);
    void uploadSpeedResult(double speed);
    void testCompleted();
    void testError(const QString &error);

private:
    void runDownloadTest();
    void runUploadTest();
    void parseSpeedTestOutput(const QString &output);
    
    bool m_cancelled;
    QProcess *m_process;
    bool m_downloadCompleted;
    double m_downloadSpeed;
    double m_uploadSpeed;
};

#endif // SPEEDTESTWIDGET_H