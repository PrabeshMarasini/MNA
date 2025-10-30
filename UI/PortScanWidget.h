#ifndef PORTSCANWIDGET_H
#define PORTSCANWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QLineEdit>
#include <QComboBox>
#include <QSpinBox>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QThread>
#include <QTimer>
#include <QProcess>
#include <QHeaderView>

class PortScanWorker;

class PortScanWidget : public QWidget
{
    Q_OBJECT

public:
    explicit PortScanWidget(QWidget *parent = nullptr);
    ~PortScanWidget();

private slots:
    void startPortScan();
    void cancelPortScan();
    void onScanTypeChanged();
    void onPortFound(int port, const QString &service, const QString &status);
    void onProgressUpdate(float percentage);
    void onScanCompleted(int totalFound);
    void onScanError(const QString &error);
    void clearResults();

private:
    void setupUI();
    void updateButtonStates();
    void resetResults();
    void addPortToTable(int port, const QString &service, const QString &status);

    // UI Components
    QVBoxLayout *m_mainLayout;
    QGridLayout *m_configLayout;
    QHBoxLayout *m_buttonLayout;
    
    // Configuration controls
    QLabel *m_targetLabel;
    QLineEdit *m_targetEdit;
    QLabel *m_scanTypeLabel;
    QComboBox *m_scanTypeCombo;
    QLabel *m_startPortLabel;
    QSpinBox *m_startPortSpin;
    QLabel *m_endPortLabel;
    QSpinBox *m_endPortSpin;
    
    // Action buttons
    QPushButton *m_startButton;
    QPushButton *m_cancelButton;
    QPushButton *m_clearButton;
    
    // Progress and status
    QProgressBar *m_progressBar;
    QLabel *m_statusLabel;
    
    // Results table
    QTableWidget *m_resultsTable;
    
    // Worker thread
    QThread *m_workerThread;
    PortScanWorker *m_worker;
    
    bool m_scanInProgress;
    int m_foundPorts;
};

// Worker class for running port scans in background
class PortScanWorker : public QObject
{
    Q_OBJECT

public:
    explicit PortScanWorker(QObject *parent = nullptr);

public slots:
    void runPortScan(const QString &hostname, const QString &scanType, int startPort = 0, int endPort = 0);
    void cancelScan();

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus);
    void onProcessError(QProcess::ProcessError error);
    void onProcessOutput();

signals:
    void portFound(int port, const QString &service, const QString &status);
    void progressUpdate(float percentage);
    void scanCompleted(int totalFound);
    void scanError(const QString &error);

private:
    void parsePortScanOutput(const QString &line);
    
    bool m_cancelled;
    QProcess *m_process;
    QString m_currentScanType;
    int m_totalFound;
};

#endif // PORTSCANWIDGET_H