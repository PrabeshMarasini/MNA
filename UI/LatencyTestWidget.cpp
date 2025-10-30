#include "LatencyTestWidget.h"
#include <QGroupBox>
#include <QGridLayout>
#include <QFont>
#include <QThread>
#include <QDebug>
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QRegularExpression>

LatencyTestWidget::LatencyTestWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_buttonLayout(nullptr)
    , m_resultsLayout(nullptr)
    , m_startButton(nullptr)
    , m_cancelButton(nullptr)
    , m_progressBar(nullptr)
    , m_dnsLabel(nullptr)
    , m_udpLabel(nullptr)
    , m_httpsLabel(nullptr)
    , m_dnsLatencyLabel(nullptr)
    , m_udpLatencyLabel(nullptr)
    , m_httpsLatencyLabel(nullptr)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_testInProgress(false)
{
    setupUI();
    updateButtonStates();
}

LatencyTestWidget::~LatencyTestWidget()
{
    if (m_workerThread && m_workerThread->isRunning()) {
        if (m_worker) {
            m_worker->cancelTest();
        }
        m_workerThread->quit();
        m_workerThread->wait(3000);
    }
}

void LatencyTestWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create main group box
    QGroupBox *latencyTestGroup = new QGroupBox("Network Latency Test", this);
    QVBoxLayout *groupLayout = new QVBoxLayout(latencyTestGroup);
    
    // Button layout
    m_buttonLayout = new QHBoxLayout();
    
    m_startButton = new QPushButton("Start Test", this);
    m_startButton->setMinimumHeight(35);
    m_startButton->setStyleSheet("QPushButton { font-weight: bold; }");
    
    m_cancelButton = new QPushButton("Cancel", this);
    m_cancelButton->setMinimumHeight(35);
    m_cancelButton->setEnabled(false);
    
    m_buttonLayout->addWidget(m_startButton);
    m_buttonLayout->addWidget(m_cancelButton);
    m_buttonLayout->addStretch();
    
    // Progress bar
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setMinimumHeight(25);
    
    // Results layout - using grid for better organization
    QGridLayout *resultsGrid = new QGridLayout();
    
    // DNS section
    m_dnsLabel = new QLabel("DNS Latency (google.com):", this);
    m_dnsLabel->setStyleSheet("QLabel { font-weight: bold; color: #333; }");
    
    m_dnsLatencyLabel = new QLabel("-- ms", this);
    m_dnsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
    QFont dnsFont = m_dnsLatencyLabel->font();
    dnsFont.setBold(true);
    m_dnsLatencyLabel->setFont(dnsFont);
    
    // UDP section  
    m_udpLabel = new QLabel("UDP Latency (8.8.8.8:53):", this);
    m_udpLabel->setStyleSheet("QLabel { font-weight: bold; color: #333; }");
    
    m_udpLatencyLabel = new QLabel("-- ms", this);
    m_udpLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
    QFont udpFont = m_udpLatencyLabel->font();
    udpFont.setBold(true);
    m_udpLatencyLabel->setFont(udpFont);
    
    // HTTPS section
    m_httpsLabel = new QLabel("HTTPS Latency (google.com:443):", this);
    m_httpsLabel->setStyleSheet("QLabel { font-weight: bold; color: #333; }");
    
    m_httpsLatencyLabel = new QLabel("-- ms", this);
    m_httpsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
    QFont httpsFont = m_httpsLatencyLabel->font();
    httpsFont.setBold(true);
    m_httpsLatencyLabel->setFont(httpsFont);
    
    // Add to grid
    resultsGrid->addWidget(m_dnsLabel, 0, 0);
    resultsGrid->addWidget(m_dnsLatencyLabel, 0, 1);
    resultsGrid->addWidget(m_udpLabel, 1, 0);
    resultsGrid->addWidget(m_udpLatencyLabel, 1, 1);
    resultsGrid->addWidget(m_httpsLabel, 2, 0);
    resultsGrid->addWidget(m_httpsLatencyLabel, 2, 1);
    
    resultsGrid->setColumnStretch(0, 1);
    resultsGrid->setColumnStretch(1, 0);
    
    // Add everything to group layout
    groupLayout->addLayout(m_buttonLayout);
    groupLayout->addWidget(m_progressBar);
    groupLayout->addLayout(resultsGrid);
    
    // Add group to main layout
    m_mainLayout->addWidget(latencyTestGroup);
    m_mainLayout->addStretch();
    
    // Connect signals
    connect(m_startButton, &QPushButton::clicked, this, &LatencyTestWidget::startLatencyTest);
    connect(m_cancelButton, &QPushButton::clicked, this, &LatencyTestWidget::cancelLatencyTest);
}

void LatencyTestWidget::startLatencyTest()
{
    if (m_testInProgress) {
        return;
    }
    
    m_testInProgress = true;
    resetResults();
    
    // Show progress bar
    m_progressBar->setVisible(true);
    m_progressBar->setRange(0, 0); // Indeterminate progress
    
    updateButtonStates();
    
    // Create worker thread
    m_workerThread = new QThread(this);
    m_worker = new LatencyTestWorker();
    m_worker->moveToThread(m_workerThread);
    
    // Connect worker signals
    connect(m_workerThread, &QThread::started, m_worker, &LatencyTestWorker::runLatencyTest);
    connect(m_worker, &LatencyTestWorker::dnsLatencyResult, this, &LatencyTestWidget::onDnsLatencyResult, Qt::QueuedConnection);
    connect(m_worker, &LatencyTestWorker::udpLatencyResult, this, &LatencyTestWidget::onUdpLatencyResult, Qt::QueuedConnection);
    connect(m_worker, &LatencyTestWorker::httpsLatencyResult, this, &LatencyTestWidget::onHttpsLatencyResult, Qt::QueuedConnection);
    connect(m_worker, &LatencyTestWorker::testCompleted, this, &LatencyTestWidget::onTestCompleted, Qt::QueuedConnection);
    connect(m_worker, &LatencyTestWorker::testError, this, &LatencyTestWidget::onTestError, Qt::QueuedConnection);
    
    // Start the thread
    m_workerThread->start();
}

void LatencyTestWidget::cancelLatencyTest()
{
    if (!m_testInProgress) {
        return;
    }
    
    if (m_worker) {
        m_worker->cancelTest();
    }
    
    if (m_workerThread && m_workerThread->isRunning()) {
        m_workerThread->quit();
        if (!m_workerThread->wait(3000)) {
            m_workerThread->terminate();
            m_workerThread->wait();
        }
    }
    
    m_testInProgress = false;
    m_progressBar->setVisible(false);
    updateButtonStates();
    
    // Clean up
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    
    if (m_workerThread) {
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}void 
LatencyTestWidget::onDnsLatencyResult(double latency)
{
    qDebug() << "Received DNS latency result:" << latency;
    if (latency > 0) {
        QString latencyText = QString("%1 ms").arg(latency, 0, 'f', 1);
        QString color = getLatencyColor(latency, "dns");
        m_dnsLatencyLabel->setText(latencyText);
        m_dnsLatencyLabel->setStyleSheet(QString("QLabel { font-size: 14px; color: %1; }").arg(color));
    } else {
        m_dnsLatencyLabel->setText("Failed");
        m_dnsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    }
}

void LatencyTestWidget::onUdpLatencyResult(double latency)
{
    qDebug() << "Received UDP latency result:" << latency;
    if (latency > 0) {
        QString latencyText = QString("%1 ms").arg(latency, 0, 'f', 1);
        QString color = getLatencyColor(latency, "udp");
        m_udpLatencyLabel->setText(latencyText);
        m_udpLatencyLabel->setStyleSheet(QString("QLabel { font-size: 14px; color: %1; }").arg(color));
    } else {
        m_udpLatencyLabel->setText("Failed");
        m_udpLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    }
}

void LatencyTestWidget::onHttpsLatencyResult(double latency)
{
    qDebug() << "Received HTTPS latency result:" << latency;
    if (latency > 0) {
        QString latencyText = QString("%1 ms").arg(latency, 0, 'f', 1);
        QString color = getLatencyColor(latency, "https");
        m_httpsLatencyLabel->setText(latencyText);
        m_httpsLatencyLabel->setStyleSheet(QString("QLabel { font-size: 14px; color: %1; }").arg(color));
    } else {
        m_httpsLatencyLabel->setText("Failed");
        m_httpsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    }
}

void LatencyTestWidget::onTestCompleted()
{
    m_testInProgress = false;
    m_progressBar->setVisible(false);
    updateButtonStates();
    
    // Clean up thread safely
    if (m_workerThread && m_workerThread->isRunning()) {
        m_workerThread->quit();
        if (!m_workerThread->wait(5000)) {
            m_workerThread->terminate();
            m_workerThread->wait();
        }
    }
    
    // Schedule cleanup for next event loop iteration
    if (m_worker) {
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    
    if (m_workerThread) {
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}

void LatencyTestWidget::onTestError(const QString &error)
{
    qDebug() << "Latency test error:" << error;
    
    m_dnsLatencyLabel->setText("Error");
    m_udpLatencyLabel->setText("Error");
    m_httpsLatencyLabel->setText("Error");
    m_dnsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    m_udpLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    m_httpsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #cc0000; }");
    
    onTestCompleted();
}

void LatencyTestWidget::updateButtonStates()
{
    m_startButton->setEnabled(!m_testInProgress);
    m_cancelButton->setEnabled(m_testInProgress);
}

void LatencyTestWidget::resetResults()
{
    m_dnsLatencyLabel->setText("Testing...");
    m_udpLatencyLabel->setText("Waiting...");
    m_httpsLatencyLabel->setText("Waiting...");
    m_dnsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
    m_udpLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
    m_httpsLatencyLabel->setStyleSheet("QLabel { font-size: 14px; color: #666; }");
}

QString LatencyTestWidget::getLatencyColor(double latency, const QString &type)
{
    if (type == "dns") {
        if (latency < 50) return "#00aa00";      // Good - green
        else if (latency < 100) return "#ff8800"; // Moderate - orange
        else return "#cc0000";                    // High - red
    } else if (type == "udp") {
        if (latency < 100) return "#00aa00";     // Good - green
        else if (latency < 200) return "#ff8800"; // Moderate - orange
        else return "#cc0000";                    // High - red
    } else if (type == "https") {
        if (latency < 200) return "#00aa00";     // Good - green
        else if (latency < 500) return "#ff8800"; // Moderate - orange
        else return "#cc0000";                    // High - red
    }
    return "#666666"; // Default gray
}

// LatencyTestWorker implementation
LatencyTestWorker::LatencyTestWorker(QObject *parent)
    : QObject(parent)
    , m_cancelled(false)
    , m_process(nullptr)
    , m_currentTest(0)
    , m_dnsLatency(-1.0)
    , m_udpLatency(-1.0)
    , m_httpsLatency(-1.0)
{
}

void LatencyTestWorker::runLatencyTest()
{
    m_cancelled = false;
    m_currentTest = 0;
    m_dnsLatency = -1.0;
    m_udpLatency = -1.0;
    m_httpsLatency = -1.0;
    
    if (!m_cancelled) {
        runDnsTest();
    }
}

void LatencyTestWorker::runDnsTest()
{
    if (m_cancelled) return;
    
    qDebug() << "Starting DNS latency test via process...";
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &LatencyTestWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &LatencyTestWorker::onProcessError);
    
    // Find the latency_tool executable
    QString program = QCoreApplication::applicationDirPath() + "/latency_tool";
    QStringList arguments;
    arguments << "--dns-only";
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void LatencyTestWorker::runUdpTest()
{
    if (m_cancelled) return;
    
    qDebug() << "Starting UDP latency test via process...";
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &LatencyTestWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &LatencyTestWorker::onProcessError);
    
    QString program = QCoreApplication::applicationDirPath() + "/latency_tool";
    QStringList arguments;
    arguments << "--udp-only";
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void LatencyTestWorker::runHttpsTest()
{
    if (m_cancelled) return;
    
    qDebug() << "Starting HTTPS latency test via process...";
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &LatencyTestWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &LatencyTestWorker::onProcessError);
    
    QString program = QCoreApplication::applicationDirPath() + "/latency_tool";
    QStringList arguments;
    arguments << "--https-only";
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void LatencyTestWorker::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_cancelled) {
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    if (exitStatus == QProcess::CrashExit) {
        emit testError("Latency test process crashed");
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    QString output = m_process->readAllStandardOutput();
    qDebug() << "Process output:" << output;
    
    parseLatencyOutput(output);
    
    m_process->deleteLater();
    m_process = nullptr;
    
    // Emit result for current test
    if (m_currentTest == 0) {
        // DNS test completed
        emit dnsLatencyResult(m_dnsLatency);
        m_currentTest = 1;
        runUdpTest();
    } else if (m_currentTest == 1) {
        // UDP test completed
        emit udpLatencyResult(m_udpLatency);
        m_currentTest = 2;
        runHttpsTest();
    } else {
        // HTTPS test completed
        emit httpsLatencyResult(m_httpsLatency);
        emit testCompleted();
    }
}

void LatencyTestWorker::onProcessError(QProcess::ProcessError error)
{
    qDebug() << "Process error:" << error;
    emit testError(QString("Process error: %1").arg(error));
    
    if (m_process) {
        m_process->deleteLater();
        m_process = nullptr;
    }
}

void LatencyTestWorker::parseLatencyOutput(const QString &output)
{
    QRegularExpression dnsRegex("DNS_RESULT:([0-9.-]+)");
    QRegularExpression udpRegex("UDP_RESULT:([0-9.-]+)");
    QRegularExpression httpsRegex("HTTPS_RESULT:([0-9.-]+)");
    
    QRegularExpressionMatch dnsMatch = dnsRegex.match(output);
    if (dnsMatch.hasMatch()) {
        m_dnsLatency = dnsMatch.captured(1).toDouble();
        qDebug() << "Parsed DNS latency:" << m_dnsLatency;
    }
    
    QRegularExpressionMatch udpMatch = udpRegex.match(output);
    if (udpMatch.hasMatch()) {
        m_udpLatency = udpMatch.captured(1).toDouble();
        qDebug() << "Parsed UDP latency:" << m_udpLatency;
    }
    
    QRegularExpressionMatch httpsMatch = httpsRegex.match(output);
    if (httpsMatch.hasMatch()) {
        m_httpsLatency = httpsMatch.captured(1).toDouble();
        qDebug() << "Parsed HTTPS latency:" << m_httpsLatency;
    }
}

void LatencyTestWorker::cancelTest()
{
    m_cancelled = true;
    
    if (m_process && m_process->state() == QProcess::Running) {
        qDebug() << "Terminating latency test process...";
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
        }
    }
}