#include "SpeedTestWidget.h"
#include <QGroupBox>
#include <QGridLayout>
#include <QFont>
#include <QThread>
#include <QDebug>
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QRegularExpression>

SpeedTestWidget::SpeedTestWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_buttonLayout(nullptr)
    , m_resultsLayout(nullptr)
    , m_startButton(nullptr)
    , m_cancelButton(nullptr)
    , m_progressBar(nullptr)
    , m_downloadLabel(nullptr)
    , m_uploadLabel(nullptr)
    , m_downloadSpeedLabel(nullptr)
    , m_uploadSpeedLabel(nullptr)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_testInProgress(false)
{
    setupUI();
    updateButtonStates();
}

SpeedTestWidget::~SpeedTestWidget()
{
    if (m_workerThread && m_workerThread->isRunning()) {
        if (m_worker) {
            // Disconnect signals before cleanup to prevent race conditions
            disconnect(m_worker, nullptr, this, nullptr);
            m_worker->cancelTest();
        }
        m_workerThread->quit();
        if (!m_workerThread->wait(3000)) {
            m_workerThread->terminate();
            m_workerThread->wait(1000);
        }
    }
}

void SpeedTestWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create main group box
    QGroupBox *speedTestGroup = new QGroupBox("Internet Speed Test", this);
    QVBoxLayout *groupLayout = new QVBoxLayout(speedTestGroup);
    
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
    
    // Results layout
    m_resultsLayout = new QHBoxLayout();
    
    // Download section
    QVBoxLayout *downloadLayout = new QVBoxLayout();
    m_downloadLabel = new QLabel("Download Speed:", this);
    m_downloadLabel->setStyleSheet("QLabel { font-weight: bold; color: #333; }");
    
    m_downloadSpeedLabel = new QLabel("-- Mbps", this);
    m_downloadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #0066cc; }");
    QFont downloadFont = m_downloadSpeedLabel->font();
    downloadFont.setBold(true);
    m_downloadSpeedLabel->setFont(downloadFont);
    
    downloadLayout->addWidget(m_downloadLabel);
    downloadLayout->addWidget(m_downloadSpeedLabel);
    
    // Upload section  
    QVBoxLayout *uploadLayout = new QVBoxLayout();
    m_uploadLabel = new QLabel("Upload Speed:", this);
    m_uploadLabel->setStyleSheet("QLabel { font-weight: bold; color: #333; }");
    
    m_uploadSpeedLabel = new QLabel("-- Mbps", this);
    m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc6600; }");
    QFont uploadFont = m_uploadSpeedLabel->font();
    uploadFont.setBold(true);
    m_uploadSpeedLabel->setFont(uploadFont);
    
    uploadLayout->addWidget(m_uploadLabel);
    uploadLayout->addWidget(m_uploadSpeedLabel);
    
    m_resultsLayout->addLayout(downloadLayout);
    m_resultsLayout->addStretch();
    m_resultsLayout->addLayout(uploadLayout);
    
    // Add everything to group layout
    groupLayout->addLayout(m_buttonLayout);
    groupLayout->addWidget(m_progressBar);
    groupLayout->addLayout(m_resultsLayout);
    
    // Add group to main layout
    m_mainLayout->addWidget(speedTestGroup);
    m_mainLayout->addStretch();
    
    // Connect signals
    connect(m_startButton, &QPushButton::clicked, this, &SpeedTestWidget::startSpeedTest);
    connect(m_cancelButton, &QPushButton::clicked, this, &SpeedTestWidget::cancelSpeedTest);
}

void SpeedTestWidget::startSpeedTest()
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
    m_worker = new SpeedTestWorker();
    m_worker->moveToThread(m_workerThread);
    
    // Connect worker signals
    connect(m_workerThread, &QThread::started, m_worker, &SpeedTestWorker::runSpeedTest);
    connect(m_worker, &SpeedTestWorker::downloadSpeedResult, this, &SpeedTestWidget::onDownloadSpeedResult, Qt::QueuedConnection);
    connect(m_worker, &SpeedTestWorker::uploadSpeedResult, this, &SpeedTestWidget::onUploadSpeedResult, Qt::QueuedConnection);
    connect(m_worker, &SpeedTestWorker::testCompleted, this, &SpeedTestWidget::onTestCompleted, Qt::QueuedConnection);
    connect(m_worker, &SpeedTestWorker::testError, this, &SpeedTestWidget::onTestError, Qt::QueuedConnection);
    
    // Start the thread
    m_workerThread->start();
}

void SpeedTestWidget::cancelSpeedTest()
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
    
    // Clean up - disconnect signals first to prevent race conditions
    if (m_worker) {
        disconnect(m_worker, nullptr, this, nullptr);
        m_worker->deleteLater();
        m_worker = nullptr;
    }
    
    if (m_workerThread) {
        m_workerThread->deleteLater();
        m_workerThread = nullptr;
    }
}

void SpeedTestWidget::onDownloadSpeedResult(double speed)
{
    qDebug() << "Received download speed result:" << speed;
    if (speed > 0) {
        QString speedText = QString("%1 Mbps").arg(speed, 0, 'f', 2);
        qDebug() << "Setting download speed text to:" << speedText;
        m_downloadSpeedLabel->setText(speedText);
    } else {
        m_downloadSpeedLabel->setText("Failed");
        m_downloadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc0000; }");
    }
}

void SpeedTestWidget::onUploadSpeedResult(double speed)
{
    qDebug() << "Received upload speed result:" << speed;
    if (speed == -1) {
        // Upload testing started or failed
        if (m_uploadSpeedLabel->text() == "Waiting...") {
            m_uploadSpeedLabel->setText("Testing...");
            m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc6600; }");
        } else {
            m_uploadSpeedLabel->setText("Failed");
            m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc0000; }");
        }
    } else if (speed > 0) {
        QString speedText = QString("%1 Mbps").arg(speed, 0, 'f', 2);
        qDebug() << "Setting upload speed text to:" << speedText;
        m_uploadSpeedLabel->setText(speedText);
        m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc6600; }");
    } else {
        m_uploadSpeedLabel->setText("Failed");
        m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc0000; }");
    }
}

void SpeedTestWidget::onTestCompleted()
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

void SpeedTestWidget::onTestError(const QString &error)
{
    qDebug() << "Speed test error:" << error;
    
    m_downloadSpeedLabel->setText("Error");
    m_uploadSpeedLabel->setText("Error");
    m_downloadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc0000; }");
    m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc0000; }");
    
    onTestCompleted();
}

void SpeedTestWidget::updateButtonStates()
{
    m_startButton->setEnabled(!m_testInProgress);
    m_cancelButton->setEnabled(m_testInProgress);
}

void SpeedTestWidget::resetResults()
{
    m_downloadSpeedLabel->setText("Testing...");
    m_uploadSpeedLabel->setText("Waiting...");
    m_downloadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #0066cc; }");
    m_uploadSpeedLabel->setStyleSheet("QLabel { font-size: 16px; color: #cc6600; }");
}

// SpeedTestWorker implementation
SpeedTestWorker::SpeedTestWorker(QObject *parent)
    : QObject(parent)
    , m_cancelled(false)
    , m_cleanupInProgress(false)
    , m_process(nullptr)
    , m_downloadCompleted(false)
    , m_downloadSpeed(-1.0)
    , m_uploadSpeed(-1.0)
{
}

SpeedTestWorker::~SpeedTestWorker()
{
    m_cleanupInProgress = true;
    cleanupProcess();
}

void SpeedTestWorker::runSpeedTest()
{
    m_cancelled = false;
    m_downloadCompleted = false;
    m_downloadSpeed = -1.0;
    m_uploadSpeed = -1.0;
    
    if (!m_cancelled) {
        runDownloadTest();
    }
}

void SpeedTestWorker::runDownloadTest()
{
    if (m_cancelled) return;
    
    qDebug() << "Starting download speed test via process...";
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &SpeedTestWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &SpeedTestWorker::onProcessError);
    
    // Find the speedtest_tool executable
    QString program = QCoreApplication::applicationDirPath() + "/speedtest_tool";
    QStringList arguments;
    arguments << "--download-only";
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void SpeedTestWorker::runUploadTest()
{
    if (m_cancelled) return;
    
    qDebug() << "Starting upload speed test via process...";
    emit uploadSpeedResult(-1); // Signal upload testing started
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &SpeedTestWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &SpeedTestWorker::onProcessError);
    
    QString program = QCoreApplication::applicationDirPath() + "/speedtest_tool";
    QStringList arguments;
    arguments << "--upload-only";
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void SpeedTestWorker::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    // Safety check: don't process if cleanup is in progress
    if (m_cleanupInProgress || m_cancelled) {
        cleanupProcess();
        return;
    }
    
    if (exitStatus == QProcess::CrashExit) {
        emit testError("Speed test process crashed");
        cleanupProcess();
        return;
    }
    
    if (!m_process) {
        qWarning() << "Process finished but m_process is null";
        return;
    }
    
    QString output = m_process->readAllStandardOutput();
    qDebug() << "Process output:" << output;
    
    parseSpeedTestOutput(output);
    
    cleanupProcess();
    
    if (!m_downloadCompleted) {
        // Download test completed
        m_downloadCompleted = true;
        if (m_downloadSpeed >= 0) {
            emit downloadSpeedResult(m_downloadSpeed);
        } else {
            emit downloadSpeedResult(-1); // Failed
        }
        
        // Start upload test
        runUploadTest();
    } else {
        // Upload test completed
        if (m_uploadSpeed >= 0) {
            emit uploadSpeedResult(m_uploadSpeed);
        } else {
            emit uploadSpeedResult(-1); // Failed
        }
        
        emit testCompleted();
    }
}

void SpeedTestWorker::onProcessError(QProcess::ProcessError error)
{
    // Safety check: don't process if cleanup is in progress
    if (m_cleanupInProgress) {
        return;
    }
    
    qDebug() << "Process error:" << error;
    emit testError(QString("Process error: %1").arg(error));
    
    cleanupProcess();
}

void SpeedTestWorker::parseSpeedTestOutput(const QString &output)
{
    QRegularExpression downloadRegex("DOWNLOAD_RESULT:([0-9.]+)");
    QRegularExpression uploadRegex("UPLOAD_RESULT:([0-9.]+)");
    
    QRegularExpressionMatch downloadMatch = downloadRegex.match(output);
    if (downloadMatch.hasMatch()) {
        m_downloadSpeed = downloadMatch.captured(1).toDouble();
        qDebug() << "Parsed download speed:" << m_downloadSpeed;
    }
    
    QRegularExpressionMatch uploadMatch = uploadRegex.match(output);
    if (uploadMatch.hasMatch()) {
        m_uploadSpeed = uploadMatch.captured(1).toDouble();
        qDebug() << "Parsed upload speed:" << m_uploadSpeed;
    }
}

void SpeedTestWorker::cancelTest()
{
    m_cancelled = true;
    m_cleanupInProgress = true;
    
    if (m_process && m_process->state() == QProcess::Running) {
        qDebug() << "Terminating speed test process...";
        // Disconnect signals before terminating to prevent race conditions
        disconnect(m_process, nullptr, this, nullptr);
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
        }
    }
    
    cleanupProcess();
}

void SpeedTestWorker::cleanupProcess()
{
    if (m_process) {
        // Disconnect all signals to prevent further callbacks
        disconnect(m_process, nullptr, this, nullptr);
        
        // Safe deletion
        m_process->deleteLater();
        m_process = nullptr;
    }
}