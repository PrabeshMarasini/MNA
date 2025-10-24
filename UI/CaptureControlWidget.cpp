#include "CaptureControlWidget.h"
#include "PacketCaptureController.h"
#include <QMessageBox>
#include <QDateTime>
#include <QDebug>
#include <QStyle>

CaptureControlWidget::CaptureControlWidget(QWidget *parent)
    : QWidget(parent)
    , m_captureController(nullptr)
    , m_startButton(nullptr)
    , m_stopButton(nullptr)
    , m_pauseButton(nullptr)
    , m_resetButton(nullptr)
    , m_statusLabel(nullptr)
    , m_interfaceLabel(nullptr)
    , m_activityIndicator(nullptr)
    , m_packetsReceivedLabel(nullptr)
    , m_packetsDroppedLabel(nullptr)
    , m_bytesReceivedLabel(nullptr)
    , m_captureRateLabel(nullptr)
    , m_captureTimeLabel(nullptr)
    , m_controlGroup(nullptr)
    , m_statusGroup(nullptr)
    , m_statisticsGroup(nullptr)
    , m_isCapturing(false)
    , m_isPaused(false)
    , m_packetsReceived(0)
    , m_packetsDropped(0)
    , m_bytesReceived(0)
    , m_statisticsTimer(new QTimer(this))
    , m_timeUpdateTimer(new QTimer(this))
    , m_lastPacketCount(0)
    , m_currentRate(0.0)
{
    setupUI();
    setupConnections();
    
    qDebug() << "CaptureControlWidget: Initialized";
}

CaptureControlWidget::~CaptureControlWidget()
{
    if (m_isCapturing) {
        stopCapture();
    }
}

void CaptureControlWidget::setCaptureController(PacketCaptureController *controller)
{
    if (m_captureController == controller) {
        return;
    }
    
    // Disconnect from old controller
    if (m_captureController) {
        disconnect(m_captureController, nullptr, this, nullptr);
    }
    
    m_captureController = controller;
    
    // Connect to new controller
    if (m_captureController) {
        connect(m_captureController, &PacketCaptureController::captureStatusChanged,
                this, &CaptureControlWidget::onCaptureStatusChanged);
        // TODO: Add captureStatistics signal to PacketCaptureController
        // connect(m_captureController, &PacketCaptureController::captureStatistics,
        //         this, &CaptureControlWidget::onCaptureStatistics);
        connect(m_captureController, &PacketCaptureController::captureError,
                this, &CaptureControlWidget::onCaptureError);
        
        // Update interface label
        m_interfaceLabel->setText(QString("Interface: %1").arg(m_captureController->getInterface()));
    }
    
    updateControlStates();
    
    qDebug() << "CaptureControlWidget: Controller set";
}

CaptureControlWidget::CaptureStats CaptureControlWidget::getCaptureStats() const
{
    CaptureStats stats;
    stats.packetsReceived = m_packetsReceived;
    stats.packetsDropped = m_packetsDropped;
    stats.bytesReceived = m_bytesReceived;
    stats.captureRate = m_currentRate;
    
    if (m_isCapturing && m_captureStartTime.isValid()) {
        stats.captureTime = m_captureStartTime.secsTo(QDateTime::currentDateTime());
    } else {
        stats.captureTime = 0;
    }
    
    return stats;
}

void CaptureControlWidget::startCapture()
{
    if (!m_captureController) {
        QMessageBox::warning(this, "No Controller", "No capture controller available");
        return;
    }
    
    if (m_isCapturing) {
        qWarning() << "CaptureControlWidget: Capture already in progress";
        return;
    }
    
    // Reset statistics
    m_packetsReceived = 0;
    m_packetsDropped = 0;
    m_bytesReceived = 0;
    m_currentRate = 0.0;
    m_lastPacketCount = 0;
    m_captureStartTime = QDateTime::currentDateTime();
    m_lastStatsUpdate = m_captureStartTime;
    
    // Start capture
    m_captureController->startCapture();
    
    // Start timers
    m_statisticsTimer->start(1000); // Update every second
    m_timeUpdateTimer->start(1000); // Update time every second
    
    // Update activity indicator
    m_activityIndicator->setRange(0, 0); // Indeterminate progress
    
    emit captureStarted();
    
    qDebug() << "CaptureControlWidget: Started capture";
}

void CaptureControlWidget::stopCapture()
{
    if (!m_isCapturing) {
        return;
    }
    
    if (m_captureController) {
        m_captureController->stopCapture();
    }
    
    // Stop timers
    m_statisticsTimer->stop();
    m_timeUpdateTimer->stop();
    
    // Reset activity indicator
    m_activityIndicator->setRange(0, 1);
    m_activityIndicator->setValue(0);
    
    emit captureStopped();
    
    qDebug() << "CaptureControlWidget: Stopped capture";
}

void CaptureControlWidget::pauseCapture()
{
    if (!m_isCapturing) {
        return;
    }
    
    m_isPaused = !m_isPaused;
    
    if (m_isPaused) {
        // Pause timers but keep capture running
        m_statisticsTimer->stop();
        m_timeUpdateTimer->stop();
        m_statusLabel->setText("Status: Paused");
        m_statusLabel->setStyleSheet("color: orange; font-weight: bold;");
    } else {
        // Resume timers
        m_statisticsTimer->start(1000);
        m_timeUpdateTimer->start(1000);
        m_statusLabel->setText("Status: Capturing");
        m_statusLabel->setStyleSheet("color: green; font-weight: bold;");
    }
    
    updateControlStates();
    emit capturePaused(m_isPaused);
    
    qDebug() << "CaptureControlWidget: Capture" << (m_isPaused ? "paused" : "resumed");
}

void CaptureControlWidget::resetStatistics()
{
    m_packetsReceived = 0;
    m_packetsDropped = 0;
    m_bytesReceived = 0;
    m_currentRate = 0.0;
    m_lastPacketCount = 0;
    
    if (m_isCapturing) {
        m_captureStartTime = QDateTime::currentDateTime();
        m_lastStatsUpdate = m_captureStartTime;
    }
    
    updateStatisticsDisplay();
    
    qDebug() << "CaptureControlWidget: Statistics reset";
}

void CaptureControlWidget::updateInterfaceStatus(const QString &interface, bool available)
{
    QString status = available ? "Available" : "Unavailable";
    QString color = available ? "green" : "red";
    
    m_interfaceLabel->setText(QString("Interface: %1 (%2)").arg(interface, status));
    m_interfaceLabel->setStyleSheet(QString("color: %1;").arg(color));
    
    // Update control availability
    m_startButton->setEnabled(available && !m_isCapturing);
    
    qDebug() << "CaptureControlWidget: Interface status updated -" << interface << status;
}

void CaptureControlWidget::onCaptureStatusChanged(bool capturing)
{
    m_isCapturing = capturing;
    
    if (capturing) {
        m_statusLabel->setText("Status: Capturing");
        m_statusLabel->setStyleSheet("color: green; font-weight: bold;");
    } else {
        m_statusLabel->setText("Status: Stopped");
        m_statusLabel->setStyleSheet("color: red; font-weight: bold;");
        m_isPaused = false;
    }
    
    updateControlStates();
    
    qDebug() << "CaptureControlWidget: Capture status changed to" << (capturing ? "capturing" : "stopped");
}

void CaptureControlWidget::onCaptureStatistics(int packetsReceived, int packetsDropped)
{
    m_packetsReceived = packetsReceived;
    m_packetsDropped = packetsDropped;
    
    // Calculate capture rate
    QDateTime now = QDateTime::currentDateTime();
    int timeDiff = m_lastStatsUpdate.msecsTo(now);
    
    if (timeDiff > 0) {
        int packetDiff = packetsReceived - m_lastPacketCount;
        m_currentRate = (packetDiff * 1000.0) / timeDiff; // packets per second
        
        m_lastPacketCount = packetsReceived;
        m_lastStatsUpdate = now;
    }
    
    updateStatisticsDisplay();
    emit statisticsUpdated(packetsReceived, m_bytesReceived, m_currentRate);
    
    qDebug() << "CaptureControlWidget: Statistics updated - packets:" << packetsReceived 
             << "dropped:" << packetsDropped << "rate:" << m_currentRate;
}

void CaptureControlWidget::onCaptureError(const QString &error)
{
    m_statusLabel->setText("Status: Error");
    m_statusLabel->setStyleSheet("color: red; font-weight: bold;");
    
    // Stop capture on error
    if (m_isCapturing) {
        stopCapture();
    }
    
    emit captureError(error);
    
    qWarning() << "CaptureControlWidget: Capture error -" << error;
}

void CaptureControlWidget::updateStatisticsDisplay()
{
    m_packetsReceivedLabel->setText(QString("Received: %1").arg(m_packetsReceived));
    m_packetsDroppedLabel->setText(QString("Dropped: %1").arg(m_packetsDropped));
    m_bytesReceivedLabel->setText(QString("Bytes: %1").arg(formatBytes(m_bytesReceived)));
    m_captureRateLabel->setText(QString("Rate: %1").arg(formatRate(m_currentRate)));
}

void CaptureControlWidget::updateCaptureTime()
{
    if (m_isCapturing && m_captureStartTime.isValid()) {
        int seconds = m_captureStartTime.secsTo(QDateTime::currentDateTime());
        m_captureTimeLabel->setText(QString("Time: %1").arg(formatDuration(seconds)));
    } else {
        m_captureTimeLabel->setText("Time: 00:00:00");
    }
}

void CaptureControlWidget::setupUI()
{
    setFixedHeight(200);
    setMinimumWidth(300);
    
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    mainLayout->setSpacing(5);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    
    // Control group
    m_controlGroup = new QGroupBox("Capture Control");
    QHBoxLayout *controlLayout = new QHBoxLayout(m_controlGroup);
    
    m_startButton = new QPushButton("Start");
    m_startButton->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    connect(m_startButton, &QPushButton::clicked, this, &CaptureControlWidget::startCapture);
    controlLayout->addWidget(m_startButton);
    
    m_stopButton = new QPushButton("Stop");
    m_stopButton->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    m_stopButton->setEnabled(false);
    connect(m_stopButton, &QPushButton::clicked, this, &CaptureControlWidget::stopCapture);
    controlLayout->addWidget(m_stopButton);
    
    m_pauseButton = new QPushButton("Pause");
    m_pauseButton->setIcon(style()->standardIcon(QStyle::SP_MediaPause));
    m_pauseButton->setEnabled(false);
    connect(m_pauseButton, &QPushButton::clicked, this, &CaptureControlWidget::pauseCapture);
    controlLayout->addWidget(m_pauseButton);
    
    m_resetButton = new QPushButton("Reset");
    m_resetButton->setIcon(style()->standardIcon(QStyle::SP_BrowserReload));
    connect(m_resetButton, &QPushButton::clicked, this, &CaptureControlWidget::resetStatistics);
    controlLayout->addWidget(m_resetButton);
    
    mainLayout->addWidget(m_controlGroup);
    
    // Status group
    m_statusGroup = new QGroupBox("Status");
    QVBoxLayout *statusLayout = new QVBoxLayout(m_statusGroup);
    
    m_statusLabel = new QLabel("Status: Stopped");
    m_statusLabel->setStyleSheet("color: red; font-weight: bold;");
    statusLayout->addWidget(m_statusLabel);
    
    m_interfaceLabel = new QLabel("Interface: None");
    statusLayout->addWidget(m_interfaceLabel);
    
    m_activityIndicator = new QProgressBar;
    m_activityIndicator->setRange(0, 1);
    m_activityIndicator->setValue(0);
    m_activityIndicator->setMaximumHeight(10);
    statusLayout->addWidget(m_activityIndicator);
    
    mainLayout->addWidget(m_statusGroup);
    
    // Statistics group
    m_statisticsGroup = new QGroupBox("Statistics");
    QGridLayout *statsLayout = new QGridLayout(m_statisticsGroup);
    
    m_packetsReceivedLabel = new QLabel("Received: 0");
    statsLayout->addWidget(m_packetsReceivedLabel, 0, 0);
    
    m_packetsDroppedLabel = new QLabel("Dropped: 0");
    statsLayout->addWidget(m_packetsDroppedLabel, 0, 1);
    
    m_bytesReceivedLabel = new QLabel("Bytes: 0");
    statsLayout->addWidget(m_bytesReceivedLabel, 1, 0);
    
    m_captureRateLabel = new QLabel("Rate: 0 pps");
    statsLayout->addWidget(m_captureRateLabel, 1, 1);
    
    m_captureTimeLabel = new QLabel("Time: 00:00:00");
    statsLayout->addWidget(m_captureTimeLabel, 2, 0, 1, 2);
    
    mainLayout->addWidget(m_statisticsGroup);
    
    qDebug() << "CaptureControlWidget: UI setup completed";
}

void CaptureControlWidget::setupConnections()
{
    // Setup timers
    connect(m_statisticsTimer, &QTimer::timeout, this, &CaptureControlWidget::updateStatisticsDisplay);
    connect(m_timeUpdateTimer, &QTimer::timeout, this, &CaptureControlWidget::updateCaptureTime);
    
    qDebug() << "CaptureControlWidget: Connections setup completed";
}

void CaptureControlWidget::updateControlStates()
{
    m_startButton->setEnabled(!m_isCapturing);
    m_stopButton->setEnabled(m_isCapturing);
    m_pauseButton->setEnabled(m_isCapturing);
    m_pauseButton->setText(m_isPaused ? "Resume" : "Pause");
    m_pauseButton->setIcon(style()->standardIcon(m_isPaused ? QStyle::SP_MediaPlay : QStyle::SP_MediaPause));
}

QString CaptureControlWidget::formatBytes(qint64 bytes) const
{
    const qint64 KB = 1024;
    const qint64 MB = KB * 1024;
    const qint64 GB = MB * 1024;
    
    if (bytes >= GB) {
        return QString("%1 GB").arg(bytes / (double)GB, 0, 'f', 2);
    } else if (bytes >= MB) {
        return QString("%1 MB").arg(bytes / (double)MB, 0, 'f', 2);
    } else if (bytes >= KB) {
        return QString("%1 KB").arg(bytes / (double)KB, 0, 'f', 2);
    } else {
        return QString("%1 B").arg(bytes);
    }
}

QString CaptureControlWidget::formatRate(double rate) const
{
    if (rate >= 1000.0) {
        return QString("%1 kpps").arg(rate / 1000.0, 0, 'f', 2);
    } else {
        return QString("%1 pps").arg(rate, 0, 'f', 1);
    }
}

QString CaptureControlWidget::formatDuration(int seconds) const
{
    int hours = seconds / 3600;
    int minutes = (seconds % 3600) / 60;
    int secs = seconds % 60;
    
    return QString("%1:%2:%3")
           .arg(hours, 2, 10, QChar('0'))
           .arg(minutes, 2, 10, QChar('0'))
           .arg(secs, 2, 10, QChar('0'));
}