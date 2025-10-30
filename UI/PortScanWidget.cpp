#include "PortScanWidget.h"
#include <QGroupBox>
#include <QFont>
#include <QThread>
#include <QDebug>
#include <QProcess>
#include <QCoreApplication>
#include <QDir>
#include <QRegularExpression>
#include <QMessageBox>
#include <QApplication>

PortScanWidget::PortScanWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_configLayout(nullptr)
    , m_buttonLayout(nullptr)
    , m_targetLabel(nullptr)
    , m_targetEdit(nullptr)
    , m_scanTypeLabel(nullptr)
    , m_scanTypeCombo(nullptr)
    , m_startPortLabel(nullptr)
    , m_startPortSpin(nullptr)
    , m_endPortLabel(nullptr)
    , m_endPortSpin(nullptr)
    , m_startButton(nullptr)
    , m_cancelButton(nullptr)
    , m_clearButton(nullptr)
    , m_progressBar(nullptr)
    , m_statusLabel(nullptr)
    , m_resultsTable(nullptr)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_scanInProgress(false)
    , m_foundPorts(0)
{
    setupUI();
    updateButtonStates();
}

PortScanWidget::~PortScanWidget()
{
    if (m_workerThread && m_workerThread->isRunning()) {
        if (m_worker) {
            m_worker->cancelScan();
        }
        m_workerThread->quit();
        m_workerThread->wait(3000);
    }
}

void PortScanWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create main group box
    QGroupBox *portScanGroup = new QGroupBox("Network Port Scanner", this);
    QVBoxLayout *groupLayout = new QVBoxLayout(portScanGroup);
    
    // Configuration section
    QGroupBox *configGroup = new QGroupBox("Scan Configuration", this);
    m_configLayout = new QGridLayout(configGroup);
    
    // Target hostname/IP
    m_targetLabel = new QLabel("Target Host:", this);
    m_targetEdit = new QLineEdit("localhost", this);
    m_targetEdit->setPlaceholderText("Enter hostname or IP address");
    
    // Scan type selection
    m_scanTypeLabel = new QLabel("Scan Type:", this);
    m_scanTypeCombo = new QComboBox(this);
    m_scanTypeCombo->addItem("Common Ports (Fast)", "common");
    m_scanTypeCombo->addItem("Custom Range", "range");
    m_scanTypeCombo->addItem("Full Scan (All 65535 ports)", "full");
    
    // Port range controls
    m_startPortLabel = new QLabel("Start Port:", this);
    m_startPortSpin = new QSpinBox(this);
    m_startPortSpin->setRange(1, 65535);
    m_startPortSpin->setValue(80);
    m_startPortSpin->setEnabled(false);
    
    m_endPortLabel = new QLabel("End Port:", this);
    m_endPortSpin = new QSpinBox(this);
    m_endPortSpin->setRange(1, 65535);
    m_endPortSpin->setValue(443);
    m_endPortSpin->setEnabled(false);
    
    // Add to config layout
    m_configLayout->addWidget(m_targetLabel, 0, 0);
    m_configLayout->addWidget(m_targetEdit, 0, 1, 1, 3);
    m_configLayout->addWidget(m_scanTypeLabel, 1, 0);
    m_configLayout->addWidget(m_scanTypeCombo, 1, 1, 1, 3);
    m_configLayout->addWidget(m_startPortLabel, 2, 0);
    m_configLayout->addWidget(m_startPortSpin, 2, 1);
    m_configLayout->addWidget(m_endPortLabel, 2, 2);
    m_configLayout->addWidget(m_endPortSpin, 2, 3);
    
    // Button layout
    m_buttonLayout = new QHBoxLayout();
    
    m_startButton = new QPushButton("Start Scan", this);
    m_startButton->setMinimumHeight(35);
    m_startButton->setStyleSheet("QPushButton { font-weight: bold; background-color: #4CAF50; color: white; }");
    
    m_cancelButton = new QPushButton("Cancel", this);
    m_cancelButton->setMinimumHeight(35);
    m_cancelButton->setEnabled(false);
    
    m_clearButton = new QPushButton("Clear Results", this);
    m_clearButton->setMinimumHeight(35);
    
    m_buttonLayout->addWidget(m_startButton);
    m_buttonLayout->addWidget(m_cancelButton);
    m_buttonLayout->addWidget(m_clearButton);
    m_buttonLayout->addStretch();
    
    // Progress and status
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setMinimumHeight(25);
    
    m_statusLabel = new QLabel("Ready to scan", this);
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    
    // Results table
    m_resultsTable = new QTableWidget(this);
    m_resultsTable->setColumnCount(3);
    QStringList headers;
    headers << "Port" << "Service" << "Status";
    m_resultsTable->setHorizontalHeaderLabels(headers);
    
    // Configure table
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setSortingEnabled(true);
    m_resultsTable->setMinimumHeight(200);
    
    // Set column widths
    m_resultsTable->setColumnWidth(0, 80);  // Port
    m_resultsTable->setColumnWidth(1, 120); // Service
    
    // Add everything to group layout
    groupLayout->addWidget(configGroup);
    groupLayout->addLayout(m_buttonLayout);
    groupLayout->addWidget(m_progressBar);
    groupLayout->addWidget(m_statusLabel);
    groupLayout->addWidget(m_resultsTable);
    
    // Add group to main layout
    m_mainLayout->addWidget(portScanGroup);
    
    // Connect signals
    connect(m_startButton, &QPushButton::clicked, this, &PortScanWidget::startPortScan);
    connect(m_cancelButton, &QPushButton::clicked, this, &PortScanWidget::cancelPortScan);
    connect(m_clearButton, &QPushButton::clicked, this, &PortScanWidget::clearResults);
    connect(m_scanTypeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), 
            this, &PortScanWidget::onScanTypeChanged);
}

void PortScanWidget::startPortScan()
{
    if (m_scanInProgress) {
        return;
    }
    
    QString hostname = m_targetEdit->text().trimmed();
    if (hostname.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a target hostname or IP address.");
        return;
    }
    
    QString scanType = m_scanTypeCombo->currentData().toString();
    
    // Warn about full scan
    if (scanType == "full") {
        int ret = QMessageBox::question(this, "Full Port Scan Warning", 
            "A full port scan will test all 65,535 ports and may take a very long time.\n\n"
            "Are you sure you want to continue?",
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No);
        if (ret != QMessageBox::Yes) {
            return;
        }
    }
    
    // Validate port range for custom scan
    int startPort = m_startPortSpin->value();
    int endPort = m_endPortSpin->value();
    if (scanType == "range" && startPort > endPort) {
        QMessageBox::warning(this, "Invalid Port Range", "Start port must be less than or equal to end port.");
        return;
    }
    
    m_scanInProgress = true;
    m_foundPorts = 0;
    
    // Clear previous results
    m_resultsTable->setRowCount(0);
    
    resetResults();
    
    // Show progress bar
    m_progressBar->setVisible(true);
    m_progressBar->setValue(0); // Reset progress value
    if (scanType == "full") {
        m_progressBar->setRange(0, 100);
        m_progressBar->setValue(0);
    } else {
        m_progressBar->setRange(0, 0); // Indeterminate for common/range scans
    }
    
    updateButtonStates();
    
    // Update status
    QString statusText;
    if (scanType == "common") {
        statusText = QString("Scanning common ports on %1...").arg(hostname);
    } else if (scanType == "range") {
        statusText = QString("Scanning ports %1-%2 on %3...").arg(startPort).arg(endPort).arg(hostname);
    } else {
        statusText = QString("Scanning all 65,535 ports on %1...").arg(hostname);
    }
    m_statusLabel->setText(statusText);
    
    // Create worker thread
    m_workerThread = new QThread(this);
    m_worker = new PortScanWorker();
    m_worker->moveToThread(m_workerThread);
    
    // Connect worker signals
    connect(m_workerThread, &QThread::started, [this, hostname, scanType, startPort, endPort]() {
        m_worker->runPortScan(hostname, scanType, startPort, endPort);
    });
    connect(m_worker, &PortScanWorker::portFound, this, &PortScanWidget::onPortFound, Qt::QueuedConnection);
    connect(m_worker, &PortScanWorker::progressUpdate, this, &PortScanWidget::onProgressUpdate, Qt::QueuedConnection);
    connect(m_worker, &PortScanWorker::scanCompleted, this, &PortScanWidget::onScanCompleted, Qt::QueuedConnection);
    connect(m_worker, &PortScanWorker::scanError, this, &PortScanWidget::onScanError, Qt::QueuedConnection);
    
    // Start the thread
    m_workerThread->start();
}

void PortScanWidget::cancelPortScan()
{
    if (!m_scanInProgress) {
        return;
    }
    
    if (m_worker) {
        m_worker->cancelScan();
    }
    
    if (m_workerThread && m_workerThread->isRunning()) {
        m_workerThread->quit();
        if (!m_workerThread->wait(3000)) {
            m_workerThread->terminate();
            m_workerThread->wait();
        }
    }
    
    m_scanInProgress = false;
    m_progressBar->setVisible(false);
    m_statusLabel->setText("Scan cancelled");
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
}

void PortScanWidget::onScanTypeChanged()
{
    QString scanType = m_scanTypeCombo->currentData().toString();
    bool isRange = (scanType == "range");
    
    m_startPortLabel->setEnabled(isRange);
    m_startPortSpin->setEnabled(isRange);
    m_endPortLabel->setEnabled(isRange);
    m_endPortSpin->setEnabled(isRange);
}

void PortScanWidget::onPortFound(int port, const QString &service, const QString &status)
{
    m_foundPorts++;
    addPortToTable(port, service, status);
    
    // Update status
    m_statusLabel->setText(QString("Found %1 open ports...").arg(m_foundPorts));
}

void PortScanWidget::onProgressUpdate(float percentage)
{
    if (m_progressBar->maximum() > 0) {
        m_progressBar->setValue(static_cast<int>(percentage));
    }
    
    m_statusLabel->setText(QString("Scanning... %.1f%% complete (%1 ports found)")
                          .arg(percentage).arg(m_foundPorts));
}

void PortScanWidget::onScanCompleted(int totalFound)
{
    m_scanInProgress = false;
    m_progressBar->setVisible(false);
    updateButtonStates();
    
    QString statusText;
    if (totalFound > 0) {
        statusText = QString("Scan completed. Found %1 open ports.").arg(totalFound);
    } else {
        statusText = "Scan completed. No open ports found.";
    }
    m_statusLabel->setText(statusText);
    
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

void PortScanWidget::onScanError(const QString &error)
{
    qDebug() << "Port scan error:" << error;
    
    m_statusLabel->setText(QString("Error: %1").arg(error));
    m_statusLabel->setStyleSheet("QLabel { color: #cc0000; font-style: italic; }");
    
    onScanCompleted(0);
}

void PortScanWidget::clearResults()
{
    m_resultsTable->setRowCount(0);
    m_foundPorts = 0;
    m_statusLabel->setText("Ready to scan");
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    updateButtonStates(); // Update button states after clearing
}

void PortScanWidget::updateButtonStates()
{
    m_startButton->setEnabled(!m_scanInProgress);
    m_cancelButton->setEnabled(m_scanInProgress);
    m_clearButton->setEnabled(!m_scanInProgress && m_resultsTable->rowCount() > 0);
    
    // Disable configuration during scan
    m_targetEdit->setEnabled(!m_scanInProgress);
    m_scanTypeCombo->setEnabled(!m_scanInProgress);
    m_startPortSpin->setEnabled(!m_scanInProgress && m_scanTypeCombo->currentData().toString() == "range");
    m_endPortSpin->setEnabled(!m_scanInProgress && m_scanTypeCombo->currentData().toString() == "range");
}

void PortScanWidget::resetResults()
{
    m_statusLabel->setText("Starting scan...");
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    m_foundPorts = 0;
}

void PortScanWidget::addPortToTable(int port, const QString &service, const QString &status)
{
    int row = m_resultsTable->rowCount();
    m_resultsTable->insertRow(row);
    
    // Port number
    QTableWidgetItem *portItem = new QTableWidgetItem(QString::number(port));
    portItem->setData(Qt::UserRole, port); // For sorting
    m_resultsTable->setItem(row, 0, portItem);
    
    // Service name
    QTableWidgetItem *serviceItem = new QTableWidgetItem(service);
    m_resultsTable->setItem(row, 1, serviceItem);
    
    // Status
    QTableWidgetItem *statusItem = new QTableWidgetItem(status);
    if (status == "open") {
        statusItem->setForeground(QBrush(QColor("#00aa00"))); // Green for open
    } else {
        statusItem->setForeground(QBrush(QColor("#cc0000"))); // Red for closed/filtered
    }
    m_resultsTable->setItem(row, 2, statusItem);
    
    // Auto-scroll to show new results
    m_resultsTable->scrollToBottom();
}

// PortScanWorker implementation
PortScanWorker::PortScanWorker(QObject *parent)
    : QObject(parent)
    , m_cancelled(false)
    , m_process(nullptr)
    , m_totalFound(0)
{
}

void PortScanWorker::runPortScan(const QString &hostname, const QString &scanType, int startPort, int endPort)
{
    m_cancelled = false;
    m_currentScanType = scanType;
    m_totalFound = 0;
    
    if (m_cancelled) return;
    
    qDebug() << "Starting port scan via process...";
    qDebug() << "Hostname:" << hostname << "Type:" << scanType;
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &PortScanWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &PortScanWorker::onProcessError);
    connect(m_process, &QProcess::readyReadStandardOutput, this, &PortScanWorker::onProcessOutput);
    
    // Find the portscan_tool executable
    QString program = QCoreApplication::applicationDirPath() + "/portscan_tool";
    QStringList arguments;
    arguments << hostname;
    
    if (scanType == "common") {
        arguments << "--common-only";
    } else if (scanType == "range") {
        arguments << "--range" << QString::number(startPort) << QString::number(endPort);
    } else if (scanType == "full") {
        arguments << "--full";
    }
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void PortScanWorker::onProcessOutput()
{
    if (!m_process) return;
    
    QByteArray data = m_process->readAllStandardOutput();
    QString output = QString::fromUtf8(data);
    
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    for (const QString &line : lines) {
        parsePortScanOutput(line.trimmed());
    }
}

void PortScanWorker::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_cancelled) {
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    if (exitStatus == QProcess::CrashExit) {
        emit scanError("Port scan process crashed");
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    // Process any remaining output
    onProcessOutput();
    
    qDebug() << "Port scan process finished with exit code:" << exitCode;
    
    emit scanCompleted(m_totalFound);
    
    m_process->deleteLater();
    m_process = nullptr;
}

void PortScanWorker::onProcessError(QProcess::ProcessError error)
{
    qDebug() << "Process error:" << error;
    emit scanError(QString("Process error: %1").arg(error));
    
    if (m_process) {
        m_process->deleteLater();
        m_process = nullptr;
    }
}

void PortScanWorker::parsePortScanOutput(const QString &line)
{
    if (line.startsWith("OPEN_PORT:")) {
        // Parse: OPEN_PORT:port:service:status
        QStringList parts = line.split(':');
        if (parts.size() >= 4) {
            int port = parts[1].toInt();
            QString service = parts[2];
            QString status = parts[3];
            
            m_totalFound++;
            emit portFound(port, service, status);
        }
    } else if (line.startsWith("PROGRESS:")) {
        // Parse: PROGRESS:percentage
        QString percentStr = line.mid(9); // Remove "PROGRESS:"
        float percentage = percentStr.toFloat();
        emit progressUpdate(percentage);
    } else if (line.startsWith("SCAN_COMPLETE:")) {
        // Parse: SCAN_COMPLETE:total_found
        QString totalStr = line.mid(14); // Remove "SCAN_COMPLETE:"
        int total = totalStr.toInt();
        m_totalFound = total;
    } else if (line.startsWith("ERROR:")) {
        QString error = line.mid(6); // Remove "ERROR:"
        emit scanError(error);
    }
}

void PortScanWorker::cancelScan()
{
    m_cancelled = true;
    
    if (m_process && m_process->state() == QProcess::Running) {
        qDebug() << "Terminating port scan process...";
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
        }
    }
}