#include "MacLookupWidget.h"
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
#include <QHeaderView>
#include <QTimer>
#include <QFile>

MacLookupWidget::MacLookupWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_tabWidget(nullptr)
    , m_manualTab(nullptr)
    , m_manualLayout(nullptr)
    , m_macLabel(nullptr)
    , m_macEdit(nullptr)
    , m_lookupButton(nullptr)
    , m_clearButton(nullptr)
    , m_scanTab(nullptr)
    , m_scanLayout(nullptr)
    , m_scanButton(nullptr)
    , m_progressBar(nullptr)
    , m_statusLabel(nullptr)
    , m_resultsTable(nullptr)
    , m_macWorkerThread(nullptr)
    , m_macWorker(nullptr)
    , m_scanWorkerThread(nullptr)
    , m_scanWorker(nullptr)
    , m_lookupInProgress(false)
    , m_scanInProgress(false)
    , m_foundDevices(0)
{
    setupUI();
    updateButtonStates();
}

MacLookupWidget::~MacLookupWidget()
{
    if (m_macWorkerThread && m_macWorkerThread->isRunning()) {
        if (m_macWorker) {
            m_macWorker->cancelLookup();
        }
        m_macWorkerThread->quit();
        m_macWorkerThread->wait(3000);
    }
    
    if (m_scanWorkerThread && m_scanWorkerThread->isRunning()) {
        if (m_scanWorker) {
            m_scanWorker->cancelScan();
        }
        m_scanWorkerThread->quit();
        m_scanWorkerThread->wait(3000);
    }
}

void MacLookupWidget::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create main group box
    QGroupBox *macLookupGroup = new QGroupBox("MAC Address Vendor Lookup", this);
    QVBoxLayout *groupLayout = new QVBoxLayout(macLookupGroup);
    
    // Create tab widget
    m_tabWidget = new QTabWidget(this);
    
    // Manual lookup tab
    m_manualTab = new QWidget();
    m_manualLayout = new QGridLayout(m_manualTab);
    
    m_macLabel = new QLabel("MAC Address:", this);
    m_macEdit = new QLineEdit(this);
    m_macEdit->setPlaceholderText("Enter MAC address (e.g., 00:1A:2B:3C:4D:5E)");
    
    m_lookupButton = new QPushButton("Lookup Vendor", this);
    m_lookupButton->setMinimumHeight(35);
    m_lookupButton->setStyleSheet("QPushButton { font-weight: bold; background-color: #4CAF50; color: white; }");
    
    m_clearButton = new QPushButton("Clear Results", this);
    m_clearButton->setMinimumHeight(35);
    
    m_manualLayout->addWidget(m_macLabel, 0, 0);
    m_manualLayout->addWidget(m_macEdit, 0, 1, 1, 2);
    m_manualLayout->addWidget(m_lookupButton, 1, 0);
    m_manualLayout->addWidget(m_clearButton, 1, 1);
    m_manualLayout->setColumnStretch(2, 1);
    
    m_tabWidget->addTab(m_manualTab, "Manual Lookup");
    
    // LAN scan tab
    m_scanTab = new QWidget();
    m_scanLayout = new QVBoxLayout(m_scanTab);
    
    QLabel *scanDescription = new QLabel("Scan your local network to discover devices and lookup their MAC address vendors:", this);
    scanDescription->setWordWrap(true);
    scanDescription->setStyleSheet("QLabel { color: #666; font-style: italic; margin-bottom: 10px; }");
    
    m_scanButton = new QPushButton("Scan LAN Devices", this);
    m_scanButton->setMinimumHeight(40);
    m_scanButton->setStyleSheet("QPushButton { font-weight: bold; background-color: #2196F3; color: white; }");
    
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setMinimumHeight(25);
    
    m_statusLabel = new QLabel("Ready to scan", this);
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    
    m_scanLayout->addWidget(scanDescription);
    m_scanLayout->addWidget(m_scanButton);
    m_scanLayout->addWidget(m_progressBar);
    m_scanLayout->addWidget(m_statusLabel);
    m_scanLayout->addStretch();
    
    m_tabWidget->addTab(m_scanTab, "LAN Scan");
    
    // Results table
    m_resultsTable = new QTableWidget(this);
    m_resultsTable->setColumnCount(3);
    QStringList headers;
    headers << "MAC Address" << "Vendor" << "IP Address";
    m_resultsTable->setHorizontalHeaderLabels(headers);
    
    // Configure table
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setSortingEnabled(true);
    m_resultsTable->setMinimumHeight(200);
    
    // Set column widths
    m_resultsTable->setColumnWidth(0, 150);  // MAC Address
    m_resultsTable->setColumnWidth(1, 200);  // Vendor
    
    // Add everything to group layout
    groupLayout->addWidget(m_tabWidget);
    groupLayout->addWidget(m_resultsTable);
    
    // Add group to main layout
    m_mainLayout->addWidget(macLookupGroup);
    
    // Connect signals
    connect(m_lookupButton, &QPushButton::clicked, this, &MacLookupWidget::lookupMacAddress);
    connect(m_clearButton, &QPushButton::clicked, this, &MacLookupWidget::clearResults);
    connect(m_scanButton, &QPushButton::clicked, this, &MacLookupWidget::scanLanDevices);
    connect(m_resultsTable, &QTableWidget::itemDoubleClicked, this, &MacLookupWidget::onTableItemDoubleClicked);
    
    // Enable return key for lookup
    connect(m_macEdit, &QLineEdit::returnPressed, this, &MacLookupWidget::lookupMacAddress);
}

void MacLookupWidget::lookupMacAddress()
{
    if (m_lookupInProgress) {
        return;
    }
    
    QString macAddress = m_macEdit->text().trimmed();
    if (macAddress.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a MAC address.");
        return;
    }
    
    if (!validateMacAddress(macAddress)) {
        QMessageBox::warning(this, "Invalid MAC Address", 
            "Please enter a valid MAC address in format XX:XX:XX:XX:XX:XX");
        return;
    }
    
    m_lookupInProgress = true;
    updateButtonStates();
    
    // Create worker thread
    m_macWorkerThread = new QThread(this);
    m_macWorker = new MacLookupWorker();
    m_macWorker->moveToThread(m_macWorkerThread);
    
    // Connect worker signals
    connect(m_macWorkerThread, &QThread::started, [this, macAddress]() {
        m_macWorker->lookupMac(macAddress);
    });
    connect(m_macWorker, &MacLookupWorker::macLookupResult, this, &MacLookupWidget::onMacLookupResult, Qt::QueuedConnection);
    connect(m_macWorker, &MacLookupWorker::macLookupError, this, &MacLookupWidget::onMacLookupError, Qt::QueuedConnection);
    
    // Start the thread
    m_macWorkerThread->start();
}

void MacLookupWidget::scanLanDevices()
{
    if (m_scanInProgress) {
        return;
    }
    
    int ret = QMessageBox::question(this, "LAN Scan", 
        "This will scan your local network for devices and lookup their MAC vendors.\n"
        "This may take a few minutes and requires network access.\n\n"
        "Continue?",
        QMessageBox::Yes | QMessageBox::No, QMessageBox::Yes);
    if (ret != QMessageBox::Yes) {
        return;
    }
    
    m_scanInProgress = true;
    m_foundDevices = 0;
    
    // Clear previous results
    m_resultsTable->setRowCount(0);
    
    // Show progress bar
    m_progressBar->setVisible(true);
    m_progressBar->setRange(0, 0); // Indeterminate
    m_statusLabel->setText("Scanning local network...");
    
    updateButtonStates();
    
    // Create worker thread
    m_scanWorkerThread = new QThread(this);
    m_scanWorker = new LanScanWorker();
    m_scanWorker->moveToThread(m_scanWorkerThread);
    
    // Connect worker signals
    connect(m_scanWorkerThread, &QThread::started, [this]() {
        m_scanWorker->scanLanDevices();
    });
    connect(m_scanWorker, &LanScanWorker::deviceFound, this, &MacLookupWidget::onDeviceFound, Qt::QueuedConnection);
    connect(m_scanWorker, &LanScanWorker::vendorFound, this, &MacLookupWidget::onVendorFound, Qt::QueuedConnection);
    connect(m_scanWorker, &LanScanWorker::scanCompleted, this, &MacLookupWidget::onLanScanCompleted, Qt::QueuedConnection);
    connect(m_scanWorker, &LanScanWorker::scanError, this, &MacLookupWidget::onLanScanError, Qt::QueuedConnection);
    
    // Start the thread
    m_scanWorkerThread->start();
}

void MacLookupWidget::clearResults()
{
    m_resultsTable->setRowCount(0);
    m_foundDevices = 0;
    m_statusLabel->setText("Ready to scan");
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    updateButtonStates();
}

void MacLookupWidget::onMacLookupResult(const QString &mac, const QString &vendor)
{
    addResultToTable(mac, vendor);
    
    m_lookupInProgress = false;
    updateButtonStates();
    
    // Clean up thread
    if (m_macWorkerThread && m_macWorkerThread->isRunning()) {
        m_macWorkerThread->quit();
        if (!m_macWorkerThread->wait(3000)) {
            m_macWorkerThread->terminate();
            m_macWorkerThread->wait();
        }
    }
    
    if (m_macWorker) {
        m_macWorker->deleteLater();
        m_macWorker = nullptr;
    }
    
    if (m_macWorkerThread) {
        m_macWorkerThread->deleteLater();
        m_macWorkerThread = nullptr;
    }
}

void MacLookupWidget::onMacLookupError(const QString &error)
{
    qDebug() << "MAC lookup error:" << error;
    
    QString mac = m_macEdit->text().trimmed();
    addResultToTable(mac, "Lookup failed: " + error);
    
    m_lookupInProgress = false;
    updateButtonStates();
    
    // Clean up thread
    if (m_macWorkerThread && m_macWorkerThread->isRunning()) {
        m_macWorkerThread->quit();
        if (!m_macWorkerThread->wait(3000)) {
            m_macWorkerThread->terminate();
            m_macWorkerThread->wait();
        }
    }
    
    if (m_macWorker) {
        m_macWorker->deleteLater();
        m_macWorker = nullptr;
    }
    
    if (m_macWorkerThread) {
        m_macWorkerThread->deleteLater();
        m_macWorkerThread = nullptr;
    }
}

void MacLookupWidget::onDeviceFound(const QString &ip, const QString &mac)
{
    m_foundDevices++;
    addResultToTable(mac, "Looking up...", ip);
    
    m_statusLabel->setText(QString("Found %1 devices, looking up vendors...").arg(m_foundDevices));
}

void MacLookupWidget::onVendorFound(const QString &mac, const QString &vendor)
{
    // Find the row with this MAC address and update the vendor column
    for (int row = 0; row < m_resultsTable->rowCount(); row++) {
        QTableWidgetItem *macItem = m_resultsTable->item(row, 0);
        if (macItem && macItem->text().toUpper() == mac.toUpper()) {
            QTableWidgetItem *vendorItem = m_resultsTable->item(row, 1);
            if (vendorItem) {
                vendorItem->setText(vendor);
                if (vendor == "Unknown vendor") {
                    vendorItem->setForeground(QBrush(QColor("#666666"))); // Gray for unknown
                } else {
                    vendorItem->setForeground(QBrush(QColor("#00aa00"))); // Green for success
                }
            }
            break;
        }
    }
}

void MacLookupWidget::onLanScanCompleted(int deviceCount)
{
    m_scanInProgress = false;
    m_progressBar->setVisible(false);
    updateButtonStates();
    
    QString statusText;
    if (deviceCount > 0) {
        statusText = QString("Scan completed. Found %1 devices.").arg(deviceCount);
    } else {
        statusText = "Scan completed. No devices found.";
    }
    m_statusLabel->setText(statusText);
    
    // Clean up thread
    if (m_scanWorkerThread && m_scanWorkerThread->isRunning()) {
        m_scanWorkerThread->quit();
        if (!m_scanWorkerThread->wait(5000)) {
            m_scanWorkerThread->terminate();
            m_scanWorkerThread->wait();
        }
    }
    
    if (m_scanWorker) {
        m_scanWorker->deleteLater();
        m_scanWorker = nullptr;
    }
    
    if (m_scanWorkerThread) {
        m_scanWorkerThread->deleteLater();
        m_scanWorkerThread = nullptr;
    }
}

void MacLookupWidget::onLanScanError(const QString &error)
{
    qDebug() << "LAN scan error:" << error;
    
    m_statusLabel->setText(QString("Error: %1").arg(error));
    m_statusLabel->setStyleSheet("QLabel { color: #cc0000; font-style: italic; }");
    
    onLanScanCompleted(0);
}

void MacLookupWidget::onTableItemDoubleClicked(QTableWidgetItem *item)
{
    if (!item) return;
    
    int row = item->row();
    QTableWidgetItem *macItem = m_resultsTable->item(row, 0);
    if (macItem) {
        QString mac = macItem->text();
        m_macEdit->setText(mac);
        m_tabWidget->setCurrentIndex(0); // Switch to manual tab
    }
}

void MacLookupWidget::updateButtonStates()
{
    m_lookupButton->setEnabled(!m_lookupInProgress && !m_scanInProgress);
    m_scanButton->setEnabled(!m_lookupInProgress && !m_scanInProgress);
    m_clearButton->setEnabled(!m_lookupInProgress && !m_scanInProgress && m_resultsTable->rowCount() > 0);
    
    // Disable input during operations
    m_macEdit->setEnabled(!m_lookupInProgress && !m_scanInProgress);
}

void MacLookupWidget::addResultToTable(const QString &mac, const QString &vendor, const QString &ip)
{
    int row = m_resultsTable->rowCount();
    m_resultsTable->insertRow(row);
    
    // MAC Address
    QTableWidgetItem *macItem = new QTableWidgetItem(mac.toUpper());
    m_resultsTable->setItem(row, 0, macItem);
    
    // Vendor
    QTableWidgetItem *vendorItem = new QTableWidgetItem(vendor);
    if (vendor.startsWith("Lookup failed") || vendor == "Looking up...") {
        vendorItem->setForeground(QBrush(QColor("#cc6600"))); // Orange for pending/error
    } else if (vendor == "Unknown vendor") {
        vendorItem->setForeground(QBrush(QColor("#666666"))); // Gray for unknown
    } else {
        vendorItem->setForeground(QBrush(QColor("#00aa00"))); // Green for success
    }
    m_resultsTable->setItem(row, 1, vendorItem);
    
    // IP Address
    QTableWidgetItem *ipItem = new QTableWidgetItem(ip);
    m_resultsTable->setItem(row, 2, ipItem);
    
    // Auto-scroll to show new results
    m_resultsTable->scrollToBottom();
}

bool MacLookupWidget::validateMacAddress(const QString &mac)
{
    QRegularExpression macRegex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return macRegex.match(mac).hasMatch();
}

void MacLookupWidget::resetResults()
{
    m_statusLabel->setText("Starting lookup...");
    m_statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
    m_foundDevices = 0;
}

// MacLookupWorker implementation
MacLookupWorker::MacLookupWorker(QObject *parent)
    : QObject(parent)
    , m_cancelled(false)
    , m_process(nullptr)
{
}

void MacLookupWorker::lookupMac(const QString &macAddress)
{
    m_cancelled = false;
    
    if (m_cancelled) return;
    
    qDebug() << "Starting MAC lookup via process...";
    qDebug() << "MAC Address:" << macAddress;
    
    m_process = new QProcess(this);
    connect(m_process, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &MacLookupWorker::onProcessFinished);
    connect(m_process, &QProcess::errorOccurred, this, &MacLookupWorker::onProcessError);
    
    // Find the mac_tool executable
    QString program = QCoreApplication::applicationDirPath() + "/mac_tool";
    QStringList arguments;
    arguments << macAddress;
    
    qDebug() << "Running:" << program << arguments;
    m_process->start(program, arguments);
}

void MacLookupWorker::onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_cancelled) {
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    if (exitStatus == QProcess::CrashExit) {
        emit macLookupError("MAC lookup process crashed");
        m_process->deleteLater();
        m_process = nullptr;
        return;
    }
    
    QString output = QString::fromUtf8(m_process->readAllStandardOutput());
    qDebug() << "MAC lookup process finished with exit code:" << exitCode;
    qDebug() << "Output:" << output;
    
    // Parse the output to extract MAC and vendor
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    QString mac, vendor;
    
    for (const QString &line : lines) {
        if (line.startsWith("MAC Address:")) {
            mac = line.mid(13).trimmed(); // Remove "MAC Address: "
        } else if (line.startsWith("Vendor:")) {
            vendor = line.mid(8).trimmed(); // Remove "Vendor: "
        }
    }
    
    if (!mac.isEmpty() && !vendor.isEmpty()) {
        emit macLookupResult(mac, vendor);
    } else {
        emit macLookupError("Could not parse MAC lookup result");
    }
    
    m_process->deleteLater();
    m_process = nullptr;
}

void MacLookupWorker::onProcessError(QProcess::ProcessError error)
{
    qDebug() << "Process error:" << error;
    emit macLookupError(QString("Process error: %1").arg(error));
    
    if (m_process) {
        m_process->deleteLater();
        m_process = nullptr;
    }
}

void MacLookupWorker::cancelLookup()
{
    m_cancelled = true;
    
    if (m_process && m_process->state() == QProcess::Running) {
        qDebug() << "Terminating MAC lookup process...";
        m_process->terminate();
        if (!m_process->waitForFinished(3000)) {
            m_process->kill();
        }
    }
}

// LanScanWorker implementation
LanScanWorker::LanScanWorker(QObject *parent)
    : QObject(parent)
    , m_cancelled(false)
    , m_lanScanProcess(nullptr)
    , m_macLookupProcess(nullptr)
    , m_currentLookupIndex(0)
    , m_totalDevices(0)
{
}

void LanScanWorker::scanLanDevices()
{
    m_cancelled = false;
    m_devices.clear();
    m_currentLookupIndex = 0;
    
    if (m_cancelled) return;
    
    qDebug() << "Starting LAN scan...";
    
    m_lanScanProcess = new QProcess(this);
    connect(m_lanScanProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &LanScanWorker::onLanScanFinished);
    connect(m_lanScanProcess, &QProcess::errorOccurred, this, &LanScanWorker::onLanScanError);
    
    // Change to the directory containing lan_scan.sh and run it
    QString program = "bash";
    QStringList arguments;
    // Try multiple possible paths for the script
    QString scriptPath = QCoreApplication::applicationDirPath() + "/../src/packetcapture/lan_scan.sh";
    if (!QFile::exists(scriptPath)) {
        scriptPath = QCoreApplication::applicationDirPath() + "/lan_scan.sh";
    }
    if (!QFile::exists(scriptPath)) {
        scriptPath = "src/packetcapture/lan_scan.sh";
    }
    arguments << scriptPath;
    
    qDebug() << "Running:" << program << arguments;
    m_lanScanProcess->start(program, arguments);
}

void LanScanWorker::onLanScanFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_cancelled) {
        m_lanScanProcess->deleteLater();
        m_lanScanProcess = nullptr;
        return;
    }
    
    if (exitStatus == QProcess::CrashExit) {
        emit scanError("LAN scan process crashed");
        m_lanScanProcess->deleteLater();
        m_lanScanProcess = nullptr;
        return;
    }
    
    QString output = QString::fromUtf8(m_lanScanProcess->readAllStandardOutput());
    qDebug() << "LAN scan finished with exit code:" << exitCode;
    
    parseLanScanOutput(output);
    
    m_lanScanProcess->deleteLater();
    m_lanScanProcess = nullptr;
    
    // Start MAC vendor lookups
    if (!m_devices.isEmpty()) {
        lookupNextMac();
    } else {
        emit scanCompleted(0);
    }
}

void LanScanWorker::onLanScanError(QProcess::ProcessError error)
{
    qDebug() << "LAN scan process error:" << error;
    emit scanError(QString("LAN scan error: %1").arg(error));
    
    if (m_lanScanProcess) {
        m_lanScanProcess->deleteLater();
        m_lanScanProcess = nullptr;
    }
}

void LanScanWorker::parseLanScanOutput(const QString &output)
{
    QStringList lines = output.split('\n', Qt::SkipEmptyParts);
    
    for (const QString &line : lines) {
        // Look for lines with IP and MAC format: "192.168.1.1    00:11:22:33:44:55"
        QRegularExpression deviceRegex(R"((\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:]{17}))");
        QRegularExpressionMatch match = deviceRegex.match(line);
        
        if (match.hasMatch()) {
            DeviceInfo device;
            device.ip = match.captured(1);
            device.mac = match.captured(2).toUpper();
            device.vendor = "Looking up...";
            
            m_devices.append(device);
            emit deviceFound(device.ip, device.mac);
        }
    }
    
    m_totalDevices = m_devices.size();
    qDebug() << "Found" << m_totalDevices << "devices";
}

void LanScanWorker::lookupNextMac()
{
    if (m_cancelled || m_currentLookupIndex >= m_devices.size()) {
        emit scanCompleted(m_totalDevices);
        return;
    }
    
    const DeviceInfo &device = m_devices[m_currentLookupIndex];
    
    m_macLookupProcess = new QProcess(this);
    connect(m_macLookupProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
            this, &LanScanWorker::onMacLookupFinished);
    connect(m_macLookupProcess, &QProcess::errorOccurred, this, &LanScanWorker::onMacLookupError);
    
    QString program = QCoreApplication::applicationDirPath() + "/mac_tool";
    QStringList arguments;
    arguments << device.mac;
    
    m_macLookupProcess->start(program, arguments);
}

void LanScanWorker::onMacLookupFinished(int exitCode, QProcess::ExitStatus exitStatus)
{
    if (m_cancelled) {
        if (m_macLookupProcess) {
            m_macLookupProcess->deleteLater();
            m_macLookupProcess = nullptr;
        }
        return;
    }
    
    QString vendor = "Unknown vendor";
    
    if (exitStatus != QProcess::CrashExit && m_macLookupProcess) {
        QString output = QString::fromUtf8(m_macLookupProcess->readAllStandardOutput());
        QStringList lines = output.split('\n', Qt::SkipEmptyParts);
        
        for (const QString &line : lines) {
            if (line.startsWith("Vendor:")) {
                vendor = line.mid(8).trimmed();
                break;
            }
        }
    }
    
    // Update the device info and emit the result
    if (m_currentLookupIndex < m_devices.size()) {
        DeviceInfo &device = m_devices[m_currentLookupIndex];
        device.vendor = vendor;
        emit vendorFound(device.mac, vendor);
    }
    
    if (m_macLookupProcess) {
        m_macLookupProcess->deleteLater();
        m_macLookupProcess = nullptr;
    }
    
    m_currentLookupIndex++;
    
    // Continue with next MAC or finish
    if (m_currentLookupIndex < m_devices.size()) {
        // Small delay between lookups to avoid overwhelming the API
        QTimer::singleShot(500, this, &LanScanWorker::lookupNextMac);
    } else {
        emit scanCompleted(m_totalDevices);
    }
}

void LanScanWorker::onMacLookupError(QProcess::ProcessError error)
{
    qDebug() << "MAC lookup process error:" << error;
    
    // Continue with next MAC even if this one failed
    if (m_macLookupProcess) {
        m_macLookupProcess->deleteLater();
        m_macLookupProcess = nullptr;
    }
    
    m_currentLookupIndex++;
    
    if (m_currentLookupIndex < m_devices.size()) {
        QTimer::singleShot(500, this, &LanScanWorker::lookupNextMac);
    } else {
        emit scanCompleted(m_totalDevices);
    }
}

void LanScanWorker::cancelScan()
{
    m_cancelled = true;
    
    if (m_lanScanProcess && m_lanScanProcess->state() == QProcess::Running) {
        m_lanScanProcess->terminate();
        if (!m_lanScanProcess->waitForFinished(3000)) {
            m_lanScanProcess->kill();
        }
    }
    
    if (m_macLookupProcess && m_macLookupProcess->state() == QProcess::Running) {
        m_macLookupProcess->terminate();
        if (!m_macLookupProcess->waitForFinished(3000)) {
            m_macLookupProcess->kill();
        }
    }
}