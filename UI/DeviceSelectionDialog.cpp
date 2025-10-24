#include "DeviceSelectionDialog.h"
#include "DeviceDiscoveryController.h"
#include "ARPSpoofingController.h"
#include <QMessageBox>
#include <QCloseEvent>
#include <QApplication>
#include <QNetworkInterface>
#include <QTimer>

DeviceSelectionDialog::DeviceSelectionDialog(QWidget *parent)
    : QDialog(parent)
    , discoveryController(nullptr)
    , spoofingController(nullptr)
    , spoofingActive(false)
    , discoveryInProgress(false)
{
    setWindowTitle("Device Selection & ARP Spoofing");
    setModal(true);
    resize(600, 500);
    
    setupUI();
    
    // Initialize controllers
    discoveryController = new DeviceDiscoveryController(this);
    spoofingController = new ARPSpoofingController(this);
    
    // Connect signals
    connect(discoveryController, &DeviceDiscoveryController::deviceDiscovered,
            this, &DeviceSelectionDialog::onDeviceDiscovered);
    connect(discoveryController, &DeviceDiscoveryController::discoveryCompleted,
            this, &DeviceSelectionDialog::onDiscoveryCompleted);
    connect(discoveryController, &DeviceDiscoveryController::discoveryError,
            this, &DeviceSelectionDialog::onDiscoveryError);
    
    connect(spoofingController, &ARPSpoofingController::spoofingStatusChanged,
            this, &DeviceSelectionDialog::onSpoofingStatusChanged);
    connect(spoofingController, &ARPSpoofingController::spoofingError,
            this, &DeviceSelectionDialog::onSpoofingError);
    connect(spoofingController, &ARPSpoofingController::targetPacketCaptured,
            this, &DeviceSelectionDialog::spoofedPacketCaptured, Qt::QueuedConnection);
    
    populateInterfaces();
    updateButtonStates();
}

DeviceSelectionDialog::~DeviceSelectionDialog()
{
    if (spoofingActive) {
        spoofingController->stopSpoofing();
    }
}

void DeviceSelectionDialog::setupUI()
{
    mainLayout = new QVBoxLayout(this);
    
    // Interface selection group
    interfaceGroup = new QGroupBox("Network Interface", this);
    QHBoxLayout *interfaceLayout = new QHBoxLayout(interfaceGroup);
    
    interfaceCombo = new QComboBox(this);
    scanButton = new QPushButton("Scan Network", this);
    
    interfaceLayout->addWidget(new QLabel("Interface:", this));
    interfaceLayout->addWidget(interfaceCombo);
    interfaceLayout->addWidget(scanButton);
    
    // Device selection group
    setupDeviceTable();
    
    // Control buttons group
    setupControlButtons();
    
    // Status area
    setupStatusArea();
    
    // Add to main layout
    mainLayout->addWidget(interfaceGroup);
    mainLayout->addWidget(deviceGroup);
    mainLayout->addWidget(controlGroup);
    mainLayout->addWidget(progressBar);
    mainLayout->addWidget(statusLabel);
    
    // Connect button signals
    connect(scanButton, &QPushButton::clicked, this, &DeviceSelectionDialog::onScanButtonClicked);
    connect(selectAllButton, &QPushButton::clicked, this, &DeviceSelectionDialog::onSelectAllClicked);
    connect(selectNoneButton, &QPushButton::clicked, this, &DeviceSelectionDialog::onSelectNoneClicked);
    connect(startSpoofingButton, &QPushButton::clicked, this, &DeviceSelectionDialog::onStartSpoofingClicked);
    connect(stopSpoofingButton, &QPushButton::clicked, this, &DeviceSelectionDialog::onStopSpoofingClicked);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::close);
}

void DeviceSelectionDialog::setupDeviceTable()
{
    deviceGroup = new QGroupBox("Discovered Devices", this);
    QVBoxLayout *deviceLayout = new QVBoxLayout(deviceGroup);
    
    deviceTable = new QTableWidget(0, ColumnCount, this);
    deviceTable->setHorizontalHeaderLabels(QStringList() << "Select" << "IP Address" << "MAC Address" << "Type");
    deviceTable->horizontalHeader()->setStretchLastSection(true);
    deviceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    deviceTable->setAlternatingRowColors(true);
    
    // Set column widths
    deviceTable->setColumnWidth(SelectColumn, 60);
    deviceTable->setColumnWidth(IPColumn, 120);
    deviceTable->setColumnWidth(MACColumn, 140);
    
    QHBoxLayout *selectionLayout = new QHBoxLayout();
    selectAllButton = new QPushButton("Select All", this);
    selectNoneButton = new QPushButton("Select None", this);
    selectionCountLabel = new QLabel("0 devices selected", this);
    
    selectionLayout->addWidget(selectAllButton);
    selectionLayout->addWidget(selectNoneButton);
    selectionLayout->addStretch();
    selectionLayout->addWidget(selectionCountLabel);
    
    deviceLayout->addWidget(deviceTable);
    deviceLayout->addLayout(selectionLayout);
}

void DeviceSelectionDialog::setupControlButtons()
{
    controlGroup = new QGroupBox("ARP Spoofing Control", this);
    QHBoxLayout *controlLayout = new QHBoxLayout(controlGroup);
    
    startSpoofingButton = new QPushButton("Start Spoofing", this);
    stopSpoofingButton = new QPushButton("Stop Spoofing", this);
    closeButton = new QPushButton("Close", this);
    
    startSpoofingButton->setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; }");
    stopSpoofingButton->setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; }");
    
    controlLayout->addWidget(startSpoofingButton);
    controlLayout->addWidget(stopSpoofingButton);
    controlLayout->addStretch();
    controlLayout->addWidget(closeButton);
}

void DeviceSelectionDialog::setupStatusArea()
{
    progressBar = new QProgressBar(this);
    progressBar->setVisible(false);
    
    statusLabel = new QLabel("Ready to scan network", this);
    statusLabel->setStyleSheet("QLabel { color: #666; font-style: italic; }");
}

void DeviceSelectionDialog::populateInterfaces()
{
    interfaceCombo->clear();
    
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface &interface : interfaces) {
        if (interface.flags() & QNetworkInterface::IsUp &&
            interface.flags() & QNetworkInterface::IsRunning &&
            !(interface.flags() & QNetworkInterface::IsLoopBack)) {
            interfaceCombo->addItem(interface.name());
        }
    }
    
    // Set default interface if available
    if (interfaceCombo->count() > 0) {
        currentInterface = interfaceCombo->currentText();
    }
}

void DeviceSelectionDialog::onScanButtonClicked()
{
    if (discoveryInProgress) {
        return;
    }
    
    currentInterface = interfaceCombo->currentText();
    if (currentInterface.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select a network interface.");
        return;
    }
    
    clearDeviceList();
    setDiscoveryInProgress(true);
    statusLabel->setText("Scanning network for devices...");
    
    discoveryController->startDiscovery(currentInterface);
}

void DeviceSelectionDialog::onSelectAllClicked()
{
    for (int row = 0; row < deviceTable->rowCount(); ++row) {
        QCheckBox *checkBox = qobject_cast<QCheckBox*>(deviceTable->cellWidget(row, SelectColumn));
        if (checkBox) {
            checkBox->setChecked(true);
        }
    }
    updateSelectionCount();
}

void DeviceSelectionDialog::onSelectNoneClicked()
{
    for (int row = 0; row < deviceTable->rowCount(); ++row) {
        QCheckBox *checkBox = qobject_cast<QCheckBox*>(deviceTable->cellWidget(row, SelectColumn));
        if (checkBox) {
            checkBox->setChecked(false);
        }
    }
    updateSelectionCount();
}

void DeviceSelectionDialog::onStartSpoofingClicked()
{
    QList<QString> selectedIPs = getSelectedDeviceIPs();
    if (selectedIPs.isEmpty()) {
        QMessageBox::warning(this, "Warning", "Please select at least one device to spoof.");
        return;
    }
    
    if (currentInterface.isEmpty()) {
        QMessageBox::warning(this, "Warning", "No network interface selected.");
        return;
    }
    
    statusLabel->setText("Starting ARP spoofing...");
    spoofingController->startSpoofing(selectedIPs, currentInterface);
}

void DeviceSelectionDialog::onStopSpoofingClicked()
{
    statusLabel->setText("Stopping ARP spoofing... Please wait");
    stopSpoofingButton->setEnabled(false);
    
    // Show progress indicator
    progressBar->setVisible(true);
    progressBar->setRange(0, 0); // Indeterminate
    
    // Set timeout for stop operation
    QTimer::singleShot(8000, this, [this]() {
        if (spoofingActive) {
            statusLabel->setText("Stop operation timed out - forcing stop");
            spoofingActive = false;
            updateButtonStates();
            progressBar->setVisible(false);
        }
    });
    
    spoofingController->stopSpoofing();
}

void DeviceSelectionDialog::onDeviceDiscovered(const NetworkDevice &device)
{
    discoveredDevices.append(device);
    addDeviceToTable(device);
    updateSelectionCount();
}

void DeviceSelectionDialog::onDiscoveryCompleted(int deviceCount)
{
    setDiscoveryInProgress(false);
    statusLabel->setText(QString("Discovery completed. Found %1 devices.").arg(deviceCount));
    updateButtonStates();
}

void DeviceSelectionDialog::onDiscoveryError(const QString &error)
{
    setDiscoveryInProgress(false);
    statusLabel->setText("Discovery failed: " + error);
    QMessageBox::critical(this, "Discovery Error", "Failed to discover devices:\n" + error);
}

void DeviceSelectionDialog::onSpoofingStatusChanged(bool active)
{
    spoofingActive = active;
    progressBar->setVisible(false); // Hide progress when operation completes
    updateButtonStates();
    
    if (active) {
        statusLabel->setText("ARP spoofing is active");
        emit spoofingStarted(getSelectedDeviceIPs(), currentInterface);
        
        // Hide dialog when spoofing starts successfully
        hide();
        printf("[DEBUG] DeviceSelectionDialog: Hidden dialog after spoofing started\n");
    } else {
        statusLabel->setText("ARP spoofing stopped successfully");
        emit spoofingStopped();
        
        // Show dialog when spoofing stops
        show();
        raise();
        activateWindow();
        printf("[DEBUG] DeviceSelectionDialog: Shown dialog after spoofing stopped\n");
    }
}

void DeviceSelectionDialog::onSpoofingError(const QString &error)
{
    statusLabel->setText("Spoofing error: " + error);
    QMessageBox::critical(this, "Spoofing Error", "ARP spoofing failed:\n" + error);
}

void DeviceSelectionDialog::onDeviceSelectionToggled()
{
    updateSelectionCount();
    updateButtonStates();
    emit deviceSelectionChanged();
}

void DeviceSelectionDialog::clearDeviceList()
{
    discoveredDevices.clear();
    deviceTable->setRowCount(0);
    updateSelectionCount();
}

void DeviceSelectionDialog::addDeviceToTable(const NetworkDevice &device)
{
    int row = deviceTable->rowCount();
    deviceTable->insertRow(row);
    
    // Selection checkbox
    QCheckBox *checkBox = new QCheckBox();
    connect(checkBox, &QCheckBox::toggled, this, &DeviceSelectionDialog::onDeviceSelectionToggled);
    deviceTable->setCellWidget(row, SelectColumn, checkBox);
    
    // IP Address
    deviceTable->setItem(row, IPColumn, new QTableWidgetItem(device.ipAddress));
    
    // MAC Address
    deviceTable->setItem(row, MACColumn, new QTableWidgetItem(device.macAddress));
    
    // Device Type
    QString type = device.isGateway ? "Gateway" : "Device";
    QTableWidgetItem *typeItem = new QTableWidgetItem(type);
    if (device.isGateway) {
        typeItem->setBackground(QColor(255, 235, 59, 100)); // Light yellow for gateway
    }
    deviceTable->setItem(row, TypeColumn, typeItem);
    
    // Make items read-only except checkbox
    deviceTable->item(row, IPColumn)->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
    deviceTable->item(row, MACColumn)->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
    deviceTable->item(row, TypeColumn)->setFlags(Qt::ItemIsEnabled | Qt::ItemIsSelectable);
}

void DeviceSelectionDialog::updateSelectionCount()
{
    int selectedCount = 0;
    for (int row = 0; row < deviceTable->rowCount(); ++row) {
        QCheckBox *checkBox = qobject_cast<QCheckBox*>(deviceTable->cellWidget(row, SelectColumn));
        if (checkBox && checkBox->isChecked()) {
            selectedCount++;
        }
    }
    
    selectionCountLabel->setText(QString("%1 device(s) selected").arg(selectedCount));
}

void DeviceSelectionDialog::updateButtonStates()
{
    bool hasDevices = deviceTable->rowCount() > 0;
    bool hasSelection = !getSelectedDeviceIPs().isEmpty();
    
    selectAllButton->setEnabled(hasDevices && !discoveryInProgress);
    selectNoneButton->setEnabled(hasDevices && !discoveryInProgress);
    startSpoofingButton->setEnabled(hasSelection && !spoofingActive && !discoveryInProgress);
    stopSpoofingButton->setEnabled(spoofingActive);
    scanButton->setEnabled(!discoveryInProgress && !spoofingActive);
    interfaceCombo->setEnabled(!discoveryInProgress && !spoofingActive);
}

void DeviceSelectionDialog::setDiscoveryInProgress(bool inProgress)
{
    discoveryInProgress = inProgress;
    progressBar->setVisible(inProgress);
    if (inProgress) {
        progressBar->setRange(0, 0); // Indeterminate progress
    }
    updateButtonStates();
}

QList<QString> DeviceSelectionDialog::getSelectedDeviceIPs() const
{
    QList<QString> selectedIPs;
    for (int row = 0; row < deviceTable->rowCount(); ++row) {
        QCheckBox *checkBox = qobject_cast<QCheckBox*>(deviceTable->cellWidget(row, SelectColumn));
        if (checkBox && checkBox->isChecked()) {
            QTableWidgetItem *ipItem = deviceTable->item(row, IPColumn);
            if (ipItem) {
                selectedIPs.append(ipItem->text());
            }
        }
    }
    return selectedIPs;
}

QString DeviceSelectionDialog::getSelectedInterface() const
{
    return currentInterface;
}

bool DeviceSelectionDialog::isSpoofingActive() const
{
    return spoofingActive;
}

void DeviceSelectionDialog::startDeviceDiscovery()
{
    onScanButtonClicked();
}

void DeviceSelectionDialog::stopSpoofing()
{
    if (spoofingActive) {
        onStopSpoofingClicked();
    }
}

QList<QString> DeviceSelectionDialog::getMACsForIPs(const QList<QString> &targetIPs) const
{
    QList<QString> targetMACs;
    
    for (const QString &targetIP : targetIPs) {
        for (const NetworkDevice &device : discoveredDevices) {
            if (device.ipAddress == targetIP) {
                targetMACs.append(device.macAddress);
                break;
            }
        }
    }
    
    qDebug() << "DeviceSelectionDialog: Found" << targetMACs.size() << "MAC addresses for" << targetIPs.size() << "IPs";
    return targetMACs;
}

ARPSpoofingController* DeviceSelectionDialog::getSpoofingController() const
{
    return spoofingController;
}

void DeviceSelectionDialog::closeEvent(QCloseEvent *event)
{
    if (spoofingActive) {
        QMessageBox::StandardButton reply = QMessageBox::question(this, 
            "ARP Spoofing Active", 
            "ARP spoofing is currently active. Stop spoofing before closing?",
            QMessageBox::Yes | QMessageBox::No | QMessageBox::Cancel);
        
        if (reply == QMessageBox::Yes) {
            spoofingController->stopSpoofing();
            event->accept();
        } else if (reply == QMessageBox::No) {
            event->accept();
        } else {
            event->ignore();
        }
    } else {
        event->accept();
    }
}