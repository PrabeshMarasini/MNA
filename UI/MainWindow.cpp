#include "MainWindow.h"
#include "PacketTableView.h"
#include "HexView.h"
#include "ProtocolTreeView.h"
#include "PacketCaptureController.h"
#include "PacketDisplayController.h"
#include "PacketFilterWidget.h"
#include "DeviceSelectionDialog.h"
#include "ARPSpoofingController.h"
#include "SpeedTestWidget.h"
#include "LatencyTestWidget.h"
#include "PortScanWidget.h"
#include "MacLookupWidget.h"
#include "Models/PacketModel.h"
#include "Models/ProtocolTreeModel.h"
#include "Models/PacketFilterProxyModel.h"
#include "Utils/ErrorHandler.h"
#include "Utils/MemoryManager.h"
#include "Utils/ErrorRecoveryDialog.h"
#include "Utils/SettingsManager.h"
#include <QApplication>
#include <QCloseEvent>
#include <QMessageBox>
#include <QMenuBar>
#include <QToolBar>
#include <QStatusBar>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QLabel>
#include <QTimer>
#include <QAction>
#include <QFileDialog>
#include <QDialog>
#include <QPushButton>
#include <QStandardPaths>
#include <QStyle>
#include <QDebug>
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonValue>
#include <QFileInfo>
#include <QMessageBox>
#include <QFile>

MainWindow::MainWindow(const QString &interface, QWidget *parent)
    : QMainWindow(parent)
    , centralWidget(nullptr)
    , mainSplitter(nullptr)
    , bottomSplitter(nullptr)
    , packetTable(nullptr)
    , hexView(nullptr)
    , protocolView(nullptr)
    , filterWidget(nullptr)
    , mainToolBar(nullptr)
    , startCaptureAction(nullptr)
    , stopCaptureAction(nullptr)
    , clearPacketsAction(nullptr)
    , savePacketsAction(nullptr)
    , deviceSelectionAction(nullptr)
    , exitAction(nullptr)
    , interfaceLabel(nullptr)
    , captureStatusLabel(nullptr)
    , packetCountLabel(nullptr)
    , bytesCountLabel(nullptr)
    , spoofingStatusLabel(nullptr)

    , statisticsTimer(new QTimer(this))
    , uiUpdateTimer(new QTimer(this))
    , captureController(nullptr)
    , displayController(new PacketDisplayController(this))
    , packetModel(new PacketModel(this))
    , protocolModel(new ProtocolTreeModel(this))
    , filterProxyModel(new PacketFilterProxyModel(this))
    , deviceSelectionDialog(nullptr)
    , networkInterface(interface)
    , isCapturing(false)
    , packetCount(0)
    , totalBytes(0)
    , spoofingActive(false)
    , arpSpoofingController(nullptr)

{
    try {
        // Fast initialization - defer heavy operations
        ErrorHandler::instance()->setParentWidget(this);
        
        // Defer heavy initializations for faster startup
        QTimer::singleShot(0, this, [this]() {
            ErrorHandler::instance()->initialize(this);
            MemoryManager::instance()->initialize();
            SettingsManager::instance()->initialize();
        });
        
        // Defer signal connections for faster startup
        QTimer::singleShot(0, this, [this]() {
            // Connect error handling signals
            connect(ErrorHandler::instance(), &ErrorHandler::criticalErrorOccurred,
                    this, &MainWindow::onCriticalError);
            connect(MemoryManager::instance(), &MemoryManager::criticalMemoryWarning,
                    this, &MainWindow::onCriticalMemory);
            
            // Connect settings signals
            connect(SettingsManager::instance(), &SettingsManager::settingChanged,
                    this, &MainWindow::onSettingChanged);
        });
        
        setWindowTitle(QString("Packet Capture GUI - Interface: %1").arg(interface));
        setMinimumSize(1200, 800);
        
        // Show window immediately for better perceived performance
        show();
        QApplication::processEvents();
        
        // Fast UI setup - only essential components first
        setupUI();
        setupMenuBar();
        setupToolBar();
        setupStatusBar();
        setupSplitters();
        
        // Defer signal connections for faster startup
        QTimer::singleShot(0, this, &MainWindow::connectSignals);
        
        // Defer capture controller initialization for faster startup
        // captureController will be created lazily when first needed
        captureController = nullptr;
        
        // Defer window settings restoration for faster startup
        QTimer::singleShot(0, this, &MainWindow::restoreWindowSettings);
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("Critical error during MainWindow initialization: %1").arg(e.what()));
        QMessageBox::critical(this, "Initialization Error", 
            QString("Failed to initialize application: %1").arg(e.what()));
        throw;
    } catch (...) {
        LOG_CRITICAL("Unknown critical error during MainWindow initialization");
        QMessageBox::critical(this, "Initialization Error", 
            "Unknown error occurred during application initialization");
        throw;
    }
}

MainWindow::~MainWindow()
{
    if (isCapturing) {
        captureController->stopCapture();
    }
}

void MainWindow::setupUI()
{
    // Create central widget
    centralWidget = new QWidget;
    setCentralWidget(centralWidget);
    
    // Create main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(centralWidget);
    mainLayout->setContentsMargins(5, 5, 5, 5);
    mainLayout->setSpacing(5);
    
    // Create packet table view
    packetTable = new PacketTableView;
    
    // Enable virtual scrolling for better performance with large packet lists
    packetTable->setVirtualScrollingEnabled(true);
    
    // Defer model setup for faster startup
    QTimer::singleShot(0, this, [this]() {
        // Set up filter proxy model
        filterProxyModel->setSourceModel(packetModel);
        
        try {
            packetTable->setModel(filterProxyModel);
        } catch (const std::exception &e) {
            qWarning() << "Failed to set packet table model:" << e.what();
        } catch (...) {
            qWarning() << "Unknown error setting packet table model";
        }
    });
    
    // Create hex view
    hexView = new HexView;
    
    // Create protocol tree view
    protocolView = new ProtocolTreeView;
    protocolView->setProtocolModel(protocolModel);
    
    // Defer display controller setup for faster startup
    QTimer::singleShot(0, this, [this]() {
        displayController->setViews(packetTable, hexView, protocolView);
        displayController->setModels(packetModel, protocolModel);
    });
    
    // Connect memory limit exceeded signal
    connect(packetModel, &PacketModel::memoryLimitExceeded, this, &MainWindow::onMemoryLimitExceeded);
    
    qDebug() << "MainWindow: UI components created";
}

void MainWindow::setupMenuBar()
{
    // File menu
    QMenu *fileMenu = menuBar()->addMenu("&File");
    
    savePacketsAction = new QAction("&Save Packets...", this);
    savePacketsAction->setShortcut(QKeySequence::Save);

    savePacketsAction->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));
    savePacketsAction->setEnabled(false);
    connect(savePacketsAction, &QAction::triggered, this, &MainWindow::onExportPackets);
    fileMenu->addAction(savePacketsAction);
    
    fileMenu->addSeparator();
    
    exitAction = new QAction("E&xit", this);
    exitAction->setShortcut(QKeySequence::Quit);

    connect(exitAction, &QAction::triggered, this, &QWidget::close);
    fileMenu->addAction(exitAction);
    
    // Capture menu
    QMenu *captureMenu = menuBar()->addMenu("&Capture");
    
    startCaptureAction = new QAction("&Start Capture", this);
    startCaptureAction->setShortcut(QKeySequence("Ctrl+R"));

    startCaptureAction->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    connect(startCaptureAction, &QAction::triggered, this, &MainWindow::onStartCapture);
    captureMenu->addAction(startCaptureAction);
    
    stopCaptureAction = new QAction("S&top Capture", this);
    stopCaptureAction->setShortcut(QKeySequence("Ctrl+T"));

    stopCaptureAction->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    stopCaptureAction->setEnabled(false);
    connect(stopCaptureAction, &QAction::triggered, this, &MainWindow::onStopCapture);
    captureMenu->addAction(stopCaptureAction);
    
    captureMenu->addSeparator();
    
    deviceSelectionAction = new QAction("&Device Selection", this);
    deviceSelectionAction->setShortcut(QKeySequence("Ctrl+D"));

    deviceSelectionAction->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    connect(deviceSelectionAction, &QAction::triggered, this, &MainWindow::onDeviceSelectionRequested);
    captureMenu->addAction(deviceSelectionAction);
    
    captureMenu->addSeparator();
    
    clearPacketsAction = new QAction("&Clear Packets", this);
    clearPacketsAction->setShortcut(QKeySequence("Ctrl+L"));

    clearPacketsAction->setIcon(style()->standardIcon(QStyle::SP_DialogResetButton));
    connect(clearPacketsAction, &QAction::triggered, packetModel, &PacketModel::clearPackets);
    captureMenu->addAction(clearPacketsAction);
    
    // Tools menu
    QMenu *toolsMenu = menuBar()->addMenu("&Tools");
    
    QAction *speedTestAction = new QAction("&Internet Speed Test", this);
    speedTestAction->setShortcut(QKeySequence("Ctrl+I"));
    speedTestAction->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    connect(speedTestAction, &QAction::triggered, this, &MainWindow::onSpeedTestRequested);
    toolsMenu->addAction(speedTestAction);
    
    QAction *latencyTestAction = new QAction("&Network Latency Test", this);
    latencyTestAction->setShortcut(QKeySequence("Ctrl+L"));
    latencyTestAction->setIcon(style()->standardIcon(QStyle::SP_DialogApplyButton));
    connect(latencyTestAction, &QAction::triggered, this, &MainWindow::onLatencyTestRequested);
    toolsMenu->addAction(latencyTestAction);
    
    QAction *portScanAction = new QAction("&Port Scanner", this);
    portScanAction->setShortcut(QKeySequence("Ctrl+P"));
    portScanAction->setIcon(style()->standardIcon(QStyle::SP_FileDialogDetailedView));
    connect(portScanAction, &QAction::triggered, this, &MainWindow::onPortScanRequested);
    toolsMenu->addAction(portScanAction);
    
    QAction *macLookupAction = new QAction("&MAC Address Lookup", this);
    macLookupAction->setShortcut(QKeySequence("Ctrl+M"));
    macLookupAction->setIcon(style()->standardIcon(QStyle::SP_ComputerIcon));
    connect(macLookupAction, &QAction::triggered, this, &MainWindow::onMacLookupRequested);
    toolsMenu->addAction(macLookupAction);
    

    
    // View menu
    QMenu *viewMenu = menuBar()->addMenu("&View");
    
    QAction *expandAllAction = new QAction("&Expand All Protocol Fields", this);

    connect(expandAllAction, &QAction::triggered, protocolView, &ProtocolTreeView::expandAll);
    viewMenu->addAction(expandAllAction);
    
    QAction *collapseAllAction = new QAction("&Collapse All Protocol Fields", this);

    connect(collapseAllAction, &QAction::triggered, protocolView, &ProtocolTreeView::collapseAll);
    viewMenu->addAction(collapseAllAction);
    
    qDebug() << "MainWindow: Menu bar setup completed";
}

void MainWindow::setupToolBar()
{
    mainToolBar = addToolBar("Main");
    mainToolBar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    
    // Add capture actions to toolbar
    mainToolBar->addAction(startCaptureAction);
    mainToolBar->addAction(stopCaptureAction);
    mainToolBar->addSeparator();
    mainToolBar->addAction(deviceSelectionAction);
    mainToolBar->addSeparator();
    mainToolBar->addAction(clearPacketsAction);
    mainToolBar->addAction(savePacketsAction);
    
    qDebug() << "MainWindow: Toolbar setup completed";
}

void MainWindow::setupStatusBar()
{
    // Interface label
    interfaceLabel = new QLabel(QString("Interface: %1").arg(networkInterface));
    statusBar()->addWidget(interfaceLabel);
    
    statusBar()->addWidget(new QLabel("|"));
    
    // Capture status label
    captureStatusLabel = new QLabel("Status: Stopped");
    captureStatusLabel->setStyleSheet("color: red; font-weight: bold;");
    statusBar()->addWidget(captureStatusLabel);
    
    statusBar()->addWidget(new QLabel("|"));
    
    // Packet count label
    packetCountLabel = new QLabel("Packets: 0");
    statusBar()->addWidget(packetCountLabel);
    
    statusBar()->addWidget(new QLabel("|"));
    
    // Bytes count label
    bytesCountLabel = new QLabel("Bytes: 0");
    statusBar()->addWidget(bytesCountLabel);
    
    statusBar()->addWidget(new QLabel("|"));
    
    // Spoofing status label
    spoofingStatusLabel = new QLabel("ARP: Inactive");
    spoofingStatusLabel->setStyleSheet("color: gray; font-weight: bold;");
    statusBar()->addWidget(spoofingStatusLabel);
    
    // Defer timer setup for faster startup
    QTimer::singleShot(0, this, [this]() {
        // Setup statistics timer
        statisticsTimer->setInterval(1000); // Update every second
        connect(statisticsTimer, &QTimer::timeout, this, &MainWindow::updateStatistics);
        
        // Setup UI update timer for throttled updates
        uiUpdateTimer->setInterval(500); // Update UI every 500ms for better performance
        uiUpdateTimer->setSingleShot(false);
        connect(uiUpdateTimer, &QTimer::timeout, this, &MainWindow::performThrottledUIUpdate);
    });
    
    qDebug() << "MainWindow: Status bar setup completed";
}

void MainWindow::setupSplitters()
{
    // Create filter widget
    filterWidget = new PacketFilterWidget(centralWidget);
    
    // Create main splitter (vertical - top and bottom)
    mainSplitter = new QSplitter(Qt::Vertical, centralWidget);
    
    // Add packet table to top
    mainSplitter->addWidget(packetTable);
    
    // Create bottom splitter (horizontal - hex view and protocol view)
    bottomSplitter = new QSplitter(Qt::Horizontal);
    bottomSplitter->addWidget(hexView);
    bottomSplitter->addWidget(protocolView);
    
    // Add bottom splitter to main splitter
    mainSplitter->addWidget(bottomSplitter);
    
    // Set splitter proportions: top 50%, bottom 50%
    mainSplitter->setSizes({400, 400});
    
    // Set bottom splitter proportions: left 50%, right 50% (each gets 25% of total)
    bottomSplitter->setSizes({200, 200});
    
    // Configure splitter properties
    mainSplitter->setChildrenCollapsible(false);
    bottomSplitter->setChildrenCollapsible(false);
    
    // Set minimum sizes to ensure usability
    packetTable->setMinimumHeight(200);
    hexView->setMinimumWidth(150);
    protocolView->setMinimumWidth(150);
    
    // Add widgets to layout
    QVBoxLayout *layout = qobject_cast<QVBoxLayout*>(centralWidget->layout());
    if (layout) {
        layout->addWidget(filterWidget);
        layout->addWidget(mainSplitter);
    }
    
    qDebug() << "MainWindow: Splitter layout setup completed";
}

void MainWindow::connectSignals()
{
    // Connect display controller signals
    connect(displayController, &PacketDisplayController::selectionChanged,
            this, &MainWindow::onSelectionChanged);
    connect(displayController, &PacketDisplayController::fieldSelected,
            this, &MainWindow::onFieldSelected);
    connect(displayController, &PacketDisplayController::bytesHighlighted,
            this, &MainWindow::onBytesHighlighted);
    connect(displayController, &PacketDisplayController::displayError,
            this, &MainWindow::onDisplayError);
    
    // Capture controller signals are connected after creation in constructor
    if (captureController) {
        connect(captureController, &PacketCaptureController::backpressureApplied,
                this, &MainWindow::onBackpressureApplied);
        connect(captureController, &PacketCaptureController::samplingApplied,
                this, &MainWindow::onSamplingApplied);
    }
    
    // Connect model signals
    connect(packetModel, &PacketModel::rowsInserted,
            this, [this]() {
                packetCount = packetModel->rowCount();
                savePacketsAction->setEnabled(packetCount > 0);
            });
    
    // Connect statistics changes to update GUI immediately
    connect(packetModel, &PacketModel::statisticsChanged,
            this, &MainWindow::updateStatistics);
    
    // Connect filter signals
    connect(filterWidget, &PacketFilterWidget::filterChanged,
            this, &MainWindow::onFilterChanged);
    connect(filterWidget, &PacketFilterWidget::filterCleared,
            this, &MainWindow::onFilterCleared);
    
    // Connect packet model to filter widget for auto-complete
    connect(packetModel, QOverload<const PacketInfo &>::of(&PacketModel::packetAdded),
            filterWidget, &PacketFilterWidget::onPacketAdded);
    
    qDebug() << "MainWindow: Signal connections completed";
}

void MainWindow::onStartCapture()
{
    // If spoofing is active, this button should not start normal capture
    if (spoofingActive) {
        qDebug() << "MainWindow: Cannot start normal capture while spoofing is active";
        return;
    }
    
    // Lazy initialization of capture controller for better performance
    if (!captureController) {
        try {
            captureController = new PacketCaptureController(networkInterface, this);
            LOG_INFO(QString("MainWindow initialized capture controller for interface: %1").arg(networkInterface));
            
            // Connect capture controller signals after creation
            connect(captureController, &PacketCaptureController::packetsBatchCaptured,
                    this, &MainWindow::onNewPacketsBatchCaptured);
            connect(captureController, &PacketCaptureController::captureError,
                    this, &MainWindow::onCaptureError);
            connect(captureController, &PacketCaptureController::captureStatusChanged,
                    this, &MainWindow::onCaptureStatusChanged);
            
        } catch (const std::exception &e) {
            LOG_CRITICAL(QString("Failed to initialize capture controller: %1").arg(e.what()));
            QMessageBox::critical(this, "Capture Error", 
                QString("Failed to initialize packet capture: %1").arg(e.what()));
            return;
        }
    }
    
    captureController->startCapture();
    
    // Update UI state
    startCaptureAction->setEnabled(false);
    stopCaptureAction->setEnabled(true);
    
    // Start statistics timer
    statisticsTimer->start();
    
    qDebug() << "MainWindow: Started packet capture";
}

void MainWindow::onStopCapture()
{
    // Handle both normal capture and spoofing
    if (spoofingActive) {
        printf("[DEBUG] MainWindow: Stopping spoofing with timeout protection\n");
        
        // Set a timeout for spoofing stop operation
        QTimer::singleShot(5000, this, [this]() {
            if (spoofingActive) {
                qWarning() << "MainWindow: Spoofing stop timeout, forcing UI update";
                spoofingActive = false;
                onSpoofingStopped();
            }
        });
        
        // Use direct reference to spoofing controller (safer than going through dialog)
        if (arpSpoofingController) {
            printf("[DEBUG] MainWindow: Direct spoofing controller exists, calling stopSpoofing()\n");
            arpSpoofingController->stopSpoofing();
        } else {
            printf("[DEBUG] MainWindow: ERROR - Direct spoofing controller is null\n");
            // Fallback: try through dialog
            if (deviceSelectionDialog) {
                ARPSpoofingController* spoofingController = deviceSelectionDialog->getSpoofingController();
                if (spoofingController) {
                    printf("[DEBUG] MainWindow: Using dialog spoofing controller as fallback\n");
                    spoofingController->stopSpoofing();
                }
            }
        }
        
        // Note: UI state will be updated by onSpoofingStopped() when spoofing actually stops
    } else {
        // Stop normal capture
        if (captureController) {
            captureController->stopCapture();
        }
        
        // Update UI state for normal capture
        startCaptureAction->setEnabled(true);
        stopCaptureAction->setEnabled(false);
        
        // Stop statistics timer
        statisticsTimer->stop();
        
        qDebug() << "MainWindow: Stopped packet capture";
    }
}

void MainWindow::onSelectionChanged(int packetIndex)
{
    // Update status bar with selection info
    if (packetIndex >= 0) {
        statusBar()->showMessage(QString("Selected packet %1").arg(packetIndex + 1), 2000);
    } else {
        statusBar()->showMessage("No packet selected", 2000);
    }
    
    qDebug() << "MainWindow: Selection changed to packet" << packetIndex;
}

void MainWindow::onFieldSelected(const QString &fieldName, const QString &fieldValue, int packetIndex)
{
    // Update status bar with field info
    QString message = QString("Field: %1 = %2 (Packet %3)")
                     .arg(fieldName)
                     .arg(fieldValue)
                     .arg(packetIndex + 1);
    statusBar()->showMessage(message, 3000);
    
    qDebug() << "MainWindow: Field selected -" << fieldName << ":" << fieldValue;
}

void MainWindow::onBytesHighlighted(int startOffset, int length, int packetIndex)
{
    // Update status bar with highlight info
    QString message = QString("Highlighted bytes %1-%2 (Packet %3)")
                     .arg(startOffset)
                     .arg(startOffset + length - 1)
                     .arg(packetIndex + 1);
    statusBar()->showMessage(message, 2000);
    
    qDebug() << "MainWindow: Bytes highlighted -" << startOffset << "length:" << length;
}

void MainWindow::onDisplayError(const QString &error)
{
    // Show error in status bar and log
    statusBar()->showMessage(QString("Display error: %1").arg(error), 5000);
    LOG_ERROR(QString("Display error: %1").arg(error));
}

void MainWindow::onNewPacketCaptured(const PacketInfo &packet)
{
    
    // Add packet to model
    packetModel->addPacket(packet);
    
    qDebug() << "MainWindow: New packet captured, total:" << packetModel->rowCount();
}

void MainWindow::onNewPacketsBatchCaptured(const QList<PacketInfo> &packets)
{
    if (packets.isEmpty()) {
        return;
    }
    
    // Add batch of packets to model (much more efficient)
    packetModel->addPacketsBatch(packets);
    
    // High-speed capture optimization: disable auto-scrolling for large batches
    static int consecutiveLargeBatches = 0;
    if (packets.size() > 100) {
        consecutiveLargeBatches++;
        // Disable auto-scrolling during high-speed capture to prevent UI overload
        if (consecutiveLargeBatches > 3) {
            // Temporarily disable scrolling updates
            packetTable->setAutoScroll(false);
        }
    } else {
        consecutiveLargeBatches = 0;
        packetTable->setAutoScroll(true);
    }
    
    // Adaptive throttling: adjust UI update frequency based on batch size
    if (packets.size() > 1000) {
        // Large batch - reduce UI update frequency
        if (uiUpdateTimer->interval() < 1000) {
            uiUpdateTimer->setInterval(1000);
        }
    } else if (packets.size() > 500) {
        // Medium batch - moderate UI update frequency
        if (uiUpdateTimer->interval() < 500) {
            uiUpdateTimer->setInterval(500);
        }
    }
    
    // Start throttled UI updates if not already running
    if (!uiUpdateTimer->isActive()) {
        uiUpdateTimer->start();
    }
    
    qDebug() << "MainWindow: Batch of" << packets.size() << "packets captured, total:" << packetModel->rowCount();
}

void MainWindow::onCaptureError(const QString &error)
{
    LOG_CAPTURE_ERROR(error, QString("Interface: %1").arg(networkInterface));
    
    // Show error recovery dialog
    ErrorHandler::ErrorInfo errorInfo;
    errorInfo.level = ErrorHandler::Error;
    errorInfo.category = ErrorHandler::PacketCapture;
    errorInfo.message = "Packet capture error occurred";
    errorInfo.details = error;
    errorInfo.source = "MainWindow::onCaptureError";
    errorInfo.timestamp = QDateTime::currentDateTime();
    
    ErrorRecoveryDialog recoveryDialog(errorInfo, this);
    recoveryDialog.setAutoRecoveryTimeout(5); // 5 seconds auto recovery
    
    auto result = recoveryDialog.exec();
    if (result == QDialog::Accepted) {
        auto recoveryResult = recoveryDialog.getRecoveryResult();
        
        switch (recoveryResult.action) {
            case ErrorRecoveryDialog::Retry:
                // Retry capture after a brief delay
                QTimer::singleShot(1000, this, &MainWindow::onStartCapture);
                break;
            case ErrorRecoveryDialog::Reset:
                // Reset capture controller
                resetCaptureController();
                break;
            case ErrorRecoveryDialog::IgnoreError:
                // Just continue without capture
                break;
            default:
                break;
        }
    }
    
    // Reset UI state
    onStopCapture();
}

void MainWindow::onCaptureStatusChanged(bool capturing)
{
    isCapturing = capturing;
    
    if (capturing) {
        captureStatusLabel->setText("Status: Capturing");
        captureStatusLabel->setStyleSheet("color: green; font-weight: bold;");
    } else {
        captureStatusLabel->setText("Status: Stopped");
        captureStatusLabel->setStyleSheet("color: red; font-weight: bold;");
    }
    
    qDebug() << "MainWindow: Capture status changed to" << (capturing ? "capturing" : "stopped");
}

void MainWindow::updateStatistics()
{
    packetCount = packetModel->rowCount();
    totalBytes = packetModel->getTotalBytes();  // Get from model instead of tracking separately
    
    packetCountLabel->setText(QString("Packets: %1").arg(packetCount));
    bytesCountLabel->setText(QString("Bytes: %1").arg(totalBytes));
}

void MainWindow::performThrottledUIUpdate()
{
    // This method is called periodically to perform UI updates that don't need to happen immediately
    // It helps reduce UI thread load during high packet capture rates
    
    // Update statistics if needed
    updateStatistics();
    
    // Process any pending events to keep UI responsive
    QApplication::processEvents(QEventLoop::ExcludeUserInputEvents, 10);
    
    // Adaptive throttling based on packet rate
    static int lastPacketCount = 0;
    int currentPacketCount = packetModel->getPacketCount();
    int packetsPerSecond = currentPacketCount - lastPacketCount;
    lastPacketCount = currentPacketCount;
    
    // Adjust UI update frequency based on packet rate
    if (packetsPerSecond > 10000) {
        // Very high rate - update every 2 seconds
        uiUpdateTimer->setInterval(2000);
    } else if (packetsPerSecond > 5000) {
        // High rate - update every 1 second
        uiUpdateTimer->setInterval(1000);
    } else if (packetsPerSecond > 1000) {
        // Medium rate - update every 500ms
        uiUpdateTimer->setInterval(500);
    } else {
        // Low rate - update every 200ms
        uiUpdateTimer->setInterval(200);
    }
    
    // Stop the timer if capture is not active
    if (!isCapturing) {
        uiUpdateTimer->stop();
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    try {
        if (isCapturing) {
            QMessageBox::StandardButton reply = QMessageBox::question(this,
                "Packet Capture Active",
                "Packet capture is currently active. Do you want to stop capture and exit?",
                QMessageBox::Yes | QMessageBox::No);
            
            if (reply == QMessageBox::Yes) {
                onStopCapture();
            } else {
                event->ignore();
                return;
            }
        }
        
        // Save window settings before closing
        saveWindowSettings();
        
        // Save final settings
        SettingsManager::instance()->saveSettings();
        
        LOG_INFO("MainWindow: Application closing gracefully");
        event->accept();
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("MainWindow: Exception during close: %1").arg(e.what()));
        event->accept(); // Accept anyway to prevent hanging
    }
}

void MainWindow::onCriticalError(const QString &message)
{
    LOG_CRITICAL(QString("Critical error in MainWindow: %1").arg(message));
    
    // Show critical error dialog with recovery options
    ErrorHandler::ErrorInfo errorInfo;
    errorInfo.level = ErrorHandler::Critical;
    errorInfo.category = ErrorHandler::General;
    errorInfo.message = "Critical application error";
    errorInfo.details = message;
    errorInfo.source = "MainWindow::onCriticalError";
    errorInfo.timestamp = QDateTime::currentDateTime();
    
    ErrorRecoveryDialog recoveryDialog(errorInfo, this);
    recoveryDialog.setDefaultAction(ErrorRecoveryDialog::Restart);
    
    auto result = recoveryDialog.exec();
    if (result == QDialog::Accepted) {
        auto recoveryResult = recoveryDialog.getRecoveryResult();
        
        switch (recoveryResult.action) {
            case ErrorRecoveryDialog::Restart:
                // Application restart is handled by the dialog
                break;
            case ErrorRecoveryDialog::SafeShutdown:
                // Safe shutdown is handled by the dialog
                break;
            case ErrorRecoveryDialog::Reset:
                // Try to reset the application state
                resetApplicationState();
                break;
            default:
                break;
        }
    }
}

void MainWindow::onCriticalMemory()
{
    LOG_CRITICAL("Critical memory situation detected");
    
    // Stop capture to free memory
    if (isCapturing) {
        onStopCapture();
    }
    
    // Clear packet data to free memory
    packetModel->clearPackets();
    
    // Force garbage collection
    QApplication::processEvents();
    
    // Show memory warning
    QMessageBox::warning(this, "Low Memory Warning",
        "Critical memory situation detected. Packet capture has been stopped and data cleared to free memory.\n\n"
        "Consider:\n"
        "- Closing other applications\n"
        "- Restarting the application\n"
        "- Using packet filtering to reduce memory usage");
}

void MainWindow::resetCaptureController()
{
    try {
        LOG_INFO("Resetting capture controller");
        
        // Stop current capture
        if (isCapturing) {
            onStopCapture();
        }
        
        // Delete and recreate capture controller
        if (captureController) {
            captureController->deleteLater();
            captureController = nullptr;
        }
        
        // Wait for deletion
        QApplication::processEvents();
        
        // Create new capture controller
        captureController = new PacketCaptureController(networkInterface, this);
        
        // Reconnect signals
        // Individual packet processing disabled for performance - only use batch processing
        // connect(captureController, &PacketCaptureController::packetCaptured,
        //         this, &MainWindow::onNewPacketCaptured);
        connect(captureController, &PacketCaptureController::packetsBatchCaptured,
                this, &MainWindow::onNewPacketsBatchCaptured);
        connect(captureController, &PacketCaptureController::captureError,
                this, &MainWindow::onCaptureError);
        connect(captureController, &PacketCaptureController::captureStatusChanged,
                this, &MainWindow::onCaptureStatusChanged);
        
        LOG_INFO("Capture controller reset successfully");
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("Failed to reset capture controller: %1").arg(e.what()));
        QMessageBox::critical(this, "Reset Failed", 
            QString("Failed to reset capture controller: %1").arg(e.what()));
    }
}

void MainWindow::resetApplicationState()
{
    try {
        LOG_INFO("Resetting application state");
        
        // Stop capture
        if (isCapturing) {
            onStopCapture();
        }
        
        // Clear all data
        packetModel->clearPackets();
        protocolModel->clear();
        hexView->clear();
        
        // Statistics will be updated automatically via statisticsChanged signal
        updateStatistics();
        
        // Reset capture controller
        resetCaptureController();
        
        // Clear status messages
        statusBar()->clearMessage();
        captureStatusLabel->setText("Status: Ready");
        
        LOG_INFO("Application state reset successfully");
        
        QMessageBox::information(this, "Reset Complete", 
            "Application state has been reset successfully.");
        
    } catch (const std::exception &e) {
        LOG_CRITICAL(QString("Failed to reset application state: %1").arg(e.what()));
        QMessageBox::critical(this, "Reset Failed", 
            QString("Failed to reset application state: %1").arg(e.what()));
    }
}

void MainWindow::onSettingChanged(const QString &key, const QVariant &value)
{
    LOG_DEBUG(QString("Setting changed: %1 = %2").arg(key).arg(value.toString()));
    
    // Handle specific setting changes
    if (key == "display/hex_font_family" || key == "display/hex_font_size") {
        // Update hex view font
        QString fontFamily = SettingsManager::instance()->getHexViewFontFamily();
        int fontSize = SettingsManager::instance()->getHexViewFontSize();
        
        if (hexView) {
            QFont font(fontFamily, fontSize);
            hexView->setFont(font);
        }
    }
    else if (key == "display/tree_expanded") {
        // Update protocol tree expansion state
        bool expanded = value.toBool();
        if (protocolView) {
            if (expanded) {
                protocolView->expandAll();
            } else {
                protocolView->collapseAll();
            }
        }
    }
    else if (key == "performance/update_interval") {
        // Update statistics timer interval
        int interval = value.toInt();
        if (statisticsTimer) {
            statisticsTimer->setInterval(interval);
        }
    }
}

void MainWindow::saveWindowSettings()
{
    try {
        LOG_INFO("MainWindow: Saving window settings");
        
        // Save window geometry and state
        SettingsManager::instance()->saveWindowGeometry(saveGeometry());
        SettingsManager::instance()->saveWindowState(saveState());
        
        // Save splitter states
        if (mainSplitter) {
            SettingsManager::instance()->saveSplitterState("main", mainSplitter->saveState());
        }
        if (bottomSplitter) {
            SettingsManager::instance()->saveSplitterState("bottom", bottomSplitter->saveState());
        }
        
        // Save table column widths
        if (packetTable) {
            QList<int> widths;
            for (int i = 0; i < packetTable->horizontalHeader()->count(); ++i) {
                widths.append(packetTable->columnWidth(i));
            }
            SettingsManager::instance()->setPacketTableColumnWidths(widths);
        }
        
        // Save current interface
        SettingsManager::instance()->setLastUsedInterface(networkInterface);
        
        // Save current filter if any
        if (captureController) {
            // This would need to be implemented in PacketCaptureController
            // QString currentFilter = captureController->getCurrentFilter();
            // SettingsManager::instance()->setCaptureFilter(currentFilter);
        }
        
        LOG_INFO("MainWindow: Window settings saved successfully");
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("MainWindow: Exception saving window settings: %1").arg(e.what()));
    }
}

QList<QString> MainWindow::getTargetMACsFromIPs(const QList<QString> &targetIPs)
{
    QList<QString> targetMACs;
    
    if (!deviceSelectionDialog) {
        qWarning() << "MainWindow: Device selection dialog not available for MAC lookup";
        return targetMACs;
    }
    
    // Get MAC addresses for the target IPs from the device selection dialog
    targetMACs = deviceSelectionDialog->getMACsForIPs(targetIPs);
    
    qDebug() << "MainWindow: Converted" << targetIPs.size() << "target IPs to" << targetMACs.size() << "MAC addresses";
    
    return targetMACs;
}

void MainWindow::restoreWindowSettings()
{
    try {
        LOG_INFO("MainWindow: Restoring window settings");
        
        // Restore splitter states
        QByteArray mainSplitterState = SettingsManager::instance()->getSplitterState("main");
        if (!mainSplitterState.isEmpty() && mainSplitter) {
            mainSplitter->restoreState(mainSplitterState);
        }
        
        QByteArray bottomSplitterState = SettingsManager::instance()->getSplitterState("bottom");
        if (!bottomSplitterState.isEmpty() && bottomSplitter) {
            bottomSplitter->restoreState(bottomSplitterState);
        }
        
        // Restore table column widths
        QList<int> columnWidths = SettingsManager::instance()->getPacketTableColumnWidths();
        if (!columnWidths.isEmpty() && packetTable) {
            for (int i = 0; i < qMin(columnWidths.size(), packetTable->horizontalHeader()->count()); ++i) {
                packetTable->setColumnWidth(i, columnWidths[i]);
            }
        }
        
        // Restore hex view font
        QString fontFamily = SettingsManager::instance()->getHexViewFontFamily();
        int fontSize = SettingsManager::instance()->getHexViewFontSize();
        if (hexView) {
            QFont font(fontFamily, fontSize);
            hexView->setFont(font);
        }
        
        // Restore protocol tree expansion state
        bool treeExpanded = SettingsManager::instance()->getProtocolTreeExpanded();
        if (protocolView) {
            if (treeExpanded) {
                protocolView->expandAll();
            } else {
                protocolView->collapseAll();
            }
        }
        
        // Restore update interval
        int updateInterval = SettingsManager::instance()->getUpdateInterval();
        if (statisticsTimer) {
            statisticsTimer->setInterval(updateInterval);
        }
        
        LOG_INFO("MainWindow: Window settings restored successfully");
        
    } catch (const std::exception &e) {
        LOG_ERROR(QString("MainWindow: Exception restoring window settings: %1").arg(e.what()));
    }
}

void MainWindow::onFilterChanged(const PacketFilterWidget::FilterCriteria &criteria)
{
    if (filterProxyModel) {
        filterProxyModel->setFilter(criteria);
        
        // Update status bar to show filter is active
        if (captureStatusLabel) {
            QString status = isCapturing ? "Capturing" : "Stopped";
            if (criteria.enabled) {
                status += " (Filtered)";
            }
            captureStatusLabel->setText(status);
        }
        
        qDebug() << "MainWindow: Filter applied - Source IP:" << criteria.sourceIP 
                 << "Dest IP:" << criteria.destinationIP 
                 << "Protocol:" << criteria.protocolType
                 << "Custom:" << criteria.customFilter;
    }
}

void MainWindow::onFilterCleared()
{
    if (filterProxyModel) {
        filterProxyModel->clearFilter();
        
        // Update status bar to remove filter indication
        if (captureStatusLabel) {
            QString status = isCapturing ? "Capturing" : "Stopped";
            captureStatusLabel->setText(status);
        }
        
        qDebug() << "MainWindow: Filter cleared";
    }
}

void MainWindow::onDeviceSelectionRequested()
{
    if (!deviceSelectionDialog) {
        deviceSelectionDialog = new DeviceSelectionDialog(this);
        
        // Connect device selection dialog signals
        connect(deviceSelectionDialog, &DeviceSelectionDialog::spoofingStarted,
                this, &MainWindow::onSpoofingStarted);
        connect(deviceSelectionDialog, &DeviceSelectionDialog::spoofingStopped,
                this, &MainWindow::onSpoofingStopped);
        connect(deviceSelectionDialog, &DeviceSelectionDialog::spoofedPacketCaptured,
                this, &MainWindow::onSpoofingTargetPacketCaptured, Qt::QueuedConnection);
        
        qDebug() << "MainWindow: Connected device selection dialog signals";
    }
    
    deviceSelectionDialog->show();
    deviceSelectionDialog->raise();
    deviceSelectionDialog->activateWindow();
}

void MainWindow::onSpoofingStarted(const QList<QString> &targetIPs, const QString &interface)
{
    spoofingActive = true;
    spoofedTargets = targetIPs;
    
    // Store reference to spoofing controller for direct access
    if (deviceSelectionDialog) {
        arpSpoofingController = deviceSelectionDialog->getSpoofingController();
        printf("[DEBUG] MainWindow: Stored direct reference to spoofing controller\n");
    }
    
    // Stop normal packet capture to avoid conflicts
    if (isCapturing && captureController) {
        captureController->stopCapture();
        isCapturing = false;
    }
    
    // Update UI state - disable start capture, enable stop for spoofing
    startCaptureAction->setEnabled(false);
    stopCaptureAction->setEnabled(true);  // Enable stop button to stop spoofing
    captureStatusLabel->setText("Status: Spoofing Mode");
    captureStatusLabel->setStyleSheet("color: orange; font-weight: bold;");
    
    // Update status bar
    spoofingStatusLabel->setText(QString("ARP: Active (%1 targets)").arg(targetIPs.count()));
    spoofingStatusLabel->setStyleSheet("color: green; font-weight: bold;");
    
    // Update window title to show spoofing status
    setWindowTitle(QString("Packet Capture GUI - Interface: %1 [ARP Spoofing: %2 targets]")
                   .arg(networkInterface).arg(targetIPs.count()));
    
    // Start statistics timer for spoofed packets
    if (!statisticsTimer->isActive()) {
        statisticsTimer->start();
    }
    
    qDebug() << "MainWindow: ARP spoofing started for targets:" << targetIPs << "on interface:" << interface;
}

void MainWindow::onSpoofingStopped()
{
    spoofingActive = false;
    spoofedTargets.clear();
    
    // Clear reference to spoofing controller
    arpSpoofingController = nullptr;
    printf("[DEBUG] MainWindow: Cleared direct reference to spoofing controller\n");
    
    // Re-enable normal capture controls
    startCaptureAction->setEnabled(true);
    stopCaptureAction->setEnabled(false);
    captureStatusLabel->setText("Status: Stopped");
    captureStatusLabel->setStyleSheet("color: red; font-weight: bold;");
    
    // Update status bar
    spoofingStatusLabel->setText("ARP: Inactive");
    spoofingStatusLabel->setStyleSheet("color: gray; font-weight: bold;");
    
    // Restore original window title
    setWindowTitle(QString("Packet Capture GUI - Interface: %1").arg(networkInterface));
    
    qDebug() << "MainWindow: ARP spoofing stopped";
}

void MainWindow::onSpoofingTargetPacketCaptured(const QByteArray &packetData, const struct timeval &timestamp)
{
    printf("[DEBUG] MainWindow: Received spoofed packet, size: %d, spoofingActive: %d\n", packetData.size(), spoofingActive);
    
    if (!spoofingActive) {
        printf("[DEBUG] MainWindow: Spoofing not active, ignoring packet\n");
        return;
    }
    
    if (packetData.isEmpty()) {
        printf("[DEBUG] MainWindow: Empty packet data, ignoring\n");
        return;
    }
    
    if (!captureController) {
        printf("[DEBUG] MainWindow: No capture controller available\n");
        return;
    }
    
    if (!packetModel) {
        printf("[DEBUG] MainWindow: No packet model available\n");
        return;
    }
    
    try {
        printf("[DEBUG] MainWindow: Creating PacketInfo from spoofed data\n");
        
        // Create PacketInfo from spoofed packet data
        PacketInfo packet = captureController->createPacketInfo(packetData, timestamp);
        
        printf("[DEBUG] MainWindow: PacketInfo created, adding to model\n");
        
        // Add packet to model - this will display it in the GUI
        packetModel->addPacket(packet);
        
        printf("[DEBUG] MainWindow: Spoofed packet added to GUI successfully, total packets: %d\n", packetModel->rowCount());
        
    } catch (const std::exception &e) {
        printf("[DEBUG] MainWindow: Error processing spoofed packet: %s\n", e.what());
    }
}

void MainWindow::onExportPackets()
{
    if (!packetModel || packetModel->rowCount() == 0) {
        QMessageBox::warning(this, "No Packets", "No packets to export.");
        return;
    }
    
    // Show format selection dialog
    QString fileName = QFileDialog::getSaveFileName(this,
        "Export Packets",
        QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) + "/captured_packets",
        "PCAP Files (*.pcap);;JSON Files (*.json);;All Files (*)");
    
    if (fileName.isEmpty()) {
        return;
    }
    
    QFileInfo fileInfo(fileName);
    QString suffix = fileInfo.suffix().toLower();
    
    if (suffix == "json" || fileInfo.completeBaseName().contains(".json")) {
        // Export as JSON
        exportToJson(fileName);
    } else if (suffix == "pcap" || fileInfo.completeBaseName().contains(".pcap")) {
        // Export as PCAP
        exportToPcap(fileName);
    } else {
        // Default to JSON if no extension
        exportToJson(fileName + ".json");
    }
}

void MainWindow::exportToJson(const QString &fileName)
{
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Export Failed", 
            QString("Failed to open file for writing:\n%1").arg(fileName));
        return;
    }
    
    QJsonArray packetsArray;
    int packetCount = packetModel->rowCount();
    
    for (int i = 0; i < packetCount; ++i) {
        PacketInfo packet = packetModel->getPacket(i);
        
        QJsonObject packetJson;
        packetJson["serialNumber"] = packet.serialNumber;
        packetJson["timestamp"] = packet.timestamp.toString(Qt::ISODate);
        packetJson["sourceIP"] = packet.sourceIP;
        packetJson["destinationIP"] = packet.destinationIP;
        packetJson["protocolType"] = packet.protocolType;
        packetJson["moreInfo"] = packet.moreInfo;
        packetJson["packetLength"] = packet.packetLength;
        packetJson["rawData"] = QString(packet.rawData.toHex());
        
        packetsArray.append(packetJson);
    }
    
    QJsonObject root;
    root["packetCount"] = packetCount;
    root["packets"] = packetsArray;
    
    QJsonDocument doc(root);
    file.write(doc.toJson());
    file.close();
    
    QMessageBox::information(this, "Export Successful", 
        QString("Exported %1 packets to:\n%2").arg(packetCount).arg(fileName));
}

void MainWindow::exportToPcap(const QString &fileName)
{
    QFile file(fileName);
    if (!file.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, "Export Failed", 
            QString("Failed to open file for writing:\n%1").arg(fileName));
        return;
    }
    
    // PCAP Global Header (24 bytes)
    struct pcap_file_header {
        quint32 magic_number;   // 0xa1b2c3d4
        quint16 version_major;  // 2
        quint16 version_minor;  // 4
        qint32  thiszone;       // 0
        quint32 sigfigs;        // 0
        quint32 snaplen;        // 65535
        quint32 network;        // 1 (Ethernet)
    } header;
    
    header.magic_number = 0xa1b2c3d4;
    header.version_major = 2;
    header.version_minor = 4;
    header.thiszone = 0;
    header.sigfigs = 0;
    header.snaplen = 65535;
    header.network = 1; // Ethernet
    
    file.write(reinterpret_cast<const char*>(&header), sizeof(header));
    
    // Write packets
    int packetCount = packetModel->rowCount();
    for (int i = 0; i < packetCount; ++i) {
        PacketInfo packet = packetModel->getPacket(i);
        
        // PCAP Packet Header (16 bytes)
        struct pcap_pkthdr {
            quint32 ts_sec;     // timestamp seconds
            quint32 ts_usec;    // timestamp microseconds
            quint32 incl_len;   // number of octets of packet saved in file
            quint32 orig_len;   // actual length of packet
        } pkt_header;
        
        pkt_header.ts_sec = packet.timestamp.toSecsSinceEpoch();
        pkt_header.ts_usec = (packet.timestamp.time().msec() * 1000);
        pkt_header.incl_len = packet.packetLength;
        pkt_header.orig_len = packet.packetLength;
        
        file.write(reinterpret_cast<const char*>(&pkt_header), sizeof(pkt_header));
        file.write(packet.rawData);
    }
    
    file.close();
    
    QMessageBox::information(this, "Export Successful", 
        QString("Exported %1 packets to:\n%2").arg(packetCount).arg(fileName));
}

void MainWindow::onSpeedTestRequested()
{
    // Create speed test dialog
    QDialog *speedTestDialog = new QDialog(this);
    speedTestDialog->setWindowTitle("Internet Speed Test");
    speedTestDialog->setModal(true);
    speedTestDialog->resize(400, 200);
    
    // Create layout
    QVBoxLayout *layout = new QVBoxLayout(speedTestDialog);
    
    // Create speed test widget
    SpeedTestWidget *speedTestWidget = new SpeedTestWidget(speedTestDialog);
    layout->addWidget(speedTestWidget);
    
    // Add close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    QPushButton *closeButton = new QPushButton("Close", speedTestDialog);
    connect(closeButton, &QPushButton::clicked, speedTestDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // Show dialog
    speedTestDialog->exec();
    
    // Clean up
    speedTestDialog->deleteLater();
}

void MainWindow::onLatencyTestRequested()
{
    // Create latency test dialog
    QDialog *latencyTestDialog = new QDialog(this);
    latencyTestDialog->setWindowTitle("Network Latency Test");
    latencyTestDialog->setModal(true);
    latencyTestDialog->resize(450, 250);
    
    // Create layout
    QVBoxLayout *layout = new QVBoxLayout(latencyTestDialog);
    
    // Create latency test widget
    LatencyTestWidget *latencyTestWidget = new LatencyTestWidget(latencyTestDialog);
    layout->addWidget(latencyTestWidget);
    
    // Add close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    QPushButton *closeButton = new QPushButton("Close", latencyTestDialog);
    connect(closeButton, &QPushButton::clicked, latencyTestDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // Show dialog
    latencyTestDialog->exec();
    
    // Clean up
    latencyTestDialog->deleteLater();
}

void MainWindow::onPortScanRequested()
{
    // Create port scan dialog
    QDialog *portScanDialog = new QDialog(this);
    portScanDialog->setWindowTitle("Network Port Scanner");
    portScanDialog->setModal(true);
    portScanDialog->resize(600, 500);
    
    // Create layout
    QVBoxLayout *layout = new QVBoxLayout(portScanDialog);
    
    // Create port scan widget
    PortScanWidget *portScanWidget = new PortScanWidget(portScanDialog);
    layout->addWidget(portScanWidget);
    
    // Add close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    QPushButton *closeButton = new QPushButton("Close", portScanDialog);
    connect(closeButton, &QPushButton::clicked, portScanDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // Show dialog
    portScanDialog->exec();
    
    // Clean up
    portScanDialog->deleteLater();
}

void MainWindow::onMacLookupRequested()
{
    // Create MAC lookup dialog
    QDialog *macLookupDialog = new QDialog(this);
    macLookupDialog->setWindowTitle("MAC Address Vendor Lookup");
    macLookupDialog->setModal(true);
    macLookupDialog->resize(700, 600);
    
    // Create layout
    QVBoxLayout *layout = new QVBoxLayout(macLookupDialog);
    
    // Create MAC lookup widget
    MacLookupWidget *macLookupWidget = new MacLookupWidget(macLookupDialog);
    layout->addWidget(macLookupWidget);
    
    // Add close button
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    buttonLayout->addStretch();
    
    QPushButton *closeButton = new QPushButton("Close", macLookupDialog);
    connect(closeButton, &QPushButton::clicked, macLookupDialog, &QDialog::accept);
    buttonLayout->addWidget(closeButton);
    
    layout->addLayout(buttonLayout);
    
    // Show dialog
    macLookupDialog->exec();
    
    // Clean up
    macLookupDialog->deleteLater();
}

void MainWindow::onMemoryLimitExceeded()
{
    LOG_WARNING("Memory limit exceeded, applying retention policy");
    
    // Show warning to user
    statusBar()->showMessage("High memory usage detected, applying retention policy", 5000);
    
    // Apply ring buffer mode to limit memory usage
    packetModel->setRetentionMode(RingBufferRetention);
    packetModel->setMaxPackets(50000); // Limit to 50K packets
    
    // Also enable ring buffer in capture controller
    if (captureController) {
        captureController->setRingBufferEnabled(true);
        captureController->setRingBufferSize(50000);
    }
}

void MainWindow::onBackpressureApplied()
{
    LOG_INFO("Backpressure applied to packet capture");
    
    // Show notification to user
    statusBar()->showMessage("High packet rate detected, applying capture throttling", 3000);
    
    // Update UI to indicate backpressure is active
    captureStatusLabel->setText("Status: Capturing (Throttled)");
    captureStatusLabel->setStyleSheet("color: orange; font-weight: bold;");
}

void MainWindow::onSamplingApplied()
{
    LOG_INFO("Packet sampling applied to reduce capture load");
    
    // Show notification to user
    statusBar()->showMessage("High packet rate detected, applying packet sampling", 3000);
    
    // Update UI to indicate sampling is active
    captureStatusLabel->setText("Status: Capturing (Sampling)");
    captureStatusLabel->setStyleSheet("color: purple; font-weight: bold;");
}