#include "TracerouteWidget.h"
#include <QApplication>
#include <QMessageBox>
#include <QClipboard>
#include <QHeaderView>
#include <QSplitter>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QScrollBar>
#include <unistd.h>

// TracerouteWorker Implementation
TracerouteWorker::TracerouteWorker(QObject *parent) : QObject(parent) {}

void TracerouteWorker::performTraceroute(const QString &target) {
    QMutexLocker locker(&m_mutex);
    
    TracerouteResult result;
    int status = perform_traceroute(target.toUtf8().constData(), &result);
    
    if (status == 0) {
        emit tracerouteCompleted(result);
    } else {
        emit tracerouteFailed(QString("Traceroute failed for target: %1").arg(target));
    }
}

// TracerouteWidget Implementation
TracerouteWidget::TracerouteWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_tracerouteInProgress(false)
    , m_updateTimer(nullptr)
{
    setupUI();
    
    // Create worker thread
    m_workerThread = new QThread(this);
    m_worker = new TracerouteWorker();
    m_worker->moveToThread(m_workerThread);
    
    // Connect signals
    connect(m_workerThread, &QThread::started, m_worker, [this]() {
        // Thread started
    });
    
    connect(m_worker, &TracerouteWorker::tracerouteCompleted,
            this, &TracerouteWidget::onTracerouteCompleted);
    connect(m_worker, &TracerouteWorker::tracerouteFailed,
            this, &TracerouteWidget::onTracerouteFailed);
    connect(m_worker, &TracerouteWorker::hopUpdate,
            this, &TracerouteWidget::onHopUpdate);
    
    m_workerThread->start();
    
    // Setup update timer
    m_updateTimer = new QTimer(this);
    m_updateTimer->setInterval(100); // Update every 100ms
}

TracerouteWidget::~TracerouteWidget() {
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
        delete m_worker;
    }
}

void TracerouteWidget::setupUI() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(10);
    m_mainLayout->setContentsMargins(10, 10, 10, 10);
    
    // Input Group
    m_inputGroup = new QGroupBox("Traceroute", this);
    m_inputLayout = new QHBoxLayout(m_inputGroup);
    
    m_targetEdit = new QLineEdit(this);
    m_targetEdit->setPlaceholderText("Enter hostname or IP address (e.g., google.com or 8.8.8.8)");
    m_targetEdit->setMinimumWidth(300);
    
    m_maxHopsSpinBox = new QSpinBox(this);
    m_maxHopsSpinBox->setRange(1, 64);
    m_maxHopsSpinBox->setValue(30);
    m_maxHopsSpinBox->setSuffix(" hops");
    m_maxHopsSpinBox->setMinimumWidth(100);
    
    m_tracerouteButton = new QPushButton("Start Traceroute", this);
    m_tracerouteButton->setMinimumWidth(120);
    m_tracerouteButton->setDefault(true);
    
    m_stopButton = new QPushButton("Stop", this);
    m_stopButton->setMinimumWidth(80);
    m_stopButton->setEnabled(false);
    
    m_clearButton = new QPushButton("Clear", this);
    m_clearButton->setMinimumWidth(80);
    
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setRange(0, 0); // Indeterminate progress
    
    m_inputLayout->addWidget(new QLabel("Target:"));
    m_inputLayout->addWidget(m_targetEdit);
    m_inputLayout->addWidget(new QLabel("Max Hops:"));
    m_inputLayout->addWidget(m_maxHopsSpinBox);
    m_inputLayout->addWidget(m_tracerouteButton);
    m_inputLayout->addWidget(m_stopButton);
    m_inputLayout->addWidget(m_clearButton);
    m_inputLayout->addStretch();
    
    m_mainLayout->addWidget(m_inputGroup);
    m_mainLayout->addWidget(m_progressBar);
    
    // Results Group
    m_resultsGroup = new QGroupBox("Route Trace", this);
    m_resultsLayout = new QVBoxLayout(m_resultsGroup);
    
    m_statusLabel = new QLabel("Ready to perform traceroute", this);
    m_statusLabel->setStyleSheet("color: #666; font-style: italic;");
    
    // Results table
    m_resultsTable = new QTableWidget(this);
    m_resultsTable->setColumnCount(6);
    QStringList headers = {"Hop", "IP Address", "Hostname", "Probe 1", "Probe 2", "Probe 3"};
    m_resultsTable->setHorizontalHeaderLabels(headers);
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSortingEnabled(false); // Disable sorting to maintain hop order
    
    m_resultsLayout->addWidget(m_statusLabel);
    m_resultsLayout->addWidget(m_resultsTable);
    
    m_mainLayout->addWidget(m_resultsGroup);
    
    // Summary Group
    m_summaryGroup = new QGroupBox("Summary", this);
    m_summaryLayout = new QVBoxLayout(m_summaryGroup);
    
    m_targetLabel = new QLabel("Target: -", this);
    m_totalHopsLabel = new QLabel("Total Hops: -", this);
    m_successfulHopsLabel = new QLabel("Successful Hops: -", this);
    m_totalTimeLabel = new QLabel("Total Time: -", this);
    
    m_summaryLayout->addWidget(m_targetLabel);
    m_summaryLayout->addWidget(m_totalHopsLabel);
    m_summaryLayout->addWidget(m_successfulHopsLabel);
    m_summaryLayout->addWidget(m_totalTimeLabel);
    
    m_mainLayout->addWidget(m_summaryGroup);
    
    // Connect signals
    connect(m_tracerouteButton, &QPushButton::clicked, this, &TracerouteWidget::onTracerouteClicked);
    connect(m_stopButton, &QPushButton::clicked, this, &TracerouteWidget::onStopClicked);
    connect(m_clearButton, &QPushButton::clicked, this, &TracerouteWidget::onClearClicked);
    connect(m_targetEdit, &QLineEdit::returnPressed, this, &TracerouteWidget::onTracerouteClicked);
    connect(m_targetEdit, &QLineEdit::textChanged, this, &TracerouteWidget::onTargetChanged);
    connect(m_resultsTable, &QTableWidget::cellClicked, this, &TracerouteWidget::onResultTableItemClicked);
    
    // Set initial state
    clearResults();
}

void TracerouteWidget::onTracerouteClicked() {
    QString target = m_targetEdit->text().trimmed();
    
    if (target.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a hostname or IP address.");
        return;
    }
    
    if (!isValidInput(target)) {
        QMessageBox::warning(this, "Input Error", "Please enter a valid hostname or IP address.");
        return;
    }
    
    if (m_tracerouteInProgress) {
        return;
    }
    
    // Check for root privileges
    if (geteuid() != 0) {
        QMessageBox::warning(this, "Permission Error", 
                           "Traceroute requires root privileges to create raw sockets.\n"
                           "Please run the application with sudo or as administrator.");
        return;
    }
    
    m_currentTarget = target;
    setTracerouteInProgress(true);
    clearResults();
    
    m_statusLabel->setText(QString("Tracing route to %1...").arg(target));
    
    QMetaObject::invokeMethod(m_worker, "performTraceroute", 
                             Qt::QueuedConnection, Q_ARG(QString, target));
}

void TracerouteWidget::onStopClicked() {
    if (m_tracerouteInProgress) {
        // Note: In a real implementation, you'd need to add a way to interrupt the traceroute
        setTracerouteInProgress(false);
        m_statusLabel->setText("Traceroute stopped by user");
        m_statusLabel->setStyleSheet("color: orange;");
    }
}

void TracerouteWidget::onClearClicked() {
    m_targetEdit->clear();
    clearResults();
    m_statusLabel->setText("Ready to perform traceroute");
}

void TracerouteWidget::onTracerouteCompleted(const TracerouteResult &result) {
    setTracerouteInProgress(false);
    updateResults(result);
}

void TracerouteWidget::onTracerouteFailed(const QString &error) {
    setTracerouteInProgress(false);
    m_statusLabel->setText(QString("Traceroute failed: %1").arg(error));
    m_statusLabel->setStyleSheet("color: red;");
}

void TracerouteWidget::onHopUpdate(int hopNumber, const QString &ipAddress, const QString &hostname, double responseTime) {
    // This would be used for real-time updates during traceroute
    Q_UNUSED(hopNumber)
    Q_UNUSED(ipAddress)
    Q_UNUSED(hostname)
    Q_UNUSED(responseTime)
}

void TracerouteWidget::onResultTableItemClicked(int row, int column) {
    Q_UNUSED(column)
    
    if (row < 0 || row >= m_resultsTable->rowCount()) {
        return;
    }
    
    QTableWidgetItem *ipItem = m_resultsTable->item(row, 1);
    QTableWidgetItem *hostnameItem = m_resultsTable->item(row, 2);
    
    if (!ipItem) {
        return;
    }
    
    QString ipAddress = ipItem->text();
    QString hostname = hostnameItem ? hostnameItem->text() : "";
    
    if (ipAddress.isEmpty() || ipAddress == "*") {
        return;
    }
    
    // Ask user what they want to do
    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Hop Actions");
    msgBox.setText(QString("What would you like to do with %1?").arg(ipAddress));
    
    QPushButton *tracerouteBtn = msgBox.addButton("Traceroute to this hop", QMessageBox::ActionRole);
    QPushButton *copyBtn = msgBox.addButton("Copy IP address", QMessageBox::ActionRole);
    QPushButton *cancelBtn = msgBox.addButton(QMessageBox::Cancel);
    
    msgBox.exec();
    
    if (msgBox.clickedButton() == tracerouteBtn) {
        m_targetEdit->setText(ipAddress);
        onTracerouteClicked();
    } else if (msgBox.clickedButton() == copyBtn) {
        QApplication::clipboard()->setText(ipAddress);
        m_statusLabel->setText(QString("Copied %1 to clipboard").arg(ipAddress));
    }
}

void TracerouteWidget::onTargetChanged() {
    // Enable/disable traceroute button based on input validity
    QString target = m_targetEdit->text().trimmed();
    m_tracerouteButton->setEnabled(!target.isEmpty() && isValidInput(target) && !m_tracerouteInProgress);
}

void TracerouteWidget::updateResults(const TracerouteResult &result) {
    m_statusLabel->setText(QString("Traceroute completed to %1 (%2)").arg(result.target_host).arg(result.target_ip));
    m_statusLabel->setStyleSheet("color: green;");
    
    // Add hops to table
    for (int i = 0; i < result.total_hops; i++) {
        addHopToTable(result.hops[i]);
    }
    
    // Update summary
    m_targetLabel->setText(QString("Target: %1 (%2)").arg(result.target_host).arg(result.target_ip));
    m_totalHopsLabel->setText(QString("Total Hops: %1").arg(result.total_hops));
    
    // Count successful hops
    int successfulHops = 0;
    for (int i = 0; i < result.total_hops; i++) {
        if (result.hops[i].probe_count > 0) {
            successfulHops++;
        }
    }
    m_successfulHopsLabel->setText(QString("Successful Hops: %1").arg(successfulHops));
    m_totalTimeLabel->setText(QString("Total Time: %.2f s").arg(result.total_time));
}

void TracerouteWidget::addHopToTable(const TracerouteHop &hop) {
    int row = m_resultsTable->rowCount();
    m_resultsTable->insertRow(row);
    
    // Hop number
    m_resultsTable->setItem(row, 0, new QTableWidgetItem(QString::number(hop.hop_number)));
    
    // IP Address
    QString ipAddress = hop.ip_address[0] ? QString(hop.ip_address) : "*";
    QTableWidgetItem *ipItem = new QTableWidgetItem(ipAddress);
    if (ipAddress != "*") {
        ipItem->setToolTip("Click to perform actions on this IP");
        ipItem->setForeground(QColor(0, 0, 255)); // Blue color for clickable items
    }
    m_resultsTable->setItem(row, 1, ipItem);
    
    // Hostname
    QString hostname = hop.hostname[0] ? QString(hop.hostname) : "*";
    m_resultsTable->setItem(row, 2, new QTableWidgetItem(hostname));
    
    // Probe times
    for (int probe = 0; probe < MAX_PROBES; probe++) {
        QString probeText;
        if (probe < hop.probe_count && hop.status[probe] == 0) {
            probeText = formatResponseTime(hop.response_times[probe]);
        } else {
            probeText = getStatusText(hop.status[probe]);
        }
        m_resultsTable->setItem(row, 3 + probe, new QTableWidgetItem(probeText));
    }
    
    // Auto-scroll to show latest hop
    m_resultsTable->scrollToBottom();
}

void TracerouteWidget::clearResults() {
    m_resultsTable->setRowCount(0);
    m_targetLabel->setText("Target: -");
    m_totalHopsLabel->setText("Total Hops: -");
    m_successfulHopsLabel->setText("Successful Hops: -");
    m_totalTimeLabel->setText("Total Time: -");
    m_statusLabel->setStyleSheet("color: #666; font-style: italic;");
}

void TracerouteWidget::setTracerouteInProgress(bool inProgress) {
    m_tracerouteInProgress = inProgress;
    m_tracerouteButton->setEnabled(!inProgress);
    m_stopButton->setEnabled(inProgress);
    m_targetEdit->setEnabled(!inProgress);
    m_maxHopsSpinBox->setEnabled(!inProgress);
    m_progressBar->setVisible(inProgress);
}

bool TracerouteWidget::isValidInput(const QString &input) {
    if (input.isEmpty()) {
        return false;
    }
    
    // Check for valid hostname or IP address
    QRegularExpression hostnameRegex("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$");
    QRegularExpression ipv4Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    QRegularExpression ipv6Regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    
    return hostnameRegex.match(input).hasMatch() || 
           ipv4Regex.match(input).hasMatch() || 
           ipv6Regex.match(input).hasMatch();
}

QString TracerouteWidget::formatResponseTime(double timeMs) {
    if (timeMs < 1.0) {
        return QString("< 1 ms");
    } else if (timeMs < 1000.0) {
        return QString("%.1f ms").arg(timeMs);
    } else {
        return QString("%.2f s").arg(timeMs / 1000.0);
    }
}

QString TracerouteWidget::getStatusText(int status) {
    switch (status) {
        case 0: return "OK";
        case 1: return "*";      // Timeout
        case 2: return "!";      // Unreachable
        default: return "?";     // Unknown
    }
}