#include "DnsLookupWidget.h"
#include <QApplication>
#include <QMessageBox>
#include <QClipboard>
#include <QHeaderView>
#include <QSplitter>
#include <QRegularExpression>
#include <QRegularExpressionValidator>

// DnsLookupWorker Implementation
DnsLookupWorker::DnsLookupWorker(QObject *parent) : QObject(parent) {}

void DnsLookupWorker::performLookup(const QString &target, const QString &recordType) {
    QMutexLocker locker(&m_mutex);
    
    DnsLookupResult result;
    int status = perform_dns_lookup(target.toUtf8().constData(), 
                                   recordType.toUtf8().constData(), 
                                   &result);
    
    if (status == 0) {
        emit lookupCompleted(result);
    } else {
        emit lookupFailed(QString("DNS lookup failed: %1").arg(result.error_message));
    }
}

void DnsLookupWorker::performReverseLookup(const QString &ipAddress) {
    QMutexLocker locker(&m_mutex);
    
    char hostname[256];
    int status = reverse_dns_lookup(ipAddress.toUtf8().constData(), hostname, sizeof(hostname));
    
    if (status == 0) {
        emit reverseLookupCompleted(ipAddress, QString(hostname));
    } else {
        emit reverseLookupCompleted(ipAddress, "No PTR record found");
    }
}

// DnsLookupWidget Implementation
DnsLookupWidget::DnsLookupWidget(QWidget *parent)
    : QWidget(parent)
    , m_mainLayout(nullptr)
    , m_workerThread(nullptr)
    , m_worker(nullptr)
    , m_lookupInProgress(false)
{
    setupUI();
    
    // Create worker thread
    m_workerThread = new QThread(this);
    m_worker = new DnsLookupWorker();
    m_worker->moveToThread(m_workerThread);
    
    // Connect signals
    connect(m_workerThread, &QThread::started, m_worker, [this]() {
        // Thread started
    });
    
    connect(m_worker, &DnsLookupWorker::lookupCompleted,
            this, &DnsLookupWidget::onLookupCompleted);
    connect(m_worker, &DnsLookupWorker::reverseLookupCompleted,
            this, &DnsLookupWidget::onReverseLookupCompleted);
    connect(m_worker, &DnsLookupWorker::lookupFailed,
            this, &DnsLookupWidget::onLookupFailed);
    
    m_workerThread->start();
}

DnsLookupWidget::~DnsLookupWidget() {
    if (m_workerThread) {
        m_workerThread->quit();
        m_workerThread->wait();
        delete m_worker;
    }
}

void DnsLookupWidget::setupUI() {
    m_mainLayout = new QVBoxLayout(this);
    m_mainLayout->setSpacing(10);
    m_mainLayout->setContentsMargins(10, 10, 10, 10);
    
    // Input Group
    m_inputGroup = new QGroupBox("DNS Lookup", this);
    m_inputLayout = new QHBoxLayout(m_inputGroup);
    
    m_targetEdit = new QLineEdit(this);
    m_targetEdit->setPlaceholderText("Enter hostname or IP address (e.g., google.com or 8.8.8.8)");
    m_targetEdit->setMinimumWidth(300);
    
    m_recordTypeCombo = new QComboBox(this);
    m_recordTypeCombo->addItems({"A", "AAAA", "PTR", "MX", "NS", "TXT", "CNAME"});
    m_recordTypeCombo->setCurrentText("A");
    m_recordTypeCombo->setMinimumWidth(80);
    
    m_lookupButton = new QPushButton("Lookup", this);
    m_lookupButton->setMinimumWidth(80);
    m_lookupButton->setDefault(true);
    
    m_clearButton = new QPushButton("Clear", this);
    m_clearButton->setMinimumWidth(80);
    
    m_progressBar = new QProgressBar(this);
    m_progressBar->setVisible(false);
    m_progressBar->setRange(0, 0); // Indeterminate progress
    
    m_inputLayout->addWidget(new QLabel("Target:"));
    m_inputLayout->addWidget(m_targetEdit);
    m_inputLayout->addWidget(new QLabel("Type:"));
    m_inputLayout->addWidget(m_recordTypeCombo);
    m_inputLayout->addWidget(m_lookupButton);
    m_inputLayout->addWidget(m_clearButton);
    m_inputLayout->addStretch();
    
    m_mainLayout->addWidget(m_inputGroup);
    m_mainLayout->addWidget(m_progressBar);
    
    // Results Group
    m_resultsGroup = new QGroupBox("Results", this);
    m_resultsLayout = new QVBoxLayout(m_resultsGroup);
    
    m_statusLabel = new QLabel("Ready to perform DNS lookup", this);
    m_statusLabel->setStyleSheet("color: #666; font-style: italic;");
    
    // Results table
    m_resultsTable = new QTableWidget(this);
    m_resultsTable->setColumnCount(3);
    QStringList headers = {"Type", "Data", "Additional Info"};
    m_resultsTable->setHorizontalHeaderLabels(headers);
    m_resultsTable->horizontalHeader()->setStretchLastSection(true);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_resultsTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_resultsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_resultsTable->setAlternatingRowColors(true);
    m_resultsTable->setSortingEnabled(true);
    
    m_resultsLayout->addWidget(m_statusLabel);
    m_resultsLayout->addWidget(m_resultsTable);
    
    m_mainLayout->addWidget(m_resultsGroup);
    
    // Details Group
    m_detailsGroup = new QGroupBox("Query Details", this);
    m_detailsLayout = new QVBoxLayout(m_detailsGroup);
    
    m_queryTimeLabel = new QLabel("Query Time: -", this);
    m_dnsServerLabel = new QLabel("DNS Server: -", this);
    m_recordCountLabel = new QLabel("Records Found: -", this);
    
    m_detailsLayout->addWidget(m_queryTimeLabel);
    m_detailsLayout->addWidget(m_dnsServerLabel);
    m_detailsLayout->addWidget(m_recordCountLabel);
    
    m_mainLayout->addWidget(m_detailsGroup);
    
    // Connect signals
    connect(m_lookupButton, &QPushButton::clicked, this, &DnsLookupWidget::onLookupClicked);
    connect(m_clearButton, &QPushButton::clicked, this, &DnsLookupWidget::onClearClicked);
    connect(m_targetEdit, &QLineEdit::returnPressed, this, &DnsLookupWidget::onLookupClicked);
    connect(m_targetEdit, &QLineEdit::textChanged, this, &DnsLookupWidget::onTargetChanged);
    connect(m_resultsTable, &QTableWidget::cellClicked, this, &DnsLookupWidget::onResultTableItemClicked);
    
    // Set initial state
    clearResults();
}

void DnsLookupWidget::onLookupClicked() {
    QString target = m_targetEdit->text().trimmed();
    
    if (target.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a hostname or IP address.");
        return;
    }
    
    if (!isValidInput(target)) {
        QMessageBox::warning(this, "Input Error", "Please enter a valid hostname or IP address.");
        return;
    }
    
    if (m_lookupInProgress) {
        return;
    }
    
    m_currentTarget = target;
    setLookupInProgress(true);
    clearResults();
    
    m_statusLabel->setText(QString("Looking up %1...").arg(target));
    
    QString recordType = m_recordTypeCombo->currentText();
    
    // Check if target is an IP address for reverse lookup
    QRegularExpression ipv4Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    QRegularExpression ipv6Regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    
    if (ipv4Regex.match(target).hasMatch() || ipv6Regex.match(target).hasMatch()) {
        // Perform reverse lookup
        QMetaObject::invokeMethod(m_worker, "performReverseLookup", 
                                 Qt::QueuedConnection, Q_ARG(QString, target));
    } else {
        // Perform forward lookup
        QMetaObject::invokeMethod(m_worker, "performLookup", 
                                 Qt::QueuedConnection, Q_ARG(QString, target), Q_ARG(QString, recordType));
    }
}

void DnsLookupWidget::onClearClicked() {
    m_targetEdit->clear();
    clearResults();
    m_statusLabel->setText("Ready to perform DNS lookup");
}

void DnsLookupWidget::onLookupCompleted(const DnsLookupResult &result) {
    setLookupInProgress(false);
    updateResults(result);
}

void DnsLookupWidget::onReverseLookupCompleted(const QString &ipAddress, const QString &hostname) {
    setLookupInProgress(false);
    
    m_statusLabel->setText(QString("Reverse lookup completed for %1").arg(ipAddress));
    
    // Add reverse lookup result
    addResultToTable("PTR", hostname, QString("Reverse lookup for %1").arg(ipAddress));
    
    // Update details
    m_queryTimeLabel->setText("Query Time: < 1 ms");
    m_dnsServerLabel->setText("DNS Server: System Default");
    m_recordCountLabel->setText("Records Found: 1");
}

void DnsLookupWidget::onLookupFailed(const QString &error) {
    setLookupInProgress(false);
    m_statusLabel->setText(QString("Lookup failed: %1").arg(error));
    m_statusLabel->setStyleSheet("color: red;");
}

void DnsLookupWidget::onResultTableItemClicked(int row, int column) {
    Q_UNUSED(column)
    
    if (row < 0 || row >= m_resultsTable->rowCount()) {
        return;
    }
    
    QTableWidgetItem *dataItem = m_resultsTable->item(row, 1);
    if (!dataItem) {
        return;
    }
    
    QString data = dataItem->text();
    
    // Check if the clicked data is an IP address that we can do reverse lookup on
    QRegularExpression ipv4Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    QRegularExpression ipv6Regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    
    if (ipv4Regex.match(data).hasMatch() || ipv6Regex.match(data).hasMatch()) {
        // Ask user if they want to perform reverse lookup
        int ret = QMessageBox::question(this, "Reverse Lookup", 
                                       QString("Do you want to perform a reverse DNS lookup for %1?").arg(data),
                                       QMessageBox::Yes | QMessageBox::No);
        
        if (ret == QMessageBox::Yes) {
            m_targetEdit->setText(data);
            onLookupClicked();
        }
    } else {
        // For hostnames, ask if they want to lookup the hostname
        int ret = QMessageBox::question(this, "DNS Lookup", 
                                       QString("Do you want to perform a DNS lookup for %1?").arg(data),
                                       QMessageBox::Yes | QMessageBox::No);
        
        if (ret == QMessageBox::Yes) {
            m_targetEdit->setText(data);
            m_recordTypeCombo->setCurrentText("A");
            onLookupClicked();
        }
    }
}

void DnsLookupWidget::onTargetChanged() {
    QString target = m_targetEdit->text().trimmed();
    
    // Auto-detect record type based on input
    QRegularExpression ipv4Regex("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$");
    QRegularExpression ipv6Regex("^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$");
    
    if (ipv4Regex.match(target).hasMatch() || ipv6Regex.match(target).hasMatch()) {
        m_recordTypeCombo->setCurrentText("PTR");
    } else if (!target.isEmpty()) {
        m_recordTypeCombo->setCurrentText("A");
    }
}

void DnsLookupWidget::updateResults(const DnsLookupResult &result) {
    if (result.status != 0) {
        m_statusLabel->setText(QString("Lookup failed: %1").arg(result.error_message));
        m_statusLabel->setStyleSheet("color: red;");
        return;
    }
    
    m_statusLabel->setText(QString("Lookup completed for %1").arg(result.hostname));
    m_statusLabel->setStyleSheet("color: green;");
    
    // Add results to table
    for (int i = 0; i < result.record_count; i++) {
        const DnsRecord &record = result.records[i];
        addResultToTable(QString(record.type), QString(record.data));
    }
    
    // Update details
    m_queryTimeLabel->setText(QString("Query Time: %1").arg(formatQueryTime(result.query_time_ms)));
    m_dnsServerLabel->setText(QString("DNS Server: %1").arg(result.dns_server));
    m_recordCountLabel->setText(QString("Records Found: %1").arg(result.record_count));
}

void DnsLookupWidget::addResultToTable(const QString &type, const QString &data, const QString &extra) {
    int row = m_resultsTable->rowCount();
    m_resultsTable->insertRow(row);
    
    m_resultsTable->setItem(row, 0, new QTableWidgetItem(type));
    m_resultsTable->setItem(row, 1, new QTableWidgetItem(data));
    m_resultsTable->setItem(row, 2, new QTableWidgetItem(extra));
    
    // Make data column clickable for backlinks
    QTableWidgetItem *dataItem = m_resultsTable->item(row, 1);
    dataItem->setToolTip("Click to perform lookup on this address");
    dataItem->setForeground(QColor(0, 0, 255)); // Blue color for clickable items
}

void DnsLookupWidget::clearResults() {
    m_resultsTable->setRowCount(0);
    m_queryTimeLabel->setText("Query Time: -");
    m_dnsServerLabel->setText("DNS Server: -");
    m_recordCountLabel->setText("Records Found: -");
    m_statusLabel->setStyleSheet("color: #666; font-style: italic;");
}

void DnsLookupWidget::setLookupInProgress(bool inProgress) {
    m_lookupInProgress = inProgress;
    m_lookupButton->setEnabled(!inProgress);
    m_targetEdit->setEnabled(!inProgress);
    m_recordTypeCombo->setEnabled(!inProgress);
    m_progressBar->setVisible(inProgress);
}

bool DnsLookupWidget::isValidInput(const QString &input) {
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

QString DnsLookupWidget::formatQueryTime(double timeMs) {
    if (timeMs < 1.0) {
        return QString("< 1 ms");
    } else if (timeMs < 1000.0) {
        return QString("%.1f ms").arg(timeMs);
    } else {
        return QString("%.2f s").arg(timeMs / 1000.0);
    }
}