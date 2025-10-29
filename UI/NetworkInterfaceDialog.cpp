#include "NetworkInterfaceDialog.h"
#include "Utils/NetworkInterfaceManager.h"
#include "Utils/PrivilegeChecker.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QSplitter>
#include <QTextEdit>
#include <QProgressBar>
#include <QTimer>
#include <QApplication>
#include <QStyle>
#include <QHeaderView>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QStandardItem>

NetworkInterfaceDialog::NetworkInterfaceDialog(QWidget *parent)
    : QDialog(parent)
    , interfaceManager(new NetworkInterfaceManager(this))
    , interfaceModel(new QStandardItemModel(this))
    , proxyModel(new QSortFilterProxyModel(this))
    , refreshTimer(new QTimer(this))

{
    setupUI();
    setupModel();
    connectSignals();
    
    // Initial refresh
    refreshInterfaceList();
    
    // Start periodic updates
    refreshTimer->start(5000); // Refresh every 5 seconds
}

NetworkInterfaceDialog::~NetworkInterfaceDialog() {
    refreshTimer->stop();
}

QString NetworkInterfaceDialog::getSelectedInterface() const {
    return selectedInterface;
}

void NetworkInterfaceDialog::setupUI() {
    setWindowTitle("Select Network Interface");
    setWindowIcon(QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));
    setModal(true);
    showMaximized(); // Make full screen
    
    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Title and instructions removed
    
    // Privilege status removed
    
    // Main content splitter
    QSplitter *splitter = new QSplitter(Qt::Horizontal, this);
    mainLayout->addWidget(splitter);
    
    // Left side - Interface list
    QWidget *leftWidget = new QWidget();
    QVBoxLayout *leftLayout = new QVBoxLayout(leftWidget);
    
    // Interface list group
    QGroupBox *interfaceGroup = new QGroupBox("Available Network Interfaces");
    QVBoxLayout *interfaceLayout = new QVBoxLayout(interfaceGroup);
    
    // Filter controls
    QHBoxLayout *filterLayout = new QHBoxLayout();
    
    showAllCheckBox = new QCheckBox("Show all interfaces");
    showAllCheckBox->setChecked(false);
    filterLayout->addWidget(showAllCheckBox);
    

    
    filterLayout->addStretch();
    
    refreshButton = new QPushButton("Refresh");
    refreshButton->setIcon(QApplication::style()->standardIcon(QStyle::SP_BrowserReload));
    filterLayout->addWidget(refreshButton);
    
    interfaceLayout->addLayout(filterLayout);
    
    // Interface table
    interfaceTable = new QTableView();
    interfaceTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    interfaceTable->setSelectionMode(QAbstractItemView::SingleSelection);
    interfaceTable->setAlternatingRowColors(true);
    interfaceTable->setSortingEnabled(true);
    interfaceTable->verticalHeader()->setVisible(false);
    
    // Improve text display for long interface names
    interfaceTable->setWordWrap(true);
    interfaceTable->setTextElideMode(Qt::ElideNone);
    interfaceTable->resizeRowsToContents();
    
    interfaceLayout->addWidget(interfaceTable);
    
    leftLayout->addWidget(interfaceGroup);
    splitter->addWidget(leftWidget);
    
    // Right side - Interface details
    QWidget *rightWidget = new QWidget();
    QVBoxLayout *rightLayout = new QVBoxLayout(rightWidget);
    
    // Interface details group
    QGroupBox *detailsGroup = new QGroupBox("Interface Details");
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    
    interfaceDetailsText = new QTextEdit();
    interfaceDetailsText->setReadOnly(true);
    // Remove height restriction to allow full height
    detailsLayout->addWidget(interfaceDetailsText);
    
    rightLayout->addWidget(detailsGroup);
    
    // Add stretch to keep rest of area blank
    rightLayout->addStretch();
    
    // Help and instructions group removed
    splitter->addWidget(rightWidget);
    
    // Set splitter proportions for full screen layout
    splitter->setStretchFactor(0, 1); // Interface list on left
    splitter->setStretchFactor(1, 1); // Details on right, equal space
    
    // Progress bar for operations
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);
    
    // Button layout
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    // Test button removed
    
    buttonLayout->addStretch();
    
    // Dialog buttons
    selectButton = new QPushButton("Select");
    selectButton->setIcon(QApplication::style()->standardIcon(QStyle::SP_DialogOkButton));
    selectButton->setEnabled(false);
    selectButton->setDefault(true);
    buttonLayout->addWidget(selectButton);
    
    cancelButton = new QPushButton("Cancel");
    cancelButton->setIcon(QApplication::style()->standardIcon(QStyle::SP_DialogCancelButton));
    buttonLayout->addWidget(cancelButton);
    
    mainLayout->addLayout(buttonLayout);
}

void NetworkInterfaceDialog::setupModel() {
    // Set up the model
    interfaceModel->setHorizontalHeaderLabels({
        "Interface", "Description", "Type", "Status", "Addresses", "Can Capture"
    });
    
    // Set up proxy model for filtering
    proxyModel->setSourceModel(interfaceModel);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterKeyColumn(-1); // Filter all columns
    
    interfaceTable->setModel(proxyModel);
    
    // Configure table appearance with better column sizing
    QHeaderView *header = interfaceTable->horizontalHeader();
    
    // Set resize modes for better column management
    header->setSectionResizeMode(0, QHeaderView::ResizeToContents); // Interface name - auto-size
    header->setSectionResizeMode(1, QHeaderView::Stretch);          // Description - stretch to fill
    header->setSectionResizeMode(2, QHeaderView::ResizeToContents); // Type - auto-size
    header->setSectionResizeMode(3, QHeaderView::ResizeToContents); // Status - auto-size
    header->setSectionResizeMode(4, QHeaderView::Interactive);      // Addresses - user resizable
    header->setSectionResizeMode(5, QHeaderView::ResizeToContents); // Can Capture - auto-size
    
    // Set minimum widths to ensure readability
    header->setMinimumSectionSize(80);
    interfaceTable->setColumnWidth(4, 200); // Set initial width for addresses column
}

void NetworkInterfaceDialog::connectSignals() {
    // Interface manager signals
    connect(interfaceManager, &NetworkInterfaceManager::interfaceListChanged,
            this, &NetworkInterfaceDialog::refreshInterfaceList);
    connect(interfaceManager, &NetworkInterfaceManager::errorOccurred,
            this, &NetworkInterfaceDialog::handleError);
    
    // UI signals
    connect(refreshButton, &QPushButton::clicked,
            this, &NetworkInterfaceDialog::onRefreshClicked);
    connect(selectButton, &QPushButton::clicked,
            this, &NetworkInterfaceDialog::onSelectClicked);
    connect(cancelButton, &QPushButton::clicked,
            this, &QDialog::reject);
    // Test button connection removed
    
    // Table selection
    connect(interfaceTable->selectionModel(), &QItemSelectionModel::currentRowChanged,
            this, &NetworkInterfaceDialog::onInterfaceSelected);
    connect(interfaceTable, &QTableView::doubleClicked,
            this, &NetworkInterfaceDialog::onInterfaceDoubleClicked);
    
    // Filter checkbox
    connect(showAllCheckBox, &QCheckBox::toggled,
            this, &NetworkInterfaceDialog::onFilterChanged);
    

    
    // Timers
    connect(refreshTimer, &QTimer::timeout,
            this, &NetworkInterfaceDialog::refreshInterfaceList);
    // Privilege check timer connection removed
}

void NetworkInterfaceDialog::refreshInterfaceList() {
    progressBar->setVisible(true);
    progressBar->setRange(0, 0); // Indeterminate progress
    
    // Get interface list
    QList<InterfaceInfo> interfaces = interfaceManager->getDetailedInterfaceList();
    
    // Clear existing items
    interfaceModel->clear();
    interfaceModel->setHorizontalHeaderLabels({
        "Interface", "Description", "Type", "Status", "Addresses", "Can Capture"
    });
    
    // Add interfaces to model
    for (const InterfaceInfo &info : interfaces) {
        // Apply filtering
        if (!showAllCheckBox->isChecked() && info.isLoopback) {
            continue; // Skip loopback interfaces unless showing all
        }
        
        QList<QStandardItem*> row;
        
        // Interface name with icon
        QStandardItem *nameItem = new QStandardItem(info.name);
        QString icon = InterfaceUtils::getInterfaceIcon(info.name);
        nameItem->setText(icon + " " + info.name);
        nameItem->setData(info.name, Qt::UserRole); // Store original name
        row.append(nameItem);
        
        // Description
        QStandardItem *descItem = new QStandardItem(info.description);
        row.append(descItem);
        
        // Type
        QString type = interfaceManager->getInterfaceType(info.name);
        QStandardItem *typeItem = new QStandardItem(type);
        row.append(typeItem);
        
        // Status
        QString status = info.isUp ? "Up" : "Down";
        QStandardItem *statusItem = new QStandardItem(status);
        if (info.isUp) {
            statusItem->setForeground(QColor(0, 128, 0)); // Green
        } else {
            statusItem->setForeground(QColor(128, 0, 0)); // Red
        }
        row.append(statusItem);
        
        // Addresses - clean up the display
        QString addresses;
        if (info.addresses.isEmpty()) {
            addresses = "None";
        } else {
            // Clean up addresses - remove interface names and extra info
            QStringList addrList = info.addresses.split(", ");
            QStringList cleanAddresses;
            for (const QString &addr : addrList) {
                QString cleanAddr = addr.trimmed();
                // Remove interface name suffix (e.g., %wlan0)
                if (cleanAddr.contains('%')) {
                    cleanAddr = cleanAddr.split('%').first();
                }
                // Skip empty addresses
                if (!cleanAddr.isEmpty()) {
                    cleanAddresses.append(cleanAddr);
                }
            }
            addresses = cleanAddresses.join(", ");
            if (addresses.isEmpty()) {
                addresses = "None";
            }
        }
        QStandardItem *addrItem = new QStandardItem(addresses);
        row.append(addrItem);
        
        // Can capture
        QString canCapture = info.canCapture ? "Yes" : "No";
        QStandardItem *captureItem = new QStandardItem(canCapture);
        if (info.canCapture) {
            captureItem->setForeground(QColor(0, 128, 0)); // Green
        } else {
            captureItem->setForeground(QColor(128, 0, 0)); // Red
        }
        row.append(captureItem);
        
        // Set row background based on suitability
        QColor backgroundColor;
        if (info.canCapture && info.isUp && !info.isLoopback) {
            backgroundColor = QColor(240, 255, 240); // Light green - best choice
        } else if (info.canCapture && !info.isLoopback) {
            backgroundColor = QColor(255, 255, 240); // Light yellow - good choice
        } else if (info.isLoopback) {
            backgroundColor = QColor(245, 245, 245); // Light gray - loopback
        } else {
            backgroundColor = QColor(255, 240, 240); // Light red - problematic
        }
        
        for (QStandardItem *item : row) {
            item->setBackground(backgroundColor);
        }
        
        interfaceModel->appendRow(row);
    }
    
    // Auto-select best interface
    autoSelectBestInterface();
    
    // Resize rows to fit content properly
    interfaceTable->resizeRowsToContents();
    
    progressBar->setVisible(false);
    updateButtonStates();
}

void NetworkInterfaceDialog::onInterfaceSelected() {
    QModelIndex current = interfaceTable->currentIndex();
    if (!current.isValid()) {
        selectedInterface.clear();
        interfaceDetailsText->clear();
        updateButtonStates();
        return;
    }
    
    // Get interface name from the model
    QModelIndex nameIndex = proxyModel->index(current.row(), 0);
    QVariant nameData = proxyModel->data(nameIndex, Qt::UserRole);
    selectedInterface = nameData.toString();
    
    // Update interface details
    updateInterfaceDetails(selectedInterface);
    updateButtonStates();
}

void NetworkInterfaceDialog::onInterfaceDoubleClicked(const QModelIndex &index) {
    Q_UNUSED(index)
    if (!selectedInterface.isEmpty() && selectButton->isEnabled()) {
        accept();
    }
}

void NetworkInterfaceDialog::onRefreshClicked() {
    refreshInterfaceList();
}

void NetworkInterfaceDialog::onSelectClicked() {
    if (!selectedInterface.isEmpty()) {
        accept();
    }
}

// Test interface method removed

void NetworkInterfaceDialog::onFilterChanged() {
    refreshInterfaceList();
}

void NetworkInterfaceDialog::handleError(const QString &error) {
    interfaceDetailsText->append(QString("\n--- Error ---\n%1").arg(error));
}

// Check privileges method removed

void NetworkInterfaceDialog::updateInterfaceDetails(const QString &interface) {
    if (interface.isEmpty()) {
        interfaceDetailsText->clear();
        return;
    }
    
    InterfaceInfo info = interfaceManager->getInterfaceInfo(interface);
    
    QString details;
    details += QString("<b>Interface:</b> %1<br>").arg(info.name);
    details += QString("<b>Description:</b> %1<br>").arg(info.description);
    details += QString("<b>Type:</b> %1<br>").arg(interfaceManager->getInterfaceType(interface));
    details += QString("<b>Status:</b> %1<br>").arg(info.isUp ? "Up" : "Down");
    details += QString("<b>Loopback:</b> %1<br>").arg(info.isLoopback ? "Yes" : "No");
    details += QString("<b>Can Capture:</b> %1<br>").arg(info.canCapture ? "Yes" : "No");
    
    if (!info.addresses.isEmpty()) {
        // Clean up addresses display
        QStringList addrList = info.addresses.split(", ");
        QStringList cleanAddresses;
        for (const QString &addr : addrList) {
            QString cleanAddr = addr.trimmed();
            // Remove interface name suffix (e.g., %wlan0)
            if (cleanAddr.contains('%')) {
                cleanAddr = cleanAddr.split('%').first();
            }
            // Skip empty addresses
            if (!cleanAddr.isEmpty()) {
                cleanAddresses.append(cleanAddr);
            }
        }
        if (!cleanAddresses.isEmpty()) {
            details += QString("<b>IP Addresses:</b> %1<br>").arg(cleanAddresses.join(", "));
        }
    }
    
    if (!info.errorMessage.isEmpty()) {
        details += QString("<b>Error:</b> <span style='color: red;'>%1</span><br>").arg(info.errorMessage);
    }
    
    // Recommendations removed
    
    interfaceDetailsText->setHtml(details);
}

void NetworkInterfaceDialog::updateButtonStates() {
    bool hasSelection = !selectedInterface.isEmpty();
    bool canCapture = false;
    
    if (hasSelection) {
        InterfaceInfo info = interfaceManager->getInterfaceInfo(selectedInterface);
        canCapture = info.canCapture;
    }
    
    selectButton->setEnabled(hasSelection);
    
    // Update select button text based on capability
    if (hasSelection && canCapture) {
        selectButton->setText("Select");
        selectButton->setStyleSheet("");
    } else if (hasSelection) {
        selectButton->setText("Select (Limited)");
        selectButton->setStyleSheet("color: orange;");
    } else {
        selectButton->setText("Select");
        selectButton->setStyleSheet("");
    }
}

void NetworkInterfaceDialog::autoSelectBestInterface() {
    QString bestInterface = interfaceManager->getBestCaptureInterface();
    
    if (bestInterface.isEmpty()) {
        return;
    }
    
    // Find the interface in the table and select it
    for (int row = 0; row < proxyModel->rowCount(); ++row) {
        QModelIndex nameIndex = proxyModel->index(row, 0);
        QVariant nameData = proxyModel->data(nameIndex, Qt::UserRole);
        
        if (nameData.toString() == bestInterface) {
            interfaceTable->selectRow(row);
            interfaceTable->scrollTo(nameIndex);
            break;
        }
    }
}

