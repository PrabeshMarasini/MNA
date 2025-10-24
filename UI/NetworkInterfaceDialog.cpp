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
    , privilegeCheckTimer(new QTimer(this))
{
    setupUI();
    setupModel();
    connectSignals();
    
    // Initial refresh
    refreshInterfaceList();
    checkPrivileges();
    
    // Start periodic updates
    refreshTimer->start(5000); // Refresh every 5 seconds
    privilegeCheckTimer->start(10000); // Check privileges every 10 seconds
}

NetworkInterfaceDialog::~NetworkInterfaceDialog() {
    refreshTimer->stop();
    privilegeCheckTimer->stop();
}

QString NetworkInterfaceDialog::getSelectedInterface() const {
    return selectedInterface;
}

void NetworkInterfaceDialog::setupUI() {
    setWindowTitle("Select Network Interface");
    setWindowIcon(QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));
    setModal(true);
    resize(800, 600);
    
    // Main layout
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    
    // Title and instructions
    instructionLabel = new QLabel(this);
    instructionLabel->setText("Select a network interface for packet capture:");
    instructionLabel->setWordWrap(true);
    QFont titleFont = instructionLabel->font();
    titleFont.setPointSize(titleFont.pointSize() + 2);
    titleFont.setBold(true);
    instructionLabel->setFont(titleFont);
    mainLayout->addWidget(instructionLabel);
    
    // Privilege status
    privilegeStatusLabel = new QLabel(this);
    privilegeStatusLabel->setWordWrap(true);
    mainLayout->addWidget(privilegeStatusLabel);
    
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
    interfaceLayout->addWidget(interfaceTable);
    
    leftLayout->addWidget(interfaceGroup);
    splitter->addWidget(leftWidget);
    
    // Right side - Interface details and help
    QWidget *rightWidget = new QWidget();
    QVBoxLayout *rightLayout = new QVBoxLayout(rightWidget);
    
    // Interface details group
    QGroupBox *detailsGroup = new QGroupBox("Interface Details");
    QVBoxLayout *detailsLayout = new QVBoxLayout(detailsGroup);
    
    interfaceDetailsText = new QTextEdit();
    interfaceDetailsText->setReadOnly(true);
    interfaceDetailsText->setMaximumHeight(200);
    detailsLayout->addWidget(interfaceDetailsText);
    
    rightLayout->addWidget(detailsGroup);
    
    // Help and instructions group
    QGroupBox *helpGroup = new QGroupBox("Help & Instructions");
    QVBoxLayout *helpLayout = new QVBoxLayout(helpGroup);
    
    helpText = new QTextEdit();
    helpText->setReadOnly(true);
    helpText->setHtml(getHelpText());
    helpLayout->addWidget(helpText);
    
    rightLayout->addWidget(helpGroup);
    splitter->addWidget(rightWidget);
    
    // Set splitter proportions
    splitter->setStretchFactor(0, 2); // Interface list gets more space
    splitter->setStretchFactor(1, 1); // Details and help get less space
    
    // Progress bar for operations
    progressBar = new QProgressBar();
    progressBar->setVisible(false);
    mainLayout->addWidget(progressBar);
    
    // Button layout
    QHBoxLayout *buttonLayout = new QHBoxLayout();
    
    // Test button
    testButton = new QPushButton("Test Interface");
    testButton->setIcon(QApplication::style()->standardIcon(QStyle::SP_DialogApplyButton));
    testButton->setEnabled(false);
    buttonLayout->addWidget(testButton);
    
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
    
    // Configure table appearance
    QHeaderView *header = interfaceTable->horizontalHeader();
    header->setStretchLastSection(true);
    header->resizeSection(0, 120); // Interface name
    header->resizeSection(1, 200); // Description
    header->resizeSection(2, 80);  // Type
    header->resizeSection(3, 80);  // Status
    header->resizeSection(4, 150); // Addresses
    header->resizeSection(5, 100); // Can Capture
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
    connect(testButton, &QPushButton::clicked,
            this, &NetworkInterfaceDialog::onTestClicked);
    
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
    connect(privilegeCheckTimer, &QTimer::timeout,
            this, &NetworkInterfaceDialog::checkPrivileges);
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
        
        // Addresses
        QString addresses = info.addresses.isEmpty() ? "None" : info.addresses;
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

void NetworkInterfaceDialog::onTestClicked() {
    if (selectedInterface.isEmpty()) {
        return;
    }
    
    testButton->setEnabled(false);
    progressBar->setVisible(true);
    progressBar->setRange(0, 0);
    
    // Test interface access
    QString testResult = PrivilegeChecker::testInterfaceAccess(selectedInterface);
    
    // Show result in details
    interfaceDetailsText->append("\n--- Interface Test Result ---");
    interfaceDetailsText->append(testResult);
    
    progressBar->setVisible(false);
    testButton->setEnabled(true);
}

void NetworkInterfaceDialog::onFilterChanged() {
    refreshInterfaceList();
}

void NetworkInterfaceDialog::handleError(const QString &error) {
    interfaceDetailsText->append(QString("\n--- Error ---\n%1").arg(error));
}

void NetworkInterfaceDialog::checkPrivileges() {
    bool hasPrivileges = PrivilegeChecker::hasPacketCapturePrivileges();
    
    if (hasPrivileges) {
        privilegeStatusLabel->setText("✅ Packet capture privileges: OK");
        privilegeStatusLabel->setStyleSheet("color: green;");
    } else {
        privilegeStatusLabel->setText("⚠️ Packet capture privileges: INSUFFICIENT");
        privilegeStatusLabel->setStyleSheet("color: red;");
        
        // Show privilege instructions in help text
        QString instructions = PrivilegeChecker::getPrivilegeInstructions();
        helpText->setHtml(getHelpText() + "<br><br><b>Privilege Instructions:</b><br>" + 
                         instructions.replace("\n", "<br>"));
    }
}

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
        details += QString("<b>IP Addresses:</b> %1<br>").arg(info.addresses);
    }
    
    if (!info.errorMessage.isEmpty()) {
        details += QString("<b>Error:</b> <span style='color: red;'>%1</span><br>").arg(info.errorMessage);
    }
    
    // Add recommendations
    details += "<br><b>Recommendation:</b> ";
    if (info.canCapture && info.isUp && !info.isLoopback) {
        details += "<span style='color: green;'>Excellent choice for packet capture</span>";
    } else if (info.canCapture && !info.isLoopback) {
        details += "<span style='color: orange;'>Good choice, but interface is down</span>";
    } else if (info.isLoopback) {
        details += "<span style='color: gray;'>Loopback interface - only captures local traffic</span>";
    } else {
        details += "<span style='color: red;'>Not suitable for packet capture</span>";
    }
    
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
    testButton->setEnabled(hasSelection);
    
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

QString NetworkInterfaceDialog::getHelpText() const {
    return QString(
        "<b>How to select a network interface:</b><br>"
        "• <span style='color: green;'>Green highlighted</span> interfaces are ideal for packet capture<br>"
        "• <span style='color: orange;'>Yellow highlighted</span> interfaces may work but have limitations<br>"
        "• <span style='color: red;'>Red highlighted</span> interfaces are not suitable for capture<br>"
        "• Loopback interfaces only capture local traffic<br>"
        "• 'Up' status means the interface is active<br>"
        "• 'Can Capture' indicates packet capture capability<br><br>"
        
        "<b>Interface Types:</b><br>"
        "• 📶 Wireless interfaces (WiFi)<br>"
        "• 🔌 Ethernet interfaces (Wired)<br>"
        "• 🔄 Loopback interfaces (Local)<br>"
        "• 🚇 Tunnel interfaces (VPN)<br>"
        "• 📦 Virtual interfaces (Containers)<br><br>"
        
        "<b>Tips:</b><br>"
        "• Use 'Test Interface' to verify packet capture capability<br>"
        "• Refresh the list if interfaces change<br>"
        "• Check 'Show all interfaces' to see loopback and virtual interfaces<br>"
        "• Double-click an interface to select it quickly"
    );
}