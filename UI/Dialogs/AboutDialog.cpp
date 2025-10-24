#include "AboutDialog.h"
#include "../Utils/ApplicationManager.h"
#include <QApplication>
#include <QClipboard>
#include <QDesktopServices>
#include <QUrl>
#include <QMessageBox>
#include <QSysInfo>
#include <QStyleOption>
#include <QStyle>

AboutDialog::AboutDialog(QWidget *parent)
    : QDialog(parent)
{
    setWindowTitle("About " + QApplication::applicationName());
    setFixedSize(500, 400);
    setModal(true);
    
    setupUI();
}

void AboutDialog::copySystemInfo()
{
    QString systemInfo = getSystemInfo();
    QApplication::clipboard()->setText(systemInfo);
    
    QMessageBox::information(this, "Copied", 
        "System information has been copied to the clipboard.");
}

void AboutDialog::openWebsite()
{
    QDesktopServices::openUrl(QUrl("https://github.com/packetcapture/gui"));
}

void AboutDialog::openRepository()
{
    QDesktopServices::openUrl(QUrl("https://github.com/packetcapture/gui"));
}

void AboutDialog::showLicense()
{
    m_tabWidget->setCurrentWidget(m_licenseTab);
}

void AboutDialog::setupUI()
{
    m_mainLayout = new QVBoxLayout(this);
    
    // Create tab widget
    m_tabWidget = new QTabWidget;
    m_mainLayout->addWidget(m_tabWidget);
    
    // Setup tabs
    setupAboutTab();
    setupSystemTab();
    setupCreditsTab();
    setupLicenseTab();
    
    // Button layout
    m_buttonLayout = new QHBoxLayout;
    
    m_websiteButton = new QPushButton("Website");
    connect(m_websiteButton, &QPushButton::clicked, this, &AboutDialog::openWebsite);
    m_buttonLayout->addWidget(m_websiteButton);
    
    m_repositoryButton = new QPushButton("Repository");
    connect(m_repositoryButton, &QPushButton::clicked, this, &AboutDialog::openRepository);
    m_buttonLayout->addWidget(m_repositoryButton);
    
    m_buttonLayout->addStretch();
    
    m_closeButton = new QPushButton("Close");
    connect(m_closeButton, &QPushButton::clicked, this, &QDialog::accept);
    m_buttonLayout->addWidget(m_closeButton);
    
    m_mainLayout->addLayout(m_buttonLayout);
}

void AboutDialog::setupAboutTab()
{
    m_aboutTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_aboutTab);
    
    // Logo (placeholder)
    m_logoLabel = new QLabel;
    m_logoLabel->setAlignment(Qt::AlignCenter);
    m_logoLabel->setMinimumHeight(64);
    m_logoLabel->setStyleSheet("QLabel { background-color: #f0f0f0; border: 1px solid #ccc; }");
    m_logoLabel->setText("📡"); // Placeholder icon
    layout->addWidget(m_logoLabel);
    
    // Title
    m_titleLabel = new QLabel(QApplication::applicationName());
    m_titleLabel->setAlignment(Qt::AlignCenter);
    m_titleLabel->setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;");
    layout->addWidget(m_titleLabel);
    
    // Version
    m_versionLabel = new QLabel("Version " + QApplication::applicationVersion());
    m_versionLabel->setAlignment(Qt::AlignCenter);
    m_versionLabel->setStyleSheet("font-size: 12px; color: #666; margin-bottom: 10px;");
    layout->addWidget(m_versionLabel);
    
    // Description
    m_descriptionLabel = new QLabel(
        "A comprehensive network packet capture and analysis tool built with Qt. "
        "Provides real-time packet capture, protocol analysis, and detailed packet inspection capabilities."
    );
    m_descriptionLabel->setWordWrap(true);
    m_descriptionLabel->setAlignment(Qt::AlignCenter);
    m_descriptionLabel->setStyleSheet("margin: 10px; line-height: 1.4;");
    layout->addWidget(m_descriptionLabel);
    
    // Features
    m_featuresText = new QTextEdit;
    m_featuresText->setReadOnly(true);
    m_featuresText->setMaximumHeight(120);
    m_featuresText->setPlainText(
        "Key Features:\n"
        "• Real-time network packet capture\n"
        "• Multi-protocol analysis (TCP, UDP, HTTP, HTTPS, SSH)\n"
        "• Hexadecimal packet data viewer\n"
        "• Protocol tree structure display\n"
        "• Comprehensive error handling and recovery\n"
        "• Performance monitoring and memory management\n"
        "• Configurable capture filters\n"
        "• Export and import capabilities"
    );
    layout->addWidget(m_featuresText);
    
    m_tabWidget->addTab(m_aboutTab, "About");
}

void AboutDialog::setupSystemTab()
{
    m_systemTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_systemTab);
    
    // System info text
    m_systemInfoText = new QTextEdit;
    m_systemInfoText->setReadOnly(true);
    m_systemInfoText->setFont(QFont("Courier", 9));
    m_systemInfoText->setPlainText(getSystemInfo());
    layout->addWidget(m_systemInfoText);
    
    // Copy button
    m_copySystemButton = new QPushButton("Copy System Info");
    connect(m_copySystemButton, &QPushButton::clicked, this, &AboutDialog::copySystemInfo);
    layout->addWidget(m_copySystemButton);
    
    m_tabWidget->addTab(m_systemTab, "System");
}

void AboutDialog::setupCreditsTab()
{
    m_creditsTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_creditsTab);
    
    m_creditsText = new QTextEdit;
    m_creditsText->setReadOnly(true);
    m_creditsText->setPlainText(getCreditsInfo());
    layout->addWidget(m_creditsText);
    
    m_tabWidget->addTab(m_creditsTab, "Credits");
}

void AboutDialog::setupLicenseTab()
{
    m_licenseTab = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout(m_licenseTab);
    
    m_licenseText = new QTextEdit;
    m_licenseText->setReadOnly(true);
    m_licenseText->setFont(QFont("Courier", 8));
    m_licenseText->setPlainText(getLicenseInfo());
    layout->addWidget(m_licenseText);
    
    m_tabWidget->addTab(m_licenseTab, "License");
}

QString AboutDialog::getApplicationInfo() const
{
    QString info;
    info += QString("Application: %1\n").arg(QApplication::applicationName());
    info += QString("Version: %1\n").arg(QApplication::applicationVersion());
    info += QString("Organization: %1\n").arg(QApplication::organizationName());
    info += QString("Build Date: %1 %2\n").arg(__DATE__).arg(__TIME__);
    
    return info;
}

QString AboutDialog::getSystemInfo() const
{
    QString info;
    
    // Application info
    info += "=== APPLICATION INFORMATION ===\n";
    info += getApplicationInfo();
    info += "\n";
    
    // Qt information
    info += "=== QT INFORMATION ===\n";
    info += QString("Qt Version: %1\n").arg(qVersion());
    info += QString("Qt Build Version: %1\n").arg(QT_VERSION_STR);
    info += "\n";
    
    // System information
    info += "=== SYSTEM INFORMATION ===\n";
    info += QString("Operating System: %1\n").arg(QSysInfo::prettyProductName());
    info += QString("Kernel Type: %1\n").arg(QSysInfo::kernelType());
    info += QString("Kernel Version: %1\n").arg(QSysInfo::kernelVersion());
    info += QString("Architecture: %1\n").arg(QSysInfo::currentCpuArchitecture());
    info += QString("Build Architecture: %1\n").arg(QSysInfo::buildCpuArchitecture());
    info += QString("Machine Host Name: %1\n").arg(QSysInfo::machineHostName());
    info += "\n";
    
    // Runtime information
    info += "=== RUNTIME INFORMATION ===\n";
    if (ApplicationManager::instance()) {
        info += QString("Uptime: %1 seconds\n").arg(ApplicationManager::instance()->getUptime());
        info += QString("State: %1\n").arg(static_cast<int>(ApplicationManager::instance()->getState()));
    }
    
    return info;
}

QString AboutDialog::getCreditsInfo() const
{
    return QString(
        "=== PACKET CAPTURE GUI CREDITS ===\n\n"
        
        "DEVELOPMENT TEAM:\n"
        "• Lead Developer: [Your Name]\n"
        "• UI/UX Design: [Designer Name]\n"
        "• Protocol Analysis: [Developer Name]\n"
        "• Testing & QA: [Tester Name]\n\n"
        
        "THIRD-PARTY LIBRARIES:\n"
        "• Qt Framework - Cross-platform application framework\n"
        "  Copyright (C) The Qt Company Ltd.\n"
        "  Licensed under LGPL v3\n\n"
        
        "• libpcap - Packet capture library\n"
        "  Copyright (c) The Tcpdump Group\n"
        "  Licensed under BSD License\n\n"
        
        "SPECIAL THANKS:\n"
        "• The Qt Community for excellent documentation and support\n"
        "• The libpcap developers for the robust packet capture library\n"
        "• The open source community for inspiration and feedback\n"
        "• Beta testers who provided valuable feedback\n\n"
        
        "ICONS AND GRAPHICS:\n"
        "• Application icons from [Icon Source]\n"
        "• UI graphics designed by [Designer]\n\n"
        
        "DOCUMENTATION:\n"
        "• Technical writing by [Writer Name]\n"
        "• User manual by [Writer Name]\n\n"
        
        "For more information, visit our website or repository."
    );
}

QString AboutDialog::getLicenseInfo() const
{
    return QString(
        "MIT License\n\n"
        
        "Copyright (c) 2024 Packet Capture GUI Project\n\n"
        
        "Permission is hereby granted, free of charge, to any person obtaining a copy\n"
        "of this software and associated documentation files (the \"Software\"), to deal\n"
        "in the Software without restriction, including without limitation the rights\n"
        "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n"
        "copies of the Software, and to permit persons to whom the Software is\n"
        "furnished to do so, subject to the following conditions:\n\n"
        
        "The above copyright notice and this permission notice shall be included in all\n"
        "copies or substantial portions of the Software.\n\n"
        
        "THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n"
        "IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n"
        "FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n"
        "AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n"
        "LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n"
        "OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n"
        "SOFTWARE.\n\n"
        
        "=== THIRD-PARTY LICENSES ===\n\n"
        
        "This software uses the Qt framework, which is licensed under the\n"
        "GNU Lesser General Public License (LGPL) version 3.\n\n"
        
        "This software uses libpcap, which is licensed under the BSD License.\n\n"
        
        "For complete license information of third-party components,\n"
        "please refer to the documentation or visit the respective project websites."
    );
}