#ifndef ABOUTDIALOG_H
#define ABOUTDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTextEdit>
#include <QTabWidget>
#include <QScrollArea>

/**
 * @brief About dialog showing application information
 * 
 * This dialog displays comprehensive information about the application
 * including version, credits, license, and system information.
 */
class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AboutDialog(QWidget *parent = nullptr);

private slots:
    void copySystemInfo();
    void openWebsite();
    void openRepository();
    void showLicense();

private:
    void setupUI();
    void setupAboutTab();
    void setupSystemTab();
    void setupCreditsTab();
    void setupLicenseTab();
    
    QString getApplicationInfo() const;
    QString getSystemInfo() const;
    QString getCreditsInfo() const;
    QString getLicenseInfo() const;

    // UI components
    QVBoxLayout *m_mainLayout;
    QTabWidget *m_tabWidget;
    
    // About tab
    QWidget *m_aboutTab;
    QLabel *m_logoLabel;
    QLabel *m_titleLabel;
    QLabel *m_versionLabel;
    QLabel *m_descriptionLabel;
    QTextEdit *m_featuresText;
    
    // System tab
    QWidget *m_systemTab;
    QTextEdit *m_systemInfoText;
    QPushButton *m_copySystemButton;
    
    // Credits tab
    QWidget *m_creditsTab;
    QTextEdit *m_creditsText;
    
    // License tab
    QWidget *m_licenseTab;
    QTextEdit *m_licenseText;
    
    // Buttons
    QHBoxLayout *m_buttonLayout;
    QPushButton *m_websiteButton;
    QPushButton *m_repositoryButton;
    QPushButton *m_closeButton;
};

#endif // ABOUTDIALOG_H