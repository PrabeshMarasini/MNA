#include <QApplication>
#include <QStyleFactory>
#include <QDir>
#include <QMessageBox>
#include <QCommandLineParser>
#include <QCommandLineOption>
#include <QSplashScreen>
#include <QPixmap>
#include <QTimer>
#include "NetworkInterfaceDialog.h"
#include "MainWindow.h"
#include "Utils/ApplicationManager.h"
#include "Utils/SettingsManager.h"
#include "Utils/ErrorHandler.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    // Set application properties
    app.setApplicationName("Packet Capture GUI");
    app.setApplicationVersion("1.0.0");
    app.setOrganizationName("PacketAnalyzer");
    app.setApplicationDisplayName("Packet Capture & Analysis Tool");
    
    // Initialize application manager
    ApplicationManager* appManager = ApplicationManager::instance();
    if (!appManager->initialize(&app)) {
        QMessageBox::critical(nullptr, "Initialization Error", 
            "Failed to initialize application. Please check the logs for details.");
        return 1;
    }
    
    // Show splash screen
    QSplashScreen *splash = nullptr;
    // QPixmap splashPixmap(":/images/splash.png");
    // if (!splashPixmap.isNull()) {
    //     splash = new QSplashScreen(splashPixmap);
    //     splash->show();
    //     splash->showMessage("Loading...", Qt::AlignBottom | Qt::AlignCenter, Qt::white);
    //     app.processEvents();
    // }
    
    try {
        // Set up command line parser
        QCommandLineParser parser;
        parser.setApplicationDescription("A comprehensive packet capture and analysis tool");
        parser.addHelpOption();
        parser.addVersionOption();
        
        QCommandLineOption interfaceOption(QStringList() << "i" << "interface",
                                         "Network interface to capture from",
                                         "interface");
        parser.addOption(interfaceOption);
        
        QCommandLineOption debugOption(QStringList() << "d" << "debug",
                                     "Enable debug mode");
        parser.addOption(debugOption);
        
        QCommandLineOption configOption(QStringList() << "c" << "config",
                                      "Configuration file path",
                                      "config");
        parser.addOption(configOption);
        
        parser.process(app);
        
        // Apply command line options
        if (parser.isSet(debugOption)) {
            SettingsManager::instance()->setDebugMode(true);
            ErrorHandler::instance()->setLogLevel(ErrorHandler::Debug);
        }
        
        if (parser.isSet(configOption)) {
            QString configPath = parser.value(configOption);
            if (!SettingsManager::instance()->importSettings(configPath)) {
                QMessageBox::warning(nullptr, "Configuration Warning",
                    QString("Failed to load configuration from: %1\nUsing default settings.").arg(configPath));
            }
        }
        
        QString selectedInterface;
        
        // Check if interface was specified via command line
        if (parser.isSet(interfaceOption)) {
            selectedInterface = parser.value(interfaceOption);
        } else {
            // Try to get last used interface from settings
            selectedInterface = SettingsManager::instance()->getLastUsedInterface();
            
            // If no saved interface or auto-start is disabled, show dialog
            if (selectedInterface.isEmpty() || !SettingsManager::instance()->getAutoStartCapture()) {
                if (splash) {
                    splash->showMessage("Selecting network interface...", Qt::AlignBottom | Qt::AlignCenter, Qt::white);
                    app.processEvents();
                }
                
                NetworkInterfaceDialog dialog;
                if (dialog.exec() == QDialog::Accepted) {
                    selectedInterface = dialog.getSelectedInterface();
                    // Save selected interface
                    SettingsManager::instance()->setLastUsedInterface(selectedInterface);
                    SettingsManager::instance()->addToInterfaceHistory(selectedInterface);
                } else {
                    // User cancelled interface selection
                    if (splash) delete splash;
                    return 0;
                }
            }
        }
        
        // Validate selected interface
        if (selectedInterface.isEmpty()) {
            if (splash) delete splash;
            QMessageBox::critical(nullptr, "Error", 
                                "No network interface selected. Application will exit.");
            return 1;
        }
        
        if (splash) {
            splash->showMessage("Initializing main window...", Qt::AlignBottom | Qt::AlignCenter, Qt::white);
            app.processEvents();
        }
        
        // Create main window
        MainWindow *mainWindow = new MainWindow(selectedInterface);
        
        // Connect application manager signals
        QObject::connect(appManager, &ApplicationManager::applicationReady, [mainWindow, splash]() {
            if (splash) {
                splash->finish(mainWindow);
                delete splash;
            }
            mainWindow->show();
            
            // Restore window geometry
            QByteArray geometry = SettingsManager::instance()->getWindowGeometry();
            if (!geometry.isEmpty()) {
                mainWindow->restoreGeometry(geometry);
            }
            
            QByteArray state = SettingsManager::instance()->getWindowState();
            if (!state.isEmpty()) {
                mainWindow->restoreState(state);
            }
        });
        
        QObject::connect(appManager, &ApplicationManager::shutdownRequested, [mainWindow](ApplicationManager::ShutdownReason reason) {
            // Save window state before shutdown
            SettingsManager::instance()->saveWindowGeometry(mainWindow->saveGeometry());
            SettingsManager::instance()->saveWindowState(mainWindow->saveState());
            
            mainWindow->close();
        });
        
        // Simulate application ready (in real app, this would be after all initialization)
        QTimer::singleShot(1000, [appManager]() {
            emit appManager->applicationReady();
        });
        
        int result = app.exec();
        
        // Cleanup
        delete mainWindow;
        
        return result;
        
    } catch (const std::exception &e) {
        if (splash) delete splash;
        
        QString errorMsg = QString("Critical error during application startup: %1").arg(e.what());
        ErrorHandler::instance()->logCritical(errorMsg);
        
        QMessageBox::critical(nullptr, "Critical Error", errorMsg);
        return 1;
        
    } catch (...) {
        if (splash) delete splash;
        
        QString errorMsg = "Unknown critical error during application startup";
        ErrorHandler::instance()->logCritical(errorMsg);
        
        QMessageBox::critical(nullptr, "Critical Error", errorMsg);
        return 1;
    }
}