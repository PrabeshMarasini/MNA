#ifndef CAPTURECONTROLWIDGET_H
#define CAPTURECONTROLWIDGET_H

#include <QWidget>
#include <QLabel>
#include <QPushButton>
#include <QProgressBar>
#include <QTimer>
#include <QGroupBox>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QDateTime>

class PacketCaptureController;

/**
 * @brief Widget providing comprehensive capture control functionality
 * 
 * This widget provides a centralized interface for controlling packet capture
 * operations, displaying capture status, statistics, and providing user controls.
 */
class CaptureControlWidget : public QWidget
{
    Q_OBJECT

public:
    explicit CaptureControlWidget(QWidget *parent = nullptr);
    ~CaptureControlWidget();

    /**
     * @brief Set the capture controller to manage
     */
    void setCaptureController(PacketCaptureController *controller);

    /**
     * @brief Get current capture status
     */
    bool isCapturing() const { return m_isCapturing; }

    /**
     * @brief Get capture statistics
     */
    struct CaptureStats {
        int packetsReceived;
        int packetsDropped;
        qint64 bytesReceived;
        double captureRate;
        int captureTime;
    };
    
    CaptureStats getCaptureStats() const;

public slots:
    /**
     * @brief Start packet capture
     */
    void startCapture();

    /**
     * @brief Stop packet capture
     */
    void stopCapture();

    /**
     * @brief Pause/resume packet capture
     */
    void pauseCapture();

    /**
     * @brief Reset capture statistics
     */
    void resetStatistics();

    /**
     * @brief Update interface status
     */
    void updateInterfaceStatus(const QString &interface, bool available);

signals:
    /**
     * @brief Emitted when capture is started
     */
    void captureStarted();

    /**
     * @brief Emitted when capture is stopped
     */
    void captureStopped();

    /**
     * @brief Emitted when capture is paused/resumed
     */
    void capturePaused(bool paused);

    /**
     * @brief Emitted when statistics are updated
     */
    void statisticsUpdated(int packets, qint64 bytes, double rate);

    /**
     * @brief Emitted when capture error occurs
     */
    void captureError(const QString &error);

private slots:
    /**
     * @brief Handle capture status changes from controller
     */
    void onCaptureStatusChanged(bool capturing);

    /**
     * @brief Handle capture statistics updates
     */
    void onCaptureStatistics(int packetsReceived, int packetsDropped);

    /**
     * @brief Handle capture errors
     */
    void onCaptureError(const QString &error);

    /**
     * @brief Update display statistics
     */
    void updateStatisticsDisplay();

    /**
     * @brief Update capture time
     */
    void updateCaptureTime();

private:
    /**
     * @brief Setup the user interface
     */
    void setupUI();

    /**
     * @brief Setup signal connections
     */
    void setupConnections();

    /**
     * @brief Update control button states
     */
    void updateControlStates();

    /**
     * @brief Format byte count for display
     */
    QString formatBytes(qint64 bytes) const;

    /**
     * @brief Format rate for display
     */
    QString formatRate(double rate) const;

    /**
     * @brief Format time duration
     */
    QString formatDuration(int seconds) const;

    // Controller reference
    PacketCaptureController *m_captureController;

    // UI Components - Control buttons
    QPushButton *m_startButton;
    QPushButton *m_stopButton;
    QPushButton *m_pauseButton;
    QPushButton *m_resetButton;

    // UI Components - Status display
    QLabel *m_statusLabel;
    QLabel *m_interfaceLabel;
    QProgressBar *m_activityIndicator;

    // UI Components - Statistics
    QLabel *m_packetsReceivedLabel;
    QLabel *m_packetsDroppedLabel;
    QLabel *m_bytesReceivedLabel;
    QLabel *m_captureRateLabel;
    QLabel *m_captureTimeLabel;

    // UI Components - Layout
    QGroupBox *m_controlGroup;
    QGroupBox *m_statusGroup;
    QGroupBox *m_statisticsGroup;

    // State tracking
    bool m_isCapturing;
    bool m_isPaused;
    int m_packetsReceived;
    int m_packetsDropped;
    qint64 m_bytesReceived;
    QDateTime m_captureStartTime;

    // Timers
    QTimer *m_statisticsTimer;
    QTimer *m_timeUpdateTimer;

    // Statistics calculation
    int m_lastPacketCount;
    QDateTime m_lastStatsUpdate;
    double m_currentRate;
};

#endif // CAPTURECONTROLWIDGET_H