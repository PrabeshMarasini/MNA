#ifndef TRACEROUTEWIDGET_H
#define TRACEROUTEWIDGET_H

#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QPushButton>
#include <QTextEdit>
#include <QLabel>
#include <QProgressBar>
#include <QGroupBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QTimer>
#include <QThread>
#include <QMutex>
#include <QSpinBox>

extern "C" {
    #include "../src/traceroute/traceroute.h"
}

class TracerouteWorker : public QObject {
    Q_OBJECT

public:
    explicit TracerouteWorker(QObject *parent = nullptr);

public slots:
    void performTraceroute(const QString &target);

signals:
    void tracerouteCompleted(const TracerouteResult &result);
    void tracerouteFailed(const QString &error);
    void hopUpdate(int hopNumber, const QString &ipAddress, const QString &hostname, double responseTime);

private:
    QMutex m_mutex;
};

class TracerouteWidget : public QWidget {
    Q_OBJECT

public:
    explicit TracerouteWidget(QWidget *parent = nullptr);
    ~TracerouteWidget();

private slots:
    void onTracerouteClicked();
    void onStopClicked();
    void onClearClicked();
    void onTracerouteCompleted(const TracerouteResult &result);
    void onTracerouteFailed(const QString &error);
    void onHopUpdate(int hopNumber, const QString &ipAddress, const QString &hostname, double responseTime);
    void onResultTableItemClicked(int row, int column);
    void onTargetChanged();

private:
    void setupUI();
    void updateResults(const TracerouteResult &result);
    void addHopToTable(const TracerouteHop &hop);
    void clearResults();
    void setTracerouteInProgress(bool inProgress);
    bool isValidInput(const QString &input);
    QString formatResponseTime(double timeMs);
    QString getStatusText(int status);

    // UI Components
    QVBoxLayout *m_mainLayout;
    QGroupBox *m_inputGroup;
    QHBoxLayout *m_inputLayout;
    QLineEdit *m_targetEdit;
    QSpinBox *m_maxHopsSpinBox;
    QPushButton *m_tracerouteButton;
    QPushButton *m_stopButton;
    QPushButton *m_clearButton;
    QProgressBar *m_progressBar;

    QGroupBox *m_resultsGroup;
    QVBoxLayout *m_resultsLayout;
    QLabel *m_statusLabel;
    QTableWidget *m_resultsTable;
    
    QGroupBox *m_summaryGroup;
    QVBoxLayout *m_summaryLayout;
    QLabel *m_targetLabel;
    QLabel *m_totalHopsLabel;
    QLabel *m_successfulHopsLabel;
    QLabel *m_totalTimeLabel;

    // Worker thread
    QThread *m_workerThread;
    TracerouteWorker *m_worker;

    // State
    QString m_currentTarget;
    bool m_tracerouteInProgress;
    QTimer *m_updateTimer;
};

#endif // TRACEROUTEWIDGET_H