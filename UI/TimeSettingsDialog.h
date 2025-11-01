#ifndef TIMESETTINGSDIALOG_H
#define TIMESETTINGSDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QRadioButton>
#include <QComboBox>
#include <QLabel>
#include <QPushButton>
#include <QButtonGroup>
#include <QTimeZone>
#include <QGroupBox>
#include "TimeZoneSettings.h"

class TimeSettingsDialog : public QDialog
{
    Q_OBJECT

public:

    explicit TimeSettingsDialog(QWidget *parent = nullptr);
    ~TimeSettingsDialog();

    void setCurrentSettings(TimeZoneMode mode, const QTimeZone &customZone = QTimeZone::utc());
    TimeZoneMode getSelectedMode() const;
    QTimeZone getSelectedCustomTimeZone() const;

private slots:
    void onModeChanged();
    void onAccept();
    void onReject();

private:
    void setupUI();
    void populateTimeZoneComboBox();
    void updateCustomTimeZoneState();

    QVBoxLayout *mainLayout;
    QGroupBox *timeZoneGroup;
    QVBoxLayout *timeZoneLayout;
    
    QRadioButton *utcRadio;
    QRadioButton *localRadio;
    QRadioButton *customRadio;
    QButtonGroup *radioGroup;
    
    QHBoxLayout *customLayout;
    QLabel *customLabel;
    QComboBox *timeZoneComboBox;
    
    QHBoxLayout *buttonLayout;
    QPushButton *okButton;
    QPushButton *cancelButton;
    
    TimeZoneMode selectedMode;
    QTimeZone selectedCustomTimeZone;
};

#endif // TIMESETTINGSDIALOG_H