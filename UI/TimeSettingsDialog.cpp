#include "TimeSettingsDialog.h"
#include <QApplication>
#include <QDebug>

TimeSettingsDialog::TimeSettingsDialog(QWidget *parent)
    : QDialog(parent)
    , selectedMode(UTC_TIME)
    , selectedCustomTimeZone(QTimeZone::utc())
{
    setWindowTitle("Time Settings");
    setModal(true);
    setFixedSize(400, 250);
    
    setupUI();
    populateTimeZoneComboBox();
    updateCustomTimeZoneState();
}

TimeSettingsDialog::~TimeSettingsDialog()
{
}

void TimeSettingsDialog::setupUI()
{
    mainLayout = new QVBoxLayout(this);
    
    // Time zone selection group
    timeZoneGroup = new QGroupBox("Time Zone Display", this);
    timeZoneLayout = new QVBoxLayout(timeZoneGroup);
    
    // Radio buttons
    utcRadio = new QRadioButton("UTC Time", this);
    localRadio = new QRadioButton("Local Time", this);
    customRadio = new QRadioButton("Custom Time Zone:", this);
    
    // Set UTC as default
    utcRadio->setChecked(true);
    
    // Button group for exclusive selection
    radioGroup = new QButtonGroup(this);
    radioGroup->addButton(utcRadio, UTC_TIME);
    radioGroup->addButton(localRadio, LOCAL_TIME);
    radioGroup->addButton(customRadio, CUSTOM_TIME);
    
    // Custom time zone selection
    customLayout = new QHBoxLayout();
    customLabel = new QLabel("    Time Zone:", this);
    timeZoneComboBox = new QComboBox(this);
    timeZoneComboBox->setEnabled(false);
    
    customLayout->addWidget(customLabel);
    customLayout->addWidget(timeZoneComboBox);
    customLayout->addStretch();
    
    // Add to time zone layout
    timeZoneLayout->addWidget(utcRadio);
    timeZoneLayout->addWidget(localRadio);
    timeZoneLayout->addWidget(customRadio);
    timeZoneLayout->addLayout(customLayout);
    
    // Buttons
    buttonLayout = new QHBoxLayout();
    okButton = new QPushButton("OK", this);
    cancelButton = new QPushButton("Cancel", this);
    
    buttonLayout->addStretch();
    buttonLayout->addWidget(okButton);
    buttonLayout->addWidget(cancelButton);
    
    // Main layout
    mainLayout->addWidget(timeZoneGroup);
    mainLayout->addStretch();
    mainLayout->addLayout(buttonLayout);
    
    // Connect signals
    connect(radioGroup, QOverload<QAbstractButton*>::of(&QButtonGroup::buttonClicked), this, &TimeSettingsDialog::onModeChanged);
    connect(okButton, &QPushButton::clicked, this, &TimeSettingsDialog::onAccept);
    connect(cancelButton, &QPushButton::clicked, this, &TimeSettingsDialog::onReject);
}

void TimeSettingsDialog::populateTimeZoneComboBox()
{
    timeZoneComboBox->clear();
    
    // Add common time zones
    QList<QByteArray> timeZoneIds = QTimeZone::availableTimeZoneIds();
    
    // Sort and add to combo box
    QStringList timeZoneNames;
    for (const QByteArray &id : timeZoneIds) {
        QTimeZone tz(id);
        if (tz.isValid()) {
            QString displayName = QString("%1 (%2)").arg(QString::fromLatin1(id)).arg(tz.displayName(QTimeZone::StandardTime));
            timeZoneNames.append(displayName);
            timeZoneComboBox->addItem(displayName, id);
        }
    }
    
    // Set default to UTC
    int utcIndex = timeZoneComboBox->findData("UTC");
    if (utcIndex >= 0) {
        timeZoneComboBox->setCurrentIndex(utcIndex);
    }
}

void TimeSettingsDialog::setCurrentSettings(TimeZoneMode mode, const QTimeZone &customZone)
{
    selectedMode = mode;
    selectedCustomTimeZone = customZone;
    
    // Update radio buttons
    switch (mode) {
        case UTC_TIME:
            utcRadio->setChecked(true);
            break;
        case LOCAL_TIME:
            localRadio->setChecked(true);
            break;
        case CUSTOM_TIME:
            customRadio->setChecked(true);
            // Find and select the custom time zone in combo box
            for (int i = 0; i < timeZoneComboBox->count(); ++i) {
                QByteArray tzId = timeZoneComboBox->itemData(i).toByteArray();
                if (QTimeZone(tzId) == customZone) {
                    timeZoneComboBox->setCurrentIndex(i);
                    break;
                }
            }
            break;
    }
    
    updateCustomTimeZoneState();
}

TimeZoneMode TimeSettingsDialog::getSelectedMode() const
{
    return selectedMode;
}

QTimeZone TimeSettingsDialog::getSelectedCustomTimeZone() const
{
    return selectedCustomTimeZone;
}

void TimeSettingsDialog::onModeChanged()
{
    selectedMode = static_cast<TimeZoneMode>(radioGroup->checkedId());
    updateCustomTimeZoneState();
}

void TimeSettingsDialog::updateCustomTimeZoneState()
{
    bool customEnabled = (selectedMode == CUSTOM_TIME);
    customLabel->setEnabled(customEnabled);
    timeZoneComboBox->setEnabled(customEnabled);
}

void TimeSettingsDialog::onAccept()
{
    // Update selected custom time zone if custom mode is selected
    if (selectedMode == CUSTOM_TIME) {
        QByteArray tzId = timeZoneComboBox->currentData().toByteArray();
        selectedCustomTimeZone = QTimeZone(tzId);
    }
    
    accept();
}

void TimeSettingsDialog::onReject()
{
    reject();
}