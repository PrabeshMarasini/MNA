#ifndef HEXVIEW_H
#define HEXVIEW_H

#include <QTextEdit>
#include <QByteArray>
#include <QFont>
#include <QScrollBar>
#include <QTextCursor>
#include <QTextCharFormat>

class HexView : public QTextEdit
{
    Q_OBJECT

public:
    explicit HexView(QWidget *parent = nullptr);
    ~HexView();
    
    void displayPacketData(const QByteArray &data);
    void clear();
    void highlightBytes(int startOffset, int length);
    void clearHighlight();

public slots:
    void setShowAscii(bool show);
    void setShowOffsets(bool show);
    void setBytesPerLine(int bytes);

signals:
    void byteSelected(int offset);

protected:
    void mousePressEvent(QMouseEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;

private slots:
    void onCursorPositionChanged();

private:
    void setupFont();
    void setupColors();
    QString formatHexData(const QByteArray &data);
    QString formatHexLine(const QByteArray &lineData, int offset);
    QString formatAsciiData(const QByteArray &data);
    int getByteOffsetFromPosition(int position);
    void updateHighlight();
    
    QByteArray currentData;
    bool showAscii;
    bool showOffsets;
    int bytesPerLine;
    int highlightStart;
    int highlightLength;
    
    QTextCharFormat normalFormat;
    QTextCharFormat highlightFormat;
    QTextCharFormat offsetFormat;
    QTextCharFormat asciiFormat;
};

#endif // HEXVIEW_H