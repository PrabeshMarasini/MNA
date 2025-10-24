#include "HexView.h"
#include <QMouseEvent>
#include <QKeyEvent>
#include <QApplication>
#include <QClipboard>
#include <QTextBlock>
#include <QDebug>
#include <QScrollBar>
#include <QPalette>

HexView::HexView(QWidget *parent)
    : QTextEdit(parent)
    , showAscii(true)
    , showOffsets(true)
    , bytesPerLine(16)
    , highlightStart(-1)
    , highlightLength(0)
{
    setupFont();
    setupColors();
    
    // Configure text edit properties
    setReadOnly(true);
    setLineWrapMode(QTextEdit::NoWrap);
    setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    
    // Connect cursor position changes for byte selection
    connect(this, &QTextEdit::cursorPositionChanged, this, &HexView::onCursorPositionChanged);
    
    // Set placeholder text
    setPlaceholderText("No packet data to display");
    
    qDebug() << "HexView: Initialized with" << bytesPerLine << "bytes per line";
}

HexView::~HexView()
{
    // Qt handles cleanup automatically
}

void HexView::displayPacketData(const QByteArray &data)
{
    currentData = data;
    
    if (data.isEmpty()) {
        clear();
        return;
    }
    
    QString hexText = formatHexData(data);
    setPlainText(hexText);
    
    // Reset cursor to beginning
    QTextCursor cursor = textCursor();
    cursor.movePosition(QTextCursor::Start);
    setTextCursor(cursor);
    
    qDebug() << "HexView: Displayed" << data.size() << "bytes of packet data";
}

void HexView::clear()
{
    currentData.clear();
    highlightStart = -1;
    highlightLength = 0;
    QTextEdit::clear();
    
    qDebug() << "HexView: Cleared display";
}

void HexView::highlightBytes(int startOffset, int length)
{
    if (currentData.isEmpty() || startOffset < 0 || length <= 0) {
        clearHighlight();
        return;
    }
    
    highlightStart = startOffset;
    highlightLength = length;
    updateHighlight();
    
    qDebug() << "HexView: Highlighted bytes" << startOffset << "to" << (startOffset + length - 1);
}

void HexView::clearHighlight()
{
    highlightStart = -1;
    highlightLength = 0;
    updateHighlight();
    
    qDebug() << "HexView: Cleared highlight";
}

void HexView::setShowAscii(bool show)
{
    if (showAscii != show) {
        showAscii = show;
        if (!currentData.isEmpty()) {
            displayPacketData(currentData); // Refresh display
        }
        qDebug() << "HexView: ASCII display" << (show ? "enabled" : "disabled");
    }
}

void HexView::setShowOffsets(bool show)
{
    if (showOffsets != show) {
        showOffsets = show;
        if (!currentData.isEmpty()) {
            displayPacketData(currentData); // Refresh display
        }
        qDebug() << "HexView: Offset display" << (show ? "enabled" : "disabled");
    }
}

void HexView::setBytesPerLine(int bytes)
{
    if (bytes > 0 && bytes <= 32 && bytesPerLine != bytes) {
        bytesPerLine = bytes;
        if (!currentData.isEmpty()) {
            displayPacketData(currentData); // Refresh display
        }
        qDebug() << "HexView: Bytes per line set to" << bytes;
    }
}

void HexView::mousePressEvent(QMouseEvent *event)
{
    QTextEdit::mousePressEvent(event);
    
    if (event->button() == Qt::LeftButton && !currentData.isEmpty()) {
        QTextCursor cursor = cursorForPosition(event->pos());
        int position = cursor.position();
        int byteOffset = getByteOffsetFromPosition(position);
        
        if (byteOffset >= 0 && byteOffset < currentData.size()) {
            emit byteSelected(byteOffset);
            qDebug() << "HexView: Byte selected at offset" << byteOffset;
        }
    }
}

void HexView::keyPressEvent(QKeyEvent *event)
{
    // Handle copy operation
    if (event->matches(QKeySequence::Copy)) {
        QTextCursor cursor = textCursor();
        if (cursor.hasSelection()) {
            QString selectedText = cursor.selectedText();
            QApplication::clipboard()->setText(selectedText);
            qDebug() << "HexView: Copied selected text to clipboard";
        }
        return;
    }
    
    // Handle navigation keys
    switch (event->key()) {
        case Qt::Key_Home:
            if (event->modifiers() & Qt::ControlModifier) {
                // Ctrl+Home - go to beginning
                QTextCursor cursor = textCursor();
                cursor.movePosition(QTextCursor::Start);
                setTextCursor(cursor);
            } else {
                // Home - go to beginning of line
                QTextEdit::keyPressEvent(event);
            }
            break;
            
        case Qt::Key_End:
            if (event->modifiers() & Qt::ControlModifier) {
                // Ctrl+End - go to end
                QTextCursor cursor = textCursor();
                cursor.movePosition(QTextCursor::End);
                setTextCursor(cursor);
            } else {
                // End - go to end of line
                QTextEdit::keyPressEvent(event);
            }
            break;
            
        default:
            QTextEdit::keyPressEvent(event);
            break;
    }
}

void HexView::onCursorPositionChanged()
{
    if (!currentData.isEmpty()) {
        QTextCursor cursor = textCursor();
        int position = cursor.position();
        int byteOffset = getByteOffsetFromPosition(position);
        
        if (byteOffset >= 0 && byteOffset < currentData.size()) {
            emit byteSelected(byteOffset);
        }
    }
}

void HexView::setupFont()
{
    // Use a monospace font for proper alignment
    QFont font("Courier New", 9);
    if (!font.exactMatch()) {
        font = QFont("Consolas", 9);
        if (!font.exactMatch()) {
            font = QFont("Monaco", 9);
            if (!font.exactMatch()) {
                font = QFont("monospace", 9);
            }
        }
    }
    
    font.setFixedPitch(true);
    setFont(font);
    
    qDebug() << "HexView: Font set to" << font.family() << font.pointSize();
}

void HexView::setupColors()
{
    // Set up text formats for different elements
    QPalette palette = this->palette();
    
    // Normal text format
    normalFormat.setForeground(palette.color(QPalette::Text));
    
    // Highlight format
    highlightFormat.setBackground(palette.color(QPalette::Highlight));
    highlightFormat.setForeground(palette.color(QPalette::HighlightedText));
    
    // Offset format (slightly dimmed)
    QColor offsetColor = palette.color(QPalette::Text);
    offsetColor.setAlpha(180);
    offsetFormat.setForeground(offsetColor);
    
    // ASCII format (slightly different color)
    QColor asciiColor = palette.color(QPalette::Text);
    asciiColor = asciiColor.darker(120);
    asciiFormat.setForeground(asciiColor);
    
    qDebug() << "HexView: Color formats initialized";
}

QString HexView::formatHexData(const QByteArray &data)
{
    if (data.isEmpty()) {
        return QString();
    }
    
    QString result;
    result.reserve(data.size() * 4); // Rough estimate for performance
    
    for (int i = 0; i < data.size(); i += bytesPerLine) {
        QByteArray lineData = data.mid(i, bytesPerLine);
        result += formatHexLine(lineData, i);
        result += "\n";
    }
    
    return result;
}

QString HexView::formatHexLine(const QByteArray &lineData, int offset)
{
    QString line;
    
    // Add offset if enabled
    if (showOffsets) {
        line += QString("%1: ").arg(offset, 8, 16, QChar('0')).toUpper();
    }
    
    // Add hex data
    for (int i = 0; i < bytesPerLine; ++i) {
        if (i < lineData.size()) {
            unsigned char byte = static_cast<unsigned char>(lineData[i]);
            line += QString("%1 ").arg(byte, 2, 16, QChar('0')).toUpper();
        } else {
            line += "   "; // Padding for incomplete lines
        }
        
        // Add extra space every 8 bytes for readability
        if ((i + 1) % 8 == 0 && i + 1 < bytesPerLine) {
            line += " ";
        }
    }
    
    // Add ASCII representation if enabled
    if (showAscii) {
        line += " |";
        for (int i = 0; i < lineData.size(); ++i) {
            char c = lineData[i];
            if (c >= 32 && c <= 126) {
                line += c;
            } else {
                line += '.';
            }
        }
        
        // Pad ASCII section for incomplete lines
        for (int i = lineData.size(); i < bytesPerLine; ++i) {
            line += ' ';
        }
        
        line += "|";
    }
    
    return line;
}

QString HexView::formatAsciiData(const QByteArray &data)
{
    QString ascii;
    ascii.reserve(data.size());
    
    for (char c : data) {
        if (c >= 32 && c <= 126) {
            ascii += c;
        } else {
            ascii += '.';
        }
    }
    
    return ascii;
}

int HexView::getByteOffsetFromPosition(int position)
{
    if (currentData.isEmpty()) {
        return -1;
    }
    
    // This is a simplified calculation
    // In a real implementation, you'd need to account for the exact text layout
    QTextCursor cursor = textCursor();
    cursor.setPosition(position);
    
    int blockNumber = cursor.blockNumber();
    int columnInBlock = cursor.columnNumber();
    
    // Calculate byte offset based on line and column
    int bytesInPreviousLines = blockNumber * bytesPerLine;
    
    // Calculate byte position within current line
    int offsetStart = showOffsets ? 10 : 0; // "XXXXXXXX: " = 10 chars
    int byteInLine = 0;
    
    if (columnInBlock >= offsetStart) {
        int hexPosition = columnInBlock - offsetStart;
        
        // Account for spaces between bytes and extra spaces every 8 bytes
        int spacesBeforePosition = hexPosition / 3; // Each byte takes 3 chars (XX )
        int extraSpaces = spacesBeforePosition / 8; // Extra space every 8 bytes
        
        byteInLine = (hexPosition - extraSpaces) / 3;
        
        if (byteInLine >= bytesPerLine) {
            byteInLine = bytesPerLine - 1;
        }
    }
    
    int totalOffset = bytesInPreviousLines + byteInLine;
    
    // Ensure offset is within data bounds
    if (totalOffset >= currentData.size()) {
        totalOffset = currentData.size() - 1;
    }
    
    return totalOffset >= 0 ? totalOffset : 0;
}

void HexView::updateHighlight()
{
    if (currentData.isEmpty()) {
        return;
    }
    
    // Clear existing formatting
    QTextCursor cursor(document());
    cursor.select(QTextCursor::Document);
    cursor.setCharFormat(normalFormat);
    
    // Apply highlight if specified
    if (highlightStart >= 0 && highlightLength > 0) {
        // This is a simplified highlighting implementation
        // A complete implementation would need to calculate exact character positions
        // for the hex bytes to highlight
        
        // For now, we'll just ensure the highlight parameters are stored
        // The actual highlighting would require more complex text position calculations
    }
    
    // Reset cursor position
    cursor.movePosition(QTextCursor::Start);
    setTextCursor(cursor);
}