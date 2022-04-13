#include "NetworkPacketSnifferGUI.h"

NetworkPacketSnifferGUI::NetworkPacketSnifferGUI(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    sniffer.setLogger([this](const QString& str) {
        ui.logBrowser->append(str);
        });
    
    sniffer.showAdapters(true);
}

