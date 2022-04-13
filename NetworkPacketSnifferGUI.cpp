#include "NetworkPacketSnifferGUI.h"

NetworkPacketSnifferGUI::NetworkPacketSnifferGUI(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
    this->configWin.reset(new ConfigGUI(this));

    sniffer.setLogger([this](const QString& str) {
        ui.logBrowser->append(str);
        });
    
    sniffer.showAdapters(true);
    connect(ui.configButton, &QPushButton::clicked, this, &NetworkPacketSnifferGUI::onConfigButtonClicked);
    connect(this, &NetworkPacketSnifferGUI::sendAdapterInfo, this->configWin.get(), &ConfigGUI::receiveAdapterInfo);
}

void NetworkPacketSnifferGUI::onConfigButtonClicked()
{
    this->configWin->show();

    auto adapterInfo = this->sniffer.getAdapterInfo();
    emit this->sendAdapterInfo(adapterInfo);
}

void NetworkPacketSnifferGUI::receiveAdapterIdx(int idx) {
    if (idx < 0)
        idx = 0;
        //qFatal("get idx: %d", idx);
    this->sniffer.setAdapter(idx);
    ui.logBrowser->append(QString::number(idx));
}