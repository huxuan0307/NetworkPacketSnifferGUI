#pragma once

#include <QtWidgets/QMainWindow>
#include <memory>
#include "ui_NetworkPacketSnifferGUI.h"
#include "Sniffer.h"
#include "ConfigGUI.h"

class NetworkPacketSnifferGUI : public QMainWindow
{
    Q_OBJECT

public:
    NetworkPacketSnifferGUI(QWidget *parent = Q_NULLPTR);

private:
    Ui::NetworkPacketSnifferGUIClass ui;
    std::shared_ptr<ConfigGUI> configWin;

    Sniffer sniffer;
    void onConfigButtonClicked();
    friend class ConfigGUI;
public slots:
    void receiveAdapterIdx(int idx);

private:
signals:
    void sendAdapterInfo(vector<AdapterInfo>&);
};
