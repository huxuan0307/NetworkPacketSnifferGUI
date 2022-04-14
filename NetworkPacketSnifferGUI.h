#pragma once

#include <QtWidgets/QMainWindow>
#include <memory>
#include "ui_NetworkPacketSnifferGUI.h"
#include "Sniffer.h"
#include "ConfigGUI.h"
#include <deque>

using std::deque;

class QStandardItem;
class Packet;

class NetworkPacketSnifferGUI : public QMainWindow
{
    Q_OBJECT

public:
    NetworkPacketSnifferGUI(QWidget *parent = Q_NULLPTR);
    ~NetworkPacketSnifferGUI();
private:
    Ui::NetworkPacketSnifferGUIClass ui;
    std::shared_ptr<ConfigGUI> configWin;
    Sniffer sniffer;
    bool running;
    deque<QList<QStandardItem*>> captureBuf;
    size_t captureIdx;
    int adapterIdx;

    void onConfigButtonClicked();
    void start();
    void stop();
    void initCaptureTable();
    void appendCaptureTable(Time t, size_t len, Packet p);
    void updateCaptureTable();
    void handlePacket(pcap_pkthdr** header, const u_char** pkt_data);
    friend class ConfigGUI;
public slots:
    void receiveAdapterIdx(int idx);

private:
signals:
    void sendAdapterInfo(vector<AdapterInfo>&);
};
