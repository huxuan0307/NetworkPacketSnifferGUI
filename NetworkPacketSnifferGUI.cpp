#include "NetworkPacketSnifferGUI.h"

#include <QStandardItemModel>
#include <QAbstractItemModel>
#include <QTimer>
#include <chrono>
#include <iomanip>
#include <deque>

using std::chrono::milliseconds;
using std::string;

class Address {

};

class Packet {
public:
    string protocal;
    Address addr;
};

NetworkPacketSnifferGUI::NetworkPacketSnifferGUI(QWidget* parent)
    : QMainWindow(parent), running(false), captureIdx(), adapterIdx(-1)
{
    ui.setupUi(this);
    this->configWin.reset(new ConfigGUI(this));

    connect(ui.configButton, &QPushButton::clicked, this, &NetworkPacketSnifferGUI::onConfigButtonClicked);
    connect(this, &NetworkPacketSnifferGUI::sendAdapterInfo, this->configWin.get(), &ConfigGUI::receiveAdapterInfo);
    connect(ui.startButton, &QPushButton::clicked, this, &NetworkPacketSnifferGUI::start);
    connect(ui.stopButton, &QPushButton::clicked, this, &NetworkPacketSnifferGUI::stop);

    QTimer* timer = new QTimer(this);
    connect(timer, &QTimer::timeout, this, &NetworkPacketSnifferGUI::updateCaptureTable);
    timer->start(1);
}

NetworkPacketSnifferGUI::~NetworkPacketSnifferGUI()
{
}

void NetworkPacketSnifferGUI::onConfigButtonClicked()
{
    this->configWin->show();

    auto adapterInfo = this->sniffer.getAdapterInfo();
    emit this->sendAdapterInfo(adapterInfo);
}

void NetworkPacketSnifferGUI::receiveAdapterIdx(int idx) {
    if (idx < 0) {
        qFatal("get idx: %d", idx);
        idx = 0;
    }
    this->sniffer.setAdapter(idx);
    ui.logBrowser->append(QString("Selected adapter: ") + QString::number(idx));
    // record from 0
    if (idx != this->adapterIdx) {
        this->adapterIdx = idx;
        this->captureIdx = 0;
        this->initCaptureTable();
    }
    this->ui.captureTable->setEnabled(true);
}

void NetworkPacketSnifferGUI::start() {
    qDebug("NetworkPacketSnifferGUI::start begin");

    int ret = this->sniffer.activate();
    if (ret < 0) {
        QMessageBox::warning(this, "Error", "请先配置要捕获的网卡", QMessageBox::StandardButton::Ok);
        return;
    }
    this->running = true;
    this->ui.startButton->setEnabled(false);
    this->ui.stopButton->setEnabled(true);
    this->sniffer.startCapture([this](
        pcap_pkthdr** header, const u_char** pkt_data) { 
            return handlePacket(header, pkt_data); 
        }
    );

    qDebug("NetworkPacketSnifferGUI::start end");
}

void NetworkPacketSnifferGUI::stop() {
    this->sniffer.stopCapture();
    this->running = false;
    this->ui.startButton->setEnabled(true);
    this->ui.stopButton->setEnabled(false);
}

void NetworkPacketSnifferGUI::initCaptureTable()
{
    QTableView* tableView = ui.captureTable;
    QStandardItemModel* standItemModel = new QStandardItemModel();

    standItemModel->setColumnCount(4);
    standItemModel->setHeaderData(0, Qt::Orientation::Horizontal, QStringLiteral("序号"));
    standItemModel->setHeaderData(1, Qt::Orientation::Horizontal, QStringLiteral("时间"));
    standItemModel->setHeaderData(2, Qt::Orientation::Horizontal, QStringLiteral("长度"));
    standItemModel->setHeaderData(3, Qt::Orientation::Horizontal, QStringLiteral("协议"));
    tableView->setModel(standItemModel);
    tableView->setEditTriggers(QAbstractItemView::EditTrigger::NoEditTriggers);
    tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignmentFlag::AlignLeft);
    tableView->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeMode::ResizeToContents);
    tableView->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeMode::ResizeToContents);
    tableView->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeMode::ResizeToContents);

    tableView->verticalHeader()->hide();
    tableView->setSelectionBehavior(QAbstractItemView::SelectRows);
}

void NetworkPacketSnifferGUI::appendCaptureTable(Time t, size_t len, Packet p)
{
    QList<QStandardItem*> row;

    QString timeStr = QString::number(t.tm_hour) + ":" + QString::number(t.tm_min) + ":" +
        QString::number(t.tm_sec) + "," + QString::number(t.tv_usec);

    row.push_back(new QStandardItem(tr("%1").arg(++captureIdx)));
    row.push_back(new QStandardItem(timeStr));
    row.push_back(new QStandardItem(tr("%1").arg(len)));
    row.push_back(new QStandardItem(QString::fromStdString(p.protocal)));
    captureBuf.push_back(row);
}

void NetworkPacketSnifferGUI::updateCaptureTable() {
    QTableView* tableView = ui.captureTable;
    QStandardItemModel* standItemModel = (QStandardItemModel*)tableView->model();
    int updateSize = captureBuf.size();
    while (updateSize-- > 0) {
        standItemModel->appendRow(captureBuf.front());
        captureBuf.pop_front();
    }
    tableView->update();
}

void NetworkPacketSnifferGUI::handlePacket(pcap_pkthdr** header, const u_char** pkt_data) {
    qDebug("handlePacket begin");
    /* convert the timestamp to readable format */
    time_t local_tv_sec = (*header)->ts.tv_sec;
    Time t(*localtime(&local_tv_sec), (*header)->ts.tv_usec);

    Packet p;

    this->appendCaptureTable(t, (*header)->len, p);
}
