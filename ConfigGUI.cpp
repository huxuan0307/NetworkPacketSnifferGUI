#include "ConfigGUI.h"
#include "NetworkPacketSnifferGUI.h"
#include "Sniffer.h"

ConfigGUI::ConfigGUI(QWidget* parent)
	: QMainWindow(parent), adapterIdx(-1)
{
	ui.setupUi(this);
	this->mainGUI = reinterpret_cast<NetworkPacketSnifferGUI*>(parent);

	connect(ui.buttonBox, &QDialogButtonBox::accepted, this, &ConfigGUI::onAccepted);
	connect(ui.buttonBox, &QDialogButtonBox::rejected, this, &ConfigGUI::close);
	connect(this, &ConfigGUI::sendAdapterIdx, this->mainGUI, &NetworkPacketSnifferGUI::receiveAdapterIdx);
}

inline ConfigGUI::~ConfigGUI()
{

}

void ConfigGUI::onAccepted() {
	int idx = ui.adapterBox->currentIndex();
	emit this->sendAdapterIdx(idx);
	this->close();
}

void ConfigGUI::receiveAdapterInfo(vector<AdapterInfo>& adapterInfos)
{
	QStringList items;
	for (auto& adaInfo : adapterInfos) {
		items.push_back(QString::fromStdString(adaInfo.toString()));
	}
	this->ui.adapterBox->clear();
	this->ui.adapterBox->addItems(items);
	this->ui.adapterBox->update();
}
