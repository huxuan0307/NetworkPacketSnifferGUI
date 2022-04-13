#pragma once

#include <QWidget>
#include <QMessagebox>
#include <memory>
#include <vector>
#include "ui_Configs.h"

using std::vector;

class NetworkPacketSnifferGUI;
class AdapterInfo;

class ConfigGUI : public QMainWindow
{
	Q_OBJECT

public:
	ConfigGUI(QWidget* parent = Q_NULLPTR);

	~ConfigGUI();

	void onAccepted();

public slots:
	void receiveAdapterInfo(vector<AdapterInfo>&);

private:
	signals:
	void sendAdapterIdx(int idx);

private:
	NetworkPacketSnifferGUI* mainGUI;

	Ui::ConfigGUI ui;

	int adapterIdx;
};
