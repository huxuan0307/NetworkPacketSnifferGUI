#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_NetworkPacketSnifferGUI.h"

class NetworkPacketSnifferGUI : public QMainWindow
{
    Q_OBJECT

public:
    NetworkPacketSnifferGUI(QWidget *parent = Q_NULLPTR);

private:
    Ui::NetworkPacketSnifferGUIClass ui;
};
