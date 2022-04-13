#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_NetworkPacketSnipperGUI.h"

class NetworkPacketSnipperGUI : public QMainWindow
{
    Q_OBJECT

public:
    NetworkPacketSnipperGUI(QWidget *parent = Q_NULLPTR);

private:
    Ui::NetworkPacketSnipperGUIClass ui;
};
