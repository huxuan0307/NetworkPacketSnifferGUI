#include "NetworkPacketSnipperGUI.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetworkPacketSnipperGUI w;
    w.show();
    return a.exec();
}
