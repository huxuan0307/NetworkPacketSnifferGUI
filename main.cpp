#include "NetworkPacketSnifferGUI.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    NetworkPacketSnifferGUI w;
    w.show();
    return a.exec();
}
