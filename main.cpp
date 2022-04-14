#include "NetworkPacketSnifferGUI.h"
#include <QtWidgets/QApplication>
#include "LogMessage.h"

int main(int argc, char *argv[])
{
    qInstallMessageHandler(MessageOutPut);
    //qSetMessagePattern ("[%{time yyyyMMdd h:mm:ss.zzz t} %{if-debug}D%{endif}%{if-info}I%{endif}%{if-warning}W%{endif}%{if-critical}C%{endif}%{if-fatal}F%{endif}] %{file}:%{line} - %{message}");
    qSetMessagePattern("[%{time yyyyMMdd h:mm:ss.zzz} %{if-debug}D%{endif}%{if-info}I%{endif}%{if-warning}W%{endif}%{if-critical}C%{endif}%{if-fatal}F%{endif}] - %{message}");

    QApplication a(argc, argv);
    NetworkPacketSnifferGUI w;
    w.show();
    return a.exec();
}
