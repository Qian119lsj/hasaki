#include "hasaki/mainwindow.h"

#include <QApplication>
#include <QDateTime>
#include <QDebug>
#include <cstdio>

void customMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg) {
    Q_UNUSED(context);

    QByteArray localMsg = msg.toLocal8Bit();
    QString timeStr = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");
    const char *typeStr = "Unknown";

    switch (type) {
    case QtDebugMsg:
        typeStr = "Debug";
        break;
    case QtInfoMsg:
        typeStr = "Info";
        break;
    case QtWarningMsg:
        typeStr = "Warning";
        break;
    case QtCriticalMsg:
        typeStr = "Critical";
        break;
    case QtFatalMsg:
        typeStr = "Fatal";
        break;
    }

    fprintf(stdout, "[%s] [%s] %s\n", timeStr.toLocal8Bit().constData(), typeStr, localMsg.constData());
    fflush(stdout);

    if (type == QtFatalMsg) {
        abort();
    }
}

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORM", "windows:darkmode=0");
    qInstallMessageHandler(customMessageHandler);

    QApplication a(argc, argv);
    QCoreApplication::setApplicationName("hasaki");

    MainWindow w;
    w.show();

    int result = a.exec();

    return result;
}
