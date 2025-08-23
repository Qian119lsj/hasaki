#include "hasaki/mainwindow.h"

#include <QApplication>
#include <QDateTime>
#include <QDebug>
#include <QMessageBox>
#include <cstdio>
#include <qicon.h>

void customMessageHandler(QtMsgType type, const QMessageLogContext &context, const QString &msg) {
    Q_UNUSED(context);

    // ANSI 颜色码
    const char *colorCode = "";
    const char *resetCode = "\033[0m"; // 恢复默认颜色
    const char *typeStr = "Unknown";

    switch (type) {
    case QtDebugMsg:
        colorCode = "\033[36m";
        typeStr = "Debug";
        break; // 青色
    case QtInfoMsg:
        colorCode = "\033[32m";
        typeStr = "Info";
        break; // 绿色
    case QtWarningMsg:
        colorCode = "\033[33m";
        typeStr = "Warning";
        break; // 黄色
    case QtCriticalMsg:
        colorCode = "\033[35m";
        typeStr = "Critical";
        break; // 紫色
    case QtFatalMsg:
        colorCode = "\033[31m";
        typeStr = "Fatal";
        break; // 红色
    }

    QString timeStr = QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss.zzz");

    // 把颜色码、时间、级别、正文、恢复码一次性输出
    fprintf(stdout, "%s[%s] [%s] %s%s\n", colorCode, timeStr.toLocal8Bit().constData(), typeStr, msg.toLocal8Bit().constData(), resetCode);
    fflush(stdout);

    if (type == QtFatalMsg)
        abort();
}

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORM", "windows:darkmode=0");
    qInstallMessageHandler(customMessageHandler);

    QApplication a(argc, argv);

    QIcon icon(":/icons/app.ico");
    QApplication::setWindowIcon(icon);

    QCoreApplication::setApplicationName("hasaki");

    MainWindow w;
    w.show();

    WSADATA wsaData;
    int ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (ret != 0) {
        qDebug() << "WSAStartup 失败:" << ret;
        return ret;
    }

    int result = a.exec();

    WSACleanup();

    return result;
}
