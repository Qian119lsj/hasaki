#include "hasaki/mainwindow.h"

#include <QApplication>
#include <QDateTime>
#include <QDebug>
#include <QMessageBox>
#include <cstdio>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

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

#ifdef Q_OS_WIN
bool isRunAsAdmin() {
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup)) {
        if (!CheckTokenMembership(NULL, AdministratorsGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdministratorsGroup);
    }
    
    return isAdmin;
}
#endif

int main(int argc, char *argv[]) {
    qputenv("QT_QPA_PLATFORM", "windows:darkmode=0");
    qInstallMessageHandler(customMessageHandler);

    QApplication a(argc, argv);
    QCoreApplication::setApplicationName("hasaki");

#ifdef Q_OS_WIN
    // 检查是否以管理员权限运行
    if (!isRunAsAdmin()) {
        QMessageBox::critical(nullptr, "权限错误", "此应用程序需要管理员权限才能正常运行。\n请右键点击应用程序，选择\"以管理员身份运行\"。");
        return 1;
    }
#endif

    MainWindow w;
    w.show();

    int result = a.exec();

    return result;
}
