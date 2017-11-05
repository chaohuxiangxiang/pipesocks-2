/*
This file is part of pipesocks. Pipesocks is a pipe-like SOCKS5 tunnel system.
Copyright (C) 2017  yvbbrjdr

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <QCoreApplication>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include "tcpserver.h"
#include "mainform.h"

QString findArg(const QStringList &argList, char letter) {
    int index = argList.indexOf(QString('-') + letter);
    if(index != -1 && index < argList.size() - 1)
        return argList.at(index + 1);
    return QString();
}

int main(int argc, char **argv) {
    QString usage(QString("Usage: %1 [pump|pipe|tap] <arguments>\nArguments:\n-H Remote Host\n-P Remote Port\n-p Local Port\n-k Password\n").arg(QString(*argv)));

    if(argc == 1)
      {
        /// GUI
        printf("%s",usage.toStdString().c_str());
#ifdef Q_OS_OSX
        QGuiApplication::setQuitOnLastWindowClosed(false);
#endif
        QGuiApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
        QGuiApplication a(argc,argv);
        QQuickStyle::setStyle("Material");
        QQmlApplicationEngine engine;
        engine.load(QUrl(QLatin1String("qrc:/Main.qml")));
        new MainForm(engine.rootObjects().value(0), &a);
        return a.exec();
      }
    else
      {
        /// Command Line
        QCoreApplication a(argc,argv);
        QStringList args = a.arguments();
        QString type = args.at(1);
        QString remoteHost = findArg(args, 'H');
        QString password = findArg(args, 'k');
        unsigned short remotePort = findArg(args, 'P').toUShort();
        unsigned short localPort = findArg(args, 'p').toUShort();

        remotePort = (remotePort == 0) ? 7473 : remotePort;
        localPort = (localPort == 0) ? 7473 : localPort;
        TcpServer *server;

        switch (type) {
          case "pump":
            {
              server = new TcpServer(TcpServer::PumpServer,remoteHost,remotePort,password);
              printf("Welcome to Pipesocks pump\nServer is listening at port %d\n",localPort);
              break;
            }

          case "pipe":
            {
              if(remoteHost == "")
                {
                  printf("Remote Host required\n%s",usage.toStdString().c_str());
                  return 1;
                }
              server = new TcpServer(TcpServer::PipeServer,remoteHost,remotePort,password);
              printf("Welcome to Pipesocks pipe\nServer is listening at port %d and connects to %s:%d\n",localPort,remoteHost.toStdString().c_str(),remotePort);
              break;
            }

          case "tap":
            {
              if(remoteHost == "")
                {
                  printf("Remote Host required\n%s",usage.toStdString().c_str());
                  return 1;
                }
              server = new TcpServer(TcpServer::TapClient,remoteHost,remotePort,password);
              printf("Welcome to Pipesocks tap\nServer is listening at port %d and connects to %s:%d\n",localPort,remoteHost.toStdString().c_str(),remotePort);
              break;
            }

          default:
            {
              printf("%s",usage.toStdString().c_str());
              return 1;
            }
          }

        if(!server->listen(QHostAddress::Any,localPort))
          {
            printf("Failed to bind to port %d, exiting. . . \n",localPort);
            return 1;
          }
        return a.exec();
    }
}
