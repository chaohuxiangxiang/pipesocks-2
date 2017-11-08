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

#include "tap.h"

Tap::Tap(qintptr handle,const QString &RemoteHost,unsigned short RemotePort,const QString &Password,GFWList *gfwlist,QObject *parent)
  : QObject(parent)
  , Password(Password)
  , gfwlist(gfwlist)
{
  csock = new TcpSocket(this);
  connect(csock,SIGNAL(RecvData(QByteArray)),
          this,SLOT(clientRecv(QByteArray)));
  connect(csock,SIGNAL(disconnected()),
          this,SLOT(endSession()));
  csock->setSocketDescriptor(handle);
  ssock = new SecureSocket(Password,false,this);
  connect(ssock,SIGNAL(RecvData(QByteArray)),this,SLOT(serverRecv(QByteArray)));
  connect(ssock,SIGNAL(disconnected()),this,SLOT(endSession()));
  ssock->connectToHost(RemoteHost,RemotePort);
  usock = NULL;
  CHost = csock->peerAddress();
  CPort = csock->peerPort();
  status = Initiated;
  Log::log(csock,"connection established");
}

void Tap::clientRecv(const QByteArray &Data)
{
  switch (status)
    {
    case Initiated:
      {
        if (Data[0] == 'G')
          {
            if (Data.indexOf("gfwlist") == -1)
              {
                emit csock->sendData(PAC());
                csock->disconnectFromHost();
                Log::log(csock,"requested global PAC");
              }
            else
              {
                connect(gfwlist,SIGNAL(recvGFWList(QString)),this,SLOT(recvGFWList(QString)));
                connect(gfwlist,SIGNAL(Fail()),this,SLOT(gfwListFail()));
                gfwlist->requestGFWList();
                Log::log(csock,"requested GFWList PAC");
              }
            return;
          }
        if (Data[0] != 5)
          {
            csock->disconnectFromHost();
            return;
          }

        bool ok = false;
        for (int i = 2;i<Data[1]+2;++i)
          {
            if (Data[i] == 0)
              {
                ok = true;
                break;
              }
          }
        if(!ok)
          {
            emit csock->sendData(QByteArray::fromHex("05ff"));
            csock->disconnectFromHost();
            return;
          }
        emit csock->sendData(QByteArray::fromHex("0500"));
        status = Handshook;
        break;
      }
    case Handshook:
      {
        QVariantMap qvm;
        if (Data[0] != 5||Data[1] == 2||Data[2] != 0)
          {
            emit csock->sendData(QByteArray::fromHex("05070001000000000000"));
            csock->disconnectFromHost();
            return;
          }
        QPair<QString,unsigned short>hostport = toNormal(Data.mid(3));
        qvm.insert("host",hostport.first);
        qvm.insert("port",hostport.second);
        qvm.insert("password",Password);
        qvm.insert("version",Version::getLowestVersion());
        if (Data[1] == 1)
          {
            qvm.insert("protocol", "TCP");
            Log::log(csock,"requested TCP connection to "+hostport.first+':'+QString::number(hostport.second));
          }
        else if (Data[1] == 3)
          {
            qvm.insert("protocol", "UDP");
            Log::log(csock,"requested UDP association");
          }
        qvm.insert("garbage",QString(randombytes_uniform(900), 'f'));
        emit ssock->sendData(QJsonDocument::fromVariant(qvm).toJson());
        break;
      }
    case CONNECT:
      emit ssock->sendData(Data);
      break;

    case UDPASSOCIATE:
      break;
    }
}

void Tap::serverRecv(const QByteArray &Data) {
  switch (status) {
    case Initiated:
      break;
    case Handshook: {
        QVariantMap qvm(QJsonDocument::fromJson(Data).toVariant().toMap());
        if (qvm["status"] == "ok") {
            if (qvm["protocol"] == "TCP") {
                emit csock->sendData(QByteArray::fromHex("05000001000000000000"));
                status = CONNECT;
              } else if (qvm["protocol"] == "UDP") {
                usock = new UdpSocket(this);
                connect(usock,SIGNAL(RecvData(QHostAddress,unsigned short,QByteArray)),this,SLOT(udpRecv(QHostAddress,unsigned short,QByteArray)));
                emit csock->sendData(QByteArray::fromHex("050000")+toSOCKS5(csock->localAddress(),usock->localPort()));
                status = UDPASSOCIATE;
              }
          } else {
            emit csock->sendData(QByteArray::fromHex("05020001000000000000"));
            csock->disconnectFromHost();
            Log::log("Connection refused by pump");
          }
        break;
      }
    case CONNECT:
      emit csock->sendData(Data);
      break;
    case UDPASSOCIATE: {
        QVariantMap qvm(QJsonDocument::fromJson(Data).toVariant().toMap());
        emit usock->sendData(UHost.toString(),UPort,QByteArray::fromHex("000000")+toSOCKS5(QHostAddress(qvm["host"].toString()),qvm["port"].toUInt())+QByteArray::fromBase64(qvm["data"].toByteArray()));
        Log::log(csock,"received a UDP package from "+qvm["host"].toString().mid(7)+':'+QString::number(qvm["port"].toUInt()));
      }
    }
}

void Tap::endSession() {
  if (csock->state() == QAbstractSocket::ConnectedState) {
      Log::log(CHost.toString().mid(7)+':'+QString::number(CPort)+" server closed the connection");
    }
  if (ssock->state() == QAbstractSocket::ConnectedState) {
      Log::log(CHost.toString().mid(7)+':'+QString::number(CPort)+" client closed the connection");
    }
  csock->disconnectFromHost();
  ssock->disconnectFromHost();
  if (ssock->state() == QAbstractSocket::UnconnectedState&&csock->state() == QAbstractSocket::UnconnectedState) {
      if (usock)
        usock->close();
      deleteLater();
    }
}

QByteArray Tap::PAC()
{
  QString pac(QString("function FindProxyForURL(url,host){return\"SOCKS5 %1:%2;SOCKS %1:%2\"}")
              .arg(csock->localAddress().toString().mid(7))
              .arg(csock->localPort()));
  QString http(QString("HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %1\r\n\r\n%2")
               .arg(pac.length())
               .arg(pac));
  return http.toLocal8Bit();
}

void Tap::recvGFWList(const QString &gfwlist)
{
  QString pac(gfwlist
              .arg(csock->localAddress().toString().mid(7))
              .arg(csock->localPort()));
  QString http(QString("HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: %1\r\n\r\n%2")
               .arg(pac.length())
               .arg(pac));
  emit csock->sendData(http.toLocal8Bit());
  csock->disconnectFromHost();
}

void Tap::gfwListFail() {
  emit csock->sendData("HTTP/1.1 503 Server Unavailable\r\nContent-Length: 0\r\n\r\n");
  csock->disconnectFromHost();
  Log::log(csock,"failed to get GFWList PAC");
}

void Tap::udpRecv(const QHostAddress &host,unsigned short port,const QByteArray &data)
{
  UHost = host;
  UPort = port;
  if (data[0]||data[1]||data[2])
    {
      csock->disconnectFromHost();
      return;
    }
  QPair<QString,unsigned short>hostport = toNormal(data.mid(3));
  QVariantMap qvm;
  qvm.insert("host",hostport.first);
  qvm.insert("port",hostport.second);
  if (data[3] == 1)
    qvm.insert("data",data.mid(10).toBase64());
  else if (data[3] == 3)
    qvm.insert("data",data.mid(data[4]+7).toBase64());
  else if (data[3] == 4)
    qvm.insert("data",data.mid(22).toBase64());
  emit ssock->sendData(QJsonDocument::fromVariant(qvm).toJson());
  Log::log(csock,"sent a UDP package to "+hostport.first+':'+QString::number(hostport.second));
}

QPair<QString,unsigned short>Tap::toNormal(const QByteArray &socks5)
{
  QString host;
  unsigned short port = 0;
  if (socks5[0] == 1)
    {
      host = QString("%1.%2.%3.%4")
          .arg((unsigned char)socks5[1])
          .arg((unsigned char)socks5[2])
          .arg((unsigned char)socks5[3])
          .arg((unsigned char)socks5[4]);
      port = ((unsigned short)(unsigned char)socks5[5]<<8)+(unsigned char)socks5[6];
    }
  else if (socks5[0] == 3)
    {
      host = socks5.mid(2, socks5[1]);
      port = ((unsigned short)(unsigned char)socks5[socks5[1]+2]<<8)+(unsigned char)socks5[socks5[1]+3];
    }
  else if (socks5[0] == 4)
    {
      host = QString("%1%2:%3%4:%5%6:%7%8:%9%10:%11%12:%13%14:%15%16")
          .arg((unsigned char)socks5[1],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[2],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[3],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[4],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[5],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[6],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[7],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[8],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[9],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[10],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[11],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[12],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[13],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[14],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[15],2,16,QLatin1Char('0'))
          .arg((unsigned char)socks5[16],2,16,QLatin1Char('0'));
      port = ((unsigned short)(unsigned char)socks5[17]<<8)+(unsigned char)socks5[18];
    }
  return QPair<QString,unsigned short>(host,port);
}

QByteArray Tap::toSOCKS5(const QHostAddress &Host,unsigned short Port)
{
  QByteArray ret;
  bool is4;
  unsigned int ipv4  =  Host.toIPv4Address(&is4);
  if (is4)
    {
      ret += char(1);
      ret += (unsigned char)(ipv4>>24);
      ret += (unsigned char)(ipv4>>16);
      ret += (unsigned char)(ipv4>>8);
      ret += (unsigned char)(ipv4);
    }
  else
    {
      Q_IPV6ADDR ipv6 = Host.toIPv6Address();
      ret += char(4);
      for (int i = 0;i<16;++i)
        ret += (unsigned char)ipv6[i];
    }
  ret += (unsigned char)(Port>>8);
  ret += (unsigned char)(Port);
  return ret;
}
