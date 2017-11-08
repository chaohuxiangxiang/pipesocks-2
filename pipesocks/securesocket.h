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

#ifndef SECURESOCKET_H
#define SECURESOCKET_H

#include <QCoreApplication>
#include <QList>
#include <sodium.h>
#include "tcpsocket.h"

class SecureSocket : public TcpSocket {
  Q_OBJECT
public:
  explicit SecureSocket(const QString &Password,bool passive,QObject *parent = 0);

private:
  bool passive;
  QByteArray local_pubKey;
  QByteArray local_priKey;
  QByteArray remote_pubKey;
  QByteArray secret_key;
  QList<QByteArray> send_buffer;
  QByteArray recv_buffer;
  QByteArray publicEncrypt(const QByteArray &Data);
  QByteArray publicDecrypt(const QByteArray &Data);
  QByteArray secretEncrypt(const QByteArray &Data);
  QByteArray secretDecrypt(const QByteArray &Data);
  void sendEncrypted(const QByteArray &Data);
  void sendPubKey();
  void sendUnencrypted(const QByteArray &Data);

private slots:
  void stateChangedSlot(QAbstractSocket::SocketState state);
  void sendDataSlot(const QByteArray &Data);
  void recvDataSlot();
};

#endif // SECURESOCKET_H
