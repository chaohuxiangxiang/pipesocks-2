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

#include "securesocket.h"

SecureSocket::SecureSocket(const QString &Password,bool passive,QObject *parent)
  : TcpSocket(parent)
  , passive(passive)
  , local_pubKey(crypto_box_PUBLICKEYBYTES,0)
  , local_priKey(crypto_box_SECRETKEYBYTES,0)
{
  connect(this,SIGNAL(stateChanged(QAbstractSocket::SocketState)),
          this,SLOT(stateChangedSlot(QAbstractSocket::SocketState)));
  if (sodium_init() == -1)
    QCoreApplication::exit(1);
  crypto_box_keypair((unsigned char*)local_pubKey.data(), (unsigned char*)local_priKey.data());
  if((unsigned int)Password.size() >= crypto_secretbox_KEYBYTES)
    secret_key = Password.toLocal8Bit().left(crypto_secretbox_KEYBYTES);
  else
    secret_key = Password.toLocal8Bit() + QByteArray(crypto_secretbox_KEYBYTES - Password.toLocal8Bit().size(), (char)0x98);
}

void SecureSocket::sendEncrypted(const QByteArray &Data)
{
  QByteArray prefix(4,0);
  unsigned int l = crypto_secretbox_MACBYTES + 4 + crypto_secretbox_NONCEBYTES + Data.size();
  prefix[0] = (unsigned char)(l>>24);
  prefix[1] = (unsigned char)(l>>16);
  prefix[2] = (unsigned char)(l>>8);
  prefix[3] = (unsigned char)l;
  write(secretEncrypt(prefix)+Data);
}

void SecureSocket::sendPubKey()
{
  unsigned int l = randombytes_uniform(900);
  QByteArray garbage(l,0);
  randombytes_buf(garbage.data(),l);
  sendEncrypted(secretEncrypt(garbage+local_pubKey));
}

void SecureSocket::stateChangedSlot(QAbstractSocket::SocketState state)
{
  if (state == ConnectedState&&!passive)
    sendPubKey();
}

void SecureSocket::sendUnencrypted(const QByteArray &Data)
{
  sendEncrypted(publicEncrypt(Data));
}

void SecureSocket::sendDataSlot(const QByteArray &Data)
{
  if (state() == QAbstractSocket::UnconnectedState)
    return;
  if (remote_pubKey.size() == 0)
    send_buffer.push_back(Data);
  else
    sendUnencrypted(Data);
}

void SecureSocket::recvDataSlot()
{
  recv_buffer += readAll();
  while ((unsigned int)recv_buffer.length() >= crypto_secretbox_MACBYTES + 4 + crypto_secretbox_NONCEBYTES)
    {
      QByteArray prefix(secretDecrypt(recv_buffer.left(crypto_secretbox_MACBYTES + 4 + crypto_secretbox_NONCEBYTES)));
      if (prefix == "")
        return;
      unsigned int l = (unsigned char)prefix[0];
      l = (l<<8) + (unsigned char)prefix[1];
      l = (l<<8) + (unsigned char)prefix[2];
      l = (l<<8) + (unsigned char)prefix[3];
      if((unsigned int)recv_buffer.length()<l)
        return;
      QByteArray segment(recv_buffer.left(l).mid(crypto_secretbox_MACBYTES + 4 + crypto_secretbox_NONCEBYTES));
      recv_buffer = recv_buffer.mid(l);
      if (remote_pubKey.size() == 0)
        {
          remote_pubKey = secretDecrypt(segment).right(crypto_box_PUBLICKEYBYTES);
          if (passive)
            sendPubKey();

          for (QList<QByteArray>::iterator it = send_buffer.begin(); it != send_buffer.end(); ++it)
            sendUnencrypted(it.i->t());

          send_buffer.clear();
        }
      else
        {
          emit recvData(publicDecrypt(segment));
        }
    }
}

QByteArray SecureSocket::publicEncrypt(const QByteArray &Data)
{
  QByteArray ret(crypto_box_MACBYTES+Data.length(),0),nonce(crypto_box_NONCEBYTES,0);
  randombytes_buf(nonce.data(),nonce.length());
  if (crypto_box_easy((unsigned char*)ret.data(),
                      (unsigned char*)Data.data(),Data.length(),
                      (unsigned char*)nonce.data(),
                      (unsigned char*)remote_pubKey.data(),
                      (unsigned char*)local_priKey.data())==0)
    return ret+nonce;

  disconnectFromHost();
  return QByteArray();
}

QByteArray SecureSocket::publicDecrypt(const QByteArray &Data)
{
  QByteArray ret(Data.length()-crypto_box_MACBYTES-crypto_box_NONCEBYTES,0);
  if (crypto_box_open_easy((unsigned char*)ret.data(),
                           (unsigned char*)Data.data(),
                           Data.length()-crypto_box_NONCEBYTES,
                           (unsigned char*)Data.right(crypto_box_NONCEBYTES).data(),
                           (unsigned char*)remote_pubKey.data(),
                           (unsigned char*)local_priKey.data())==0)
    return ret;

  disconnectFromHost();
  return QByteArray();
}

QByteArray SecureSocket::secretEncrypt(const QByteArray &Data)
{
  QByteArray ret(crypto_secretbox_MACBYTES + Data.length(),0);
  QByteArray nonce(crypto_secretbox_NONCEBYTES,0);
  randombytes_buf(nonce.data(),nonce.length());
  if (crypto_secretbox_easy((unsigned char*)ret.data(),
                            (unsigned char*)Data.data(),Data.length(),
                            (unsigned char*)nonce.data(),
                            (unsigned char*)secret_key.data())==0)
    return ret+nonce;

  disconnectFromHost();
  return QByteArray();
}

QByteArray SecureSocket::secretDecrypt(const QByteArray &Data)
{
  QByteArray ret(Data.length()-crypto_secretbox_MACBYTES-crypto_secretbox_NONCEBYTES,0);
  if (crypto_secretbox_open_easy((unsigned char*)ret.data(),
                                 (unsigned char*)Data.data(),
                                 Data.length()-crypto_secretbox_NONCEBYTES,
                                 (unsigned char*)Data.right(crypto_secretbox_NONCEBYTES).data(),
                                 (unsigned char*)secret_key.data())==0)
    return ret;

  disconnectFromHost();
  return QByteArray();
}
