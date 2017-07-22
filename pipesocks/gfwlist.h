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

#ifndef GFWLIST_H
#define GFWLIST_H

#include <QObject>
#include <QTimer>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QNetworkProxy>
#include "log.h"

class GFWList : public QObject {
    Q_OBJECT
private:
    static const QString GFWListAddress;
    QTimer *timer;
    QNetworkAccessManager *nam;
    QString PAC;
    bool available,retrieving;
public:
    explicit GFWList(QObject *parent  =  0);
    void RequestGFWList();
signals:
    void RecvGFWList(const QString &GFWList);
    void Fail();
private slots:
    void timeout();
    void ProcessGFWList(QNetworkReply *reply);
};

#endif // GFWLIST_H
