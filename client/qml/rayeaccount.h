// SPDX-License-Identifier: GPL-3.0-or-later
// RayeAccount: the Raye account as Settings and the Store see it. Every
// call to raye-accountd is asynchronous, so a slow network never blocks
// the UI; results come back through the properties and actionFailed().
#pragma once

#include <QObject>
#include <QQmlEngine>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

class QDBusPendingCall;

class RayeAccount : public QObject
{
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON

    // The hidden switch: false hides every trace of the account.
    Q_PROPERTY(bool available READ available CONSTANT)
    Q_PROPERTY(bool loaded READ loaded NOTIFY stateChanged)
    Q_PROPERTY(bool signedIn READ signedIn NOTIFY stateChanged)
    Q_PROPERTY(bool busy READ busy NOTIFY stateChanged)
    Q_PROPERTY(QString email READ email NOTIFY stateChanged)
    Q_PROPERTY(QString displayName READ displayName NOTIFY stateChanged)
    Q_PROPERTY(QUrl picture READ picture NOTIFY stateChanged)
    Q_PROPERTY(QString deviceName READ deviceName NOTIFY stateChanged)
    Q_PROPERTY(QString profileMode READ profileMode NOTIFY stateChanged)
    Q_PROPERTY(QVariantMap sync READ sync NOTIFY stateChanged)
    Q_PROPERTY(QString lastSync READ lastSync NOTIFY stateChanged)
    // error code of the last background step ("offline", "signed_out", ...)
    Q_PROPERTY(QString error READ error NOTIFY stateChanged)
    Q_PROPERTY(bool syncing READ syncing NOTIFY syncingChanged)
    // the sign-in in progress: "browser", "syncing" or ""
    Q_PROPERTY(QString stage READ stage NOTIFY stateChanged)
    // the account had other settings: this PC's or the account's?
    Q_PROPERTY(bool choosePending READ choosePending NOTIFY stateChanged)
    Q_PROPERTY(int chooseDiffer READ chooseDiffer NOTIFY stateChanged)
    // a sign-in just finished with everything synced, until dismissed
    Q_PROPERTY(bool justConnected READ justConnected NOTIFY stateChanged)
    Q_PROPERTY(QUrl manageUrl READ manageUrl NOTIFY stateChanged)
    Q_PROPERTY(QVariantList devices READ devices NOTIFY devicesChanged)
    Q_PROPERTY(bool devicesLoading READ devicesLoading NOTIFY devicesChanged)
    Q_PROPERTY(QVariantList library READ library NOTIFY libraryChanged)

public:
    explicit RayeAccount(QObject *parent = nullptr);

    bool available() const { return m_available; }
    bool loaded() const { return m_loaded; }
    bool signedIn() const { return m_state.value(QStringLiteral("signedIn")).toBool(); }
    bool busy() const { return m_state.value(QStringLiteral("busy")).toBool(); }
    QString email() const { return m_state.value(QStringLiteral("email")).toString(); }
    QString displayName() const { return m_state.value(QStringLiteral("displayName")).toString(); }
    QUrl picture() const;
    QString deviceName() const { return m_state.value(QStringLiteral("deviceName")).toString(); }
    QString profileMode() const { return m_state.value(QStringLiteral("profileMode")).toString(); }
    QVariantMap sync() const { return m_state.value(QStringLiteral("sync")).toMap(); }
    QString lastSync() const { return m_state.value(QStringLiteral("lastSync")).toString(); }
    QString error() const { return m_state.value(QStringLiteral("error")).toString(); }
    bool syncing() const { return m_syncing; }
    QString stage() const { return m_state.value(QStringLiteral("stage")).toString(); }
    bool choosePending() const { return m_state.value(QStringLiteral("choose")).toBool(); }
    int chooseDiffer() const { return m_state.value(QStringLiteral("chooseDiffer")).toInt(); }
    bool justConnected() const { return m_justConnected; }
    QUrl manageUrl() const;
    QVariantList devices() const { return m_devices; }
    bool devicesLoading() const { return m_devicesLoading; }
    QVariantList library() const { return m_library; }

    // Parses the service's State() answer; public for the tests.
    static QVariantMap parseState(const QString &json);

    Q_INVOKABLE void refresh();
    Q_INVOKABLE void signIn(bool createAccount = false);
    Q_INVOKABLE void cancelSignIn();
    Q_INVOKABLE void signOut(bool restoreProfile);
    Q_INVOKABLE void syncNow();
    Q_INVOKABLE void loadDevices();
    Q_INVOKABLE void removeDevice(const QString &id);
    Q_INVOKABLE void setSync(const QString &category, bool on);
    Q_INVOKABLE void setProfileMode(const QString &mode);
    Q_INVOKABLE void setDisplayName(const QString &name);
    Q_INVOKABLE void uploadPicture(const QUrl &file);
    Q_INVOKABLE void loadLibrary();
    // "pc" or "account"
    Q_INVOKABLE void keepSettings(const QString &from);
    Q_INVOKABLE void dismissConnected();

Q_SIGNALS:
    void stateChanged();
    void syncingChanged();
    void devicesChanged();
    void libraryChanged();
    // action: the method that failed; code: what the service said
    void actionFailed(const QString &action, const QString &code);

private:
    using Done = std::function<void(const QString &)>;
    void call(const QString &method, const QVariantList &args, Done done = {});
    void connectSignal();

    bool m_available = false;
    bool m_loaded = false;
    bool m_connected = false;
    bool m_syncing = false;
    bool m_justConnected = false;
    bool m_devicesLoading = false;
    QVariantMap m_state;
    QVariantList m_devices;
    QVariantList m_library;
};
