// SPDX-License-Identifier: GPL-3.0-or-later
#include "rayeaccount.h"

#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QFile>
#include <QJsonDocument>

namespace {
const QString service = QStringLiteral("org.raye.Account1");
const QString path = QStringLiteral("/org/raye/Account1");
const QString iface = QStringLiteral("org.raye.Account1");

// Sign-in waits on the browser for up to ten minutes; everything else is quick.
constexpr int signInTimeout = 31 * 60 * 1000;
constexpr int callTimeout = 60 * 1000;

bool previewEnabled()
{
    return qEnvironmentVariable("RAYE_ACCOUNT_PREVIEW") == QLatin1String("1")
        || QFile::exists(QStringLiteral("/etc/raye/account-preview"));
}

QVariantList parseList(const QString &json)
{
    return QJsonDocument::fromJson(json.toUtf8()).toVariant().toList();
}
}

RayeAccount::RayeAccount(QObject *parent)
    : QObject(parent)
    , m_available(previewEnabled())
{
}

QVariantMap RayeAccount::parseState(const QString &json)
{
    return QJsonDocument::fromJson(json.toUtf8()).toVariant().toMap();
}

QUrl RayeAccount::picture() const
{
    // The file name changes with each new picture, so caches never show an old one.
    return QUrl(m_state.value(QStringLiteral("picture")).toString());
}

void RayeAccount::connectSignal()
{
    if (m_connected)
        return;
    m_connected = QDBusConnection::sessionBus().connect(service, path, iface, QStringLiteral("Changed"), this,
                                                       SLOT(refresh()));
}

void RayeAccount::call(const QString &method, const QVariantList &args, Done done)
{
    if (!m_available)
        return;
    connectSignal();
    auto msg = QDBusMessage::createMethodCall(service, path, iface, method);
    msg.setArguments(args);
    const int timeout = method == QLatin1String("SignIn") || method == QLatin1String("KeepSettings") ? signInTimeout : callTimeout;
    auto *watcher = new QDBusPendingCallWatcher(QDBusConnection::sessionBus().asyncCall(msg, timeout), this);
    connect(watcher, &QDBusPendingCallWatcher::finished, this, [this, watcher, method, done] {
        watcher->deleteLater();
        const QDBusMessage reply = watcher->reply();
        if (reply.type() == QDBusMessage::ErrorMessage) {
            const QString code = reply.errorName() == QLatin1String("org.freedesktop.DBus.Error.ServiceUnknown")
                ? QStringLiteral("no_service")
                : reply.errorMessage();
            Q_EMIT actionFailed(method, code);
            if (done)
                done(QString());
            return;
        }
        if (done)
            done(reply.arguments().isEmpty() ? QString() : reply.arguments().constFirst().toString());
    });
}

void RayeAccount::refresh()
{
    call(QStringLiteral("State"), {}, [this](const QString &json) {
        if (json.isEmpty())
            return;
        const QVariantMap next = parseState(json);
        if (next == m_state && m_loaded)
            return;
        const bool wasConnecting = !m_state.value(QStringLiteral("stage")).toString().isEmpty()
            || m_state.value(QStringLiteral("choose")).toBool();
        m_state = next;
        if (wasConnecting && stage().isEmpty() && !choosePending() && signedIn() && error().isEmpty())
            m_justConnected = true;
        else if (!signedIn())
            m_justConnected = false;
        m_loaded = true;
        Q_EMIT stateChanged();
    });
}

QUrl RayeAccount::manageUrl() const
{
    const QString server = m_state.value(QStringLiteral("server")).toString();
    return QUrl(server.startsWith(QLatin1String("https://")) ? server : QStringLiteral("https://account.rayelinux.com"));
}

void RayeAccount::keepSettings(const QString &from)
{
    call(QStringLiteral("KeepSettings"), {from});
}

void RayeAccount::dismissConnected()
{
    if (!m_justConnected)
        return;
    m_justConnected = false;
    Q_EMIT stateChanged();
}

void RayeAccount::signIn(bool createAccount)
{
    call(QStringLiteral("SignIn"), {createAccount});
}

void RayeAccount::cancelSignIn()
{
    call(QStringLiteral("CancelSignIn"), {});
}

void RayeAccount::signOut(bool restoreProfile)
{
    call(QStringLiteral("SignOut"), {restoreProfile});
}

void RayeAccount::syncNow()
{
    if (m_syncing)
        return;
    m_syncing = true;
    Q_EMIT syncingChanged();
    call(QStringLiteral("SyncNow"), {}, [this](const QString &) {
        m_syncing = false;
        Q_EMIT syncingChanged();
    });
}

void RayeAccount::loadDevices()
{
    m_devicesLoading = true;
    Q_EMIT devicesChanged();
    call(QStringLiteral("Devices"), {}, [this](const QString &json) {
        m_devicesLoading = false;
        if (!json.isEmpty())
            m_devices = parseList(json);
        Q_EMIT devicesChanged();
    });
}

void RayeAccount::removeDevice(const QString &id)
{
    call(QStringLiteral("RemoveDevice"), {id}, [this](const QString &) { loadDevices(); });
}

void RayeAccount::setSync(const QString &category, bool on)
{
    call(QStringLiteral("SetSync"), {category, on});
}

void RayeAccount::setProfileMode(const QString &mode)
{
    call(QStringLiteral("SetProfileMode"), {mode});
}

void RayeAccount::setDisplayName(const QString &name)
{
    call(QStringLiteral("SetDisplayName"), {name.trimmed()});
}

void RayeAccount::uploadPicture(const QUrl &file)
{
    call(QStringLiteral("UploadPicture"), {file.toLocalFile()});
}

void RayeAccount::loadLibrary()
{
    call(QStringLiteral("Library"), {}, [this](const QString &json) {
        if (json.isEmpty())
            return;
        m_library = parseList(json);
        Q_EMIT libraryChanged();
    });
}
