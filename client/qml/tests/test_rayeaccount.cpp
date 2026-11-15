// SPDX-License-Identifier: GPL-3.0-or-later
// RayeAccount against a stand-in for raye-accountd on a private session
// bus (the test runs under dbus-run-session).
#include <QDBusConnection>
#include <QSignalSpy>
#include <QTest>

#include "rayeaccount.h"

class FakeService : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.raye.Account1")

public:
    QString state = QStringLiteral(
        R"({"signedIn":true,"busy":false,"email":"ana@example.com","displayName":"Ana",)"
        R"("picture":"file:///tmp/p.png","deviceName":"Bureau","profileMode":"both",)"
        R"("sync":{"personalization":true,"apps":false},"lastSync":"2026-11-02T10:00:00Z","error":""})");
    QStringList calls;

public Q_SLOTS:
    QString State() { return state; }
    QString Devices() { return QStringLiteral(R"([{"id":"a","name":"Bureau","this_device":true}])"); }
    void SetSync(const QString &category, bool on) { calls << QStringLiteral("SetSync %1 %2").arg(category).arg(on); }
    void SetProfileMode(const QString &mode) { calls << QStringLiteral("SetProfileMode ") + mode; }
    void KeepSettings(const QString &from) { calls << QStringLiteral("KeepSettings ") + from; }

Q_SIGNALS:
    void Changed();
};

class TestRayeAccount : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase()
    {
        qputenv("RAYE_ACCOUNT_PREVIEW", "1");
        auto bus = QDBusConnection::sessionBus();
        QVERIFY(bus.registerService(QStringLiteral("org.raye.Account1")));
        QVERIFY(bus.registerObject(QStringLiteral("/org/raye/Account1"), &m_fake,
                                   QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllSignals));
    }

    void parsesState()
    {
        const QVariantMap s = RayeAccount::parseState(m_fake.state);
        QCOMPARE(s.value(QStringLiteral("email")).toString(), QStringLiteral("ana@example.com"));
        QVERIFY(RayeAccount::parseState(QStringLiteral("not json")).isEmpty());
    }

    void loadsStateOnlyWhenAsked()
    {
        RayeAccount account;
        QVERIFY(account.available());
        QVERIFY(!account.loaded());
        QSignalSpy changed(&account, &RayeAccount::stateChanged);
        account.refresh();
        QVERIFY(changed.wait(2000));
        QVERIFY(account.signedIn());
        QCOMPARE(account.displayName(), QStringLiteral("Ana"));
        QCOMPARE(account.sync().value(QStringLiteral("apps")).toBool(), false);
        QCOMPARE(account.picture(), QUrl(QStringLiteral("file:///tmp/p.png")));
    }

    void followsTheChangedSignal()
    {
        RayeAccount account;
        QSignalSpy changed(&account, &RayeAccount::stateChanged);
        account.refresh();
        QVERIFY(changed.wait(2000));
        m_fake.state.replace(QStringLiteral("\"Ana\""), QStringLiteral("\"Ana T.\""));
        Q_EMIT m_fake.Changed();
        QVERIFY(changed.wait(2000));
        QCOMPARE(account.displayName(), QStringLiteral("Ana T."));
    }

    void sendsChoices()
    {
        RayeAccount account;
        account.setSync(QStringLiteral("apps"), true);
        account.setProfileMode(QStringLiteral("name"));
        QTRY_COMPARE(m_fake.calls.size(), 2);
        QCOMPARE(m_fake.calls.at(0), QStringLiteral("SetSync apps 1"));
        QCOMPARE(m_fake.calls.at(1), QStringLiteral("SetProfileMode name"));
    }

    void reportsFailures()
    {
        RayeAccount account;
        QSignalSpy failed(&account, &RayeAccount::actionFailed);
        account.syncNow();
        QVERIFY(account.syncing());
        QVERIFY(failed.wait(2000));
        QCOMPARE(failed.first().at(0).toString(), QStringLiteral("SyncNow"));
        QTRY_VERIFY(!account.syncing());
    }

    void saysWhenTheConnectionIsDone()
    {
        RayeAccount account;
        QSignalSpy changed(&account, &RayeAccount::stateChanged);
        m_fake.state = QStringLiteral(R"({"signedIn":true,"stage":"syncing","choose":false})");
        account.refresh();
        QVERIFY(changed.wait(2000));
        QCOMPARE(account.stage(), QStringLiteral("syncing"));
        QVERIFY(!account.justConnected());
        m_fake.state = QStringLiteral(R"({"signedIn":true,"stage":"","choose":true,"chooseDiffer":4})");
        Q_EMIT m_fake.Changed();
        QVERIFY(changed.wait(2000));
        QVERIFY(account.choosePending());
        QCOMPARE(account.chooseDiffer(), 4);
        QVERIFY2(!account.justConnected(), "still has to choose");
        account.keepSettings(QStringLiteral("pc"));
        QTRY_VERIFY(m_fake.calls.contains(QStringLiteral("KeepSettings pc")));
        m_fake.state = QStringLiteral(R"({"signedIn":true,"stage":"syncing","choose":false})");
        Q_EMIT m_fake.Changed();
        QVERIFY(changed.wait(2000));
        m_fake.state = QStringLiteral(R"({"signedIn":true,"stage":"","choose":false})");
        Q_EMIT m_fake.Changed();
        QVERIFY(changed.wait(2000));
        QVERIFY(account.justConnected());
        account.dismissConnected();
        QVERIFY(!account.justConnected());
    }

    void loadsDevices()
    {
        RayeAccount account;
        QSignalSpy spy(&account, &RayeAccount::devicesChanged);
        account.loadDevices();
        QTRY_COMPARE(account.devices().size(), 1);
        QVERIFY(!account.devicesLoading());
    }

private:
    FakeService m_fake;
};

QTEST_GUILESS_MAIN(TestRayeAccount)
#include "test_rayeaccount.moc"
