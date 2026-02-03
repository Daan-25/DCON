#pragma once

#include <functional>

#include <QCheckBox>
#include <QLineEdit>
#include <QListWidget>
#include <QProcess>
#include <QTextEdit>
#include <QWidget>

class MainWindow : public QWidget {
 public:
  explicit MainWindow(QWidget* parent = nullptr);

 private:
  QLineEdit* dconPathEdit;
  QLineEdit* dataDirEdit;
  QTextEdit* logView;
  QListWidget* addressList;
  QLineEdit* exportAddressEdit;

  QLineEdit* chainAddressEdit;
  QLineEdit* balanceAddressEdit;
  QLineEdit* balanceValueEdit;

  QLineEdit* sendFromEdit;
  QLineEdit* sendToEdit;
  QLineEdit* sendAmountEdit;
  QLineEdit* sendPeersEdit;
  QCheckBox* sendMineCheck;

  QLineEdit* nodePortEdit;
  QLineEdit* nodePeersEdit;
  QLineEdit* nodeMinerEdit;
  QProcess* nodeProcess;

  void appendLog(const QString& text);
  QString dconPath() const;
  QString dataDir() const;
  bool ensureDconPath();

  void runCommand(const QStringList& args,
                  const std::function<void(const QString&)>& onFinished = nullptr);

  void setupUi();
  void wireActions();

  void handleListAddresses(const QString& output);
  void handleBalanceOutput(const QString& output);

  void startNode();
  void stopNode();
};
