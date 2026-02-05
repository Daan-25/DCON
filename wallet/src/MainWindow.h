#pragma once

#include <functional>

#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMainWindow>
#include <QProcess>
#include <QProgressBar>
#include <QPushButton>
#include <QSet>
#include <QStackedWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QTimer>

class MainWindow : public QMainWindow {
 public:
  explicit MainWindow(QWidget* parent = nullptr);

 private:
  QStackedWidget* pages;

  QWidget* overviewPage;
  QWidget* sendPage;
  QWidget* receivePage;
  QWidget* transactionsPage;
  QWidget* networkPage;
  QWidget* settingsPage;
  QWidget* debugPage;

  QLineEdit* dconPathEdit;
  QLineEdit* dataDirEdit;
  QTextEdit* logView;
  QListWidget* addressList;
  QLineEdit* exportAddressEdit;

  QLineEdit* chainAddressEdit;
  QLineEdit* balanceAddressEdit;
  QLabel* availableValueLabel;
  QLabel* pendingValueLabel;
  QLabel* totalValueLabel;
  QLabel* overviewSyncLabel;
  QTableWidget* recentTable;
  QLabel* recentSyncLabel;

  QLineEdit* historyAddressEdit;
  QTableWidget* historyTable;

  QLineEdit* sendFromEdit;
  QLineEdit* sendToEdit;
  QLineEdit* sendAmountEdit;
  QLineEdit* sendFeeEdit;
  QComboBox* sendFeeMode;
  QLineEdit* sendPeersEdit;
  QCheckBox* sendMineCheck;

  QLineEdit* nodePortEdit;
  QLineEdit* nodePeersEdit;
  QLineEdit* nodeMinerEdit;
  QProcess* nodeProcess;
  QPushButton* startNodeBtn;
  QPushButton* stopNodeBtn;
  QLabel* nodeStatusLabel;
  QLabel* syncStatusLabel;
  QLabel* connectionsLabel;
  QLabel* heightLabel;
  QProgressBar* syncProgress;
  QTimer* peerStatusTimer;
  QTableWidget* peersTable;
  QSet<QString> knownPeers;

  void appendLog(const QString& text);
  QString dconPath() const;
  QString dataDir() const;
  bool ensureDconPath();
  QString peersFilePath() const;
  QString chainFilePath() const;
  int readChainHeight() const;
  void refreshPeerStatus();
  void refreshChainHeight();

  void runCommand(const QStringList& args,
                  const std::function<void(const QString&)>& onFinished = nullptr);

  void setupUi();
  void wireActions();

  void handleListAddresses(const QString& output);
  void handleBalanceOutput(const QString& output);
  void handleHistoryOutput(const QString& output);

  void startNode();
  void stopNode();
  void updateNodeStatus(bool running);
};
