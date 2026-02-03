#include "MainWindow.h"

#include <QApplication>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QAbstractItemView>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMessageBox>
#include <QPushButton>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <memory>

MainWindow::MainWindow(QWidget* parent) : QWidget(parent), nodeProcess(nullptr) {
  setupUi();
  wireActions();
}

void MainWindow::appendLog(const QString& text) {
  QString line = QString("[%1] %2")
                     .arg(QDateTime::currentDateTime().toString("HH:mm:ss"))
                     .arg(text.trimmed());
  logView->append(line);
}

QString MainWindow::dconPath() const {
  return dconPathEdit->text().trimmed();
}

QString MainWindow::dataDir() const {
  return dataDirEdit->text().trimmed();
}

bool MainWindow::ensureDconPath() {
  QString path = dconPath();
  if (path.isEmpty()) {
    QMessageBox::warning(this, "Missing binary",
                         "Please select the dcon binary first.");
    return false;
  }
  QFileInfo info(path);
  if (!info.exists() || !info.isFile()) {
    QMessageBox::warning(this, "Invalid binary",
                         "The selected dcon binary does not exist.");
    return false;
  }
  return true;
}

void MainWindow::runCommand(
    const QStringList& args,
    const std::function<void(const QString&)>& onFinished) {
  if (!ensureDconPath()) {
    return;
  }

  QProcess* process = new QProcess(this);
  process->setProgram(dconPath());
  process->setArguments(args);

  auto outputBuffer = std::make_shared<QString>();

  connect(process, &QProcess::readyReadStandardOutput, this, [this, process, outputBuffer]() {
    QString chunk = process->readAllStandardOutput();
    outputBuffer->append(chunk);
    if (!chunk.trimmed().isEmpty()) {
      appendLog(chunk);
    }
  });

  connect(process, &QProcess::readyReadStandardError, this, [this, process]() {
    QString chunk = process->readAllStandardError();
    if (!chunk.trimmed().isEmpty()) {
      appendLog(QString("ERROR: %1").arg(chunk));
    }
  });

  connect(process,
          QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
          this, [this, process, outputBuffer, onFinished](int, QProcess::ExitStatus) {
            if (onFinished) {
              onFinished(*outputBuffer);
            }
            process->deleteLater();
          });

  process->start();
}

void MainWindow::setupUi() {
  setWindowTitle("DCON Wallet");
  resize(980, 720);

  auto* rootLayout = new QVBoxLayout(this);

  // Binary + data directory
  auto* pathGroup = new QGroupBox("Binary & Data");
  auto* pathLayout = new QGridLayout(pathGroup);

  dconPathEdit = new QLineEdit();
  dataDirEdit = new QLineEdit();

  QString defaultBin = QDir(QCoreApplication::applicationDirPath())
                           .filePath("../../build/dcon");
  dconPathEdit->setText(QDir::cleanPath(defaultBin));
  dconPathEdit->setPlaceholderText("Path to dcon binary");
  dataDirEdit->setPlaceholderText("Optional data directory");

  auto* browseBin = new QPushButton("Browse...");
  auto* browseData = new QPushButton("Browse...");

  pathLayout->addWidget(new QLabel("DCON binary"), 0, 0);
  pathLayout->addWidget(dconPathEdit, 0, 1);
  pathLayout->addWidget(browseBin, 0, 2);
  pathLayout->addWidget(new QLabel("Data dir"), 1, 0);
  pathLayout->addWidget(dataDirEdit, 1, 1);
  pathLayout->addWidget(browseData, 1, 2);

  rootLayout->addWidget(pathGroup);

  // Left side controls
  auto* controlsLayout = new QVBoxLayout();

  // Wallets
  auto* walletGroup = new QGroupBox("Wallets");
  auto* walletLayout = new QVBoxLayout(walletGroup);
  auto* walletButtonRow = new QHBoxLayout();
  auto* createWalletBtn = new QPushButton("Create Wallet");
  auto* listWalletsBtn = new QPushButton("List Addresses");
  walletButtonRow->addWidget(createWalletBtn);
  walletButtonRow->addWidget(listWalletsBtn);
  walletLayout->addLayout(walletButtonRow);

  addressList = new QListWidget();
  walletLayout->addWidget(addressList);

  auto* exportRow = new QHBoxLayout();
  exportAddressEdit = new QLineEdit();
  exportAddressEdit->setPlaceholderText("Address to export");
  auto* exportWalletBtn = new QPushButton("Export Wallet");
  exportRow->addWidget(exportAddressEdit);
  exportRow->addWidget(exportWalletBtn);
  walletLayout->addLayout(exportRow);

  auto* importWalletBtn = new QPushButton("Import Wallet");
  walletLayout->addWidget(importWalletBtn);

  controlsLayout->addWidget(walletGroup);

  // Chain
  auto* chainGroup = new QGroupBox("Blockchain");
  auto* chainLayout = new QVBoxLayout(chainGroup);

  auto* createChainRow = new QHBoxLayout();
  chainAddressEdit = new QLineEdit();
  chainAddressEdit->setPlaceholderText("Address for genesis reward");
  auto* createChainBtn = new QPushButton("Create Blockchain");
  createChainRow->addWidget(chainAddressEdit);
  createChainRow->addWidget(createChainBtn);

  auto* balanceRow = new QHBoxLayout();
  balanceAddressEdit = new QLineEdit();
  balanceAddressEdit->setPlaceholderText("Address to check");
  auto* balanceBtn = new QPushButton("Get Balance");
  balanceValueEdit = new QLineEdit();
  balanceValueEdit->setReadOnly(true);
  balanceRow->addWidget(balanceAddressEdit);
  balanceRow->addWidget(balanceBtn);
  balanceRow->addWidget(balanceValueEdit);

  chainLayout->addLayout(createChainRow);
  chainLayout->addLayout(balanceRow);

  controlsLayout->addWidget(chainGroup);

  // Transactions
  auto* historyGroup = new QGroupBox("Transactions");
  auto* historyLayout = new QVBoxLayout(historyGroup);
  auto* historyRow = new QHBoxLayout();
  historyAddressEdit = new QLineEdit();
  historyAddressEdit->setPlaceholderText("Address for history");
  auto* historyBtn = new QPushButton("Load History");
  historyRow->addWidget(historyAddressEdit);
  historyRow->addWidget(historyBtn);
  historyLayout->addLayout(historyRow);

  historyTable = new QTableWidget(0, 6);
  historyTable->setHorizontalHeaderLabels(
      {"Height", "Time", "TxID", "Received", "Sent", "Net"});
  historyTable->horizontalHeader()->setStretchLastSection(true);
  historyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  historyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  historyLayout->addWidget(historyTable);

  controlsLayout->addWidget(historyGroup);

  // Send
  auto* sendGroup = new QGroupBox("Send");
  auto* sendLayout = new QFormLayout(sendGroup);

  sendFromEdit = new QLineEdit();
  sendToEdit = new QLineEdit();
  sendAmountEdit = new QLineEdit();
  sendPeersEdit = new QLineEdit();
  sendMineCheck = new QCheckBox("Mine immediately");
  sendMineCheck->setChecked(true);

  sendLayout->addRow("From", sendFromEdit);
  sendLayout->addRow("To", sendToEdit);
  sendLayout->addRow("Amount", sendAmountEdit);
  sendLayout->addRow("Peers (optional)", sendPeersEdit);
  sendLayout->addRow(sendMineCheck);

  auto* sendBtn = new QPushButton("Send Transaction");
  sendLayout->addRow(sendBtn);

  controlsLayout->addWidget(sendGroup);

  // Node
  auto* nodeGroup = new QGroupBox("Node");
  auto* nodeLayout = new QFormLayout(nodeGroup);

  nodePortEdit = new QLineEdit();
  nodePeersEdit = new QLineEdit();
  nodeMinerEdit = new QLineEdit();

  nodePortEdit->setPlaceholderText("3001");
  nodePeersEdit->setPlaceholderText("127.0.0.1:3002,127.0.0.1:3003");
  nodeMinerEdit->setPlaceholderText("Miner address (optional)");

  nodeLayout->addRow("Port", nodePortEdit);
  nodeLayout->addRow("Peers", nodePeersEdit);
  nodeLayout->addRow("Miner", nodeMinerEdit);

  auto* nodeButtonRow = new QHBoxLayout();
  auto* startNodeBtn = new QPushButton("Start Node");
  auto* stopNodeBtn = new QPushButton("Stop Node");
  nodeButtonRow->addWidget(startNodeBtn);
  nodeButtonRow->addWidget(stopNodeBtn);
  nodeLayout->addRow(nodeButtonRow);

  controlsLayout->addWidget(nodeGroup);
  controlsLayout->addStretch(1);

  // Log
  auto* logGroup = new QGroupBox("Log");
  auto* logLayout = new QVBoxLayout(logGroup);
  logView = new QTextEdit();
  logView->setReadOnly(true);
  logLayout->addWidget(logView);

  // Splitter
  auto* split = new QSplitter();
  auto* leftPanel = new QWidget();
  leftPanel->setLayout(controlsLayout);
  split->addWidget(leftPanel);
  split->addWidget(logGroup);
  split->setStretchFactor(0, 1);
  split->setStretchFactor(1, 1);

  rootLayout->addWidget(split);

  // Connections
  connect(browseBin, &QPushButton::clicked, this, [this]() {
    QString path = QFileDialog::getOpenFileName(this, "Select dcon binary");
    if (!path.isEmpty()) {
      dconPathEdit->setText(path);
    }
  });

  connect(browseData, &QPushButton::clicked, this, [this]() {
    QString path = QFileDialog::getExistingDirectory(this, "Select data directory");
    if (!path.isEmpty()) {
      dataDirEdit->setText(path);
    }
  });

  connect(createWalletBtn, &QPushButton::clicked, this, [this]() {
    QStringList args = {"createwallet"};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString& output) {
      if (output.contains("New address:")) {
        handleListAddresses(output);
      }
    });
  });

  connect(listWalletsBtn, &QPushButton::clicked, this, [this]() {
    QStringList args = {"listaddresses"};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString& output) { handleListAddresses(output); });
  });

  connect(exportWalletBtn, &QPushButton::clicked, this, [this]() {
    QString address = exportAddressEdit->text().trimmed();
    if (address.isEmpty()) {
      QMessageBox::warning(this, "Missing address",
                           "Please enter an address to export.");
      return;
    }
    QString filePath = QFileDialog::getSaveFileName(this, "Export wallet",
                                                   "wallet.pem",
                                                   "PEM Files (*.pem);;All Files (*)");
    if (filePath.isEmpty()) {
      return;
    }
    QStringList args = {"exportwallet", "-address", address, "-out", filePath};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args);
  });

  connect(importWalletBtn, &QPushButton::clicked, this, [this]() {
    QString filePath = QFileDialog::getOpenFileName(this, "Import wallet",
                                                   QString(),
                                                   "PEM Files (*.pem);;All Files (*)");
    if (filePath.isEmpty()) {
      return;
    }
    QStringList args = {"importwallet", "-in", filePath};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString&) {
      QStringList listArgs = {"listaddresses"};
      if (!dataDir().isEmpty()) {
        listArgs << "-datadir" << dataDir();
      }
      runCommand(listArgs, [this](const QString& output) { handleListAddresses(output); });
    });
  });

  connect(createChainBtn, &QPushButton::clicked, this, [this]() {
    QString address = chainAddressEdit->text().trimmed();
    if (address.isEmpty()) {
      QMessageBox::warning(this, "Missing address",
                           "Please enter a genesis address.");
      return;
    }
    QStringList args = {"createblockchain", "-address", address};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args);
  });

  connect(balanceBtn, &QPushButton::clicked, this, [this]() {
    QString address = balanceAddressEdit->text().trimmed();
    if (address.isEmpty()) {
      QMessageBox::warning(this, "Missing address",
                           "Please enter an address.");
      return;
    }
    QStringList args = {"getbalance", "-address", address};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString& output) { handleBalanceOutput(output); });
  });

  connect(historyBtn, &QPushButton::clicked, this, [this]() {
    QString address = historyAddressEdit->text().trimmed();
    if (address.isEmpty()) {
      QMessageBox::warning(this, "Missing address",
                           "Please enter an address.");
      return;
    }
    QStringList args = {"txhistory", "-address", address};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString& output) { handleHistoryOutput(output); });
  });

  connect(sendBtn, &QPushButton::clicked, this, [this]() {
    QString from = sendFromEdit->text().trimmed();
    QString to = sendToEdit->text().trimmed();
    QString amount = sendAmountEdit->text().trimmed();
    QString peers = sendPeersEdit->text().trimmed();

    if (from.isEmpty() || to.isEmpty() || amount.isEmpty()) {
      QMessageBox::warning(this, "Missing fields",
                           "From, To, and Amount are required.");
      return;
    }

    QStringList args = {"send", "-from", from, "-to", to, "-amount", amount,
                        "-mine", sendMineCheck->isChecked() ? "true" : "false"};
    if (!peers.isEmpty()) {
      args << "-peers" << peers;
    }
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }

    runCommand(args);
  });

  connect(startNodeBtn, &QPushButton::clicked, this, [this]() { startNode(); });
  connect(stopNodeBtn, &QPushButton::clicked, this, [this]() { stopNode(); });

  connect(addressList, &QListWidget::itemClicked, this, [this](QListWidgetItem* item) {
    QString address = item->text();
    if (sendFromEdit->text().isEmpty()) {
      sendFromEdit->setText(address);
    } else {
      sendToEdit->setText(address);
    }
    if (chainAddressEdit->text().isEmpty()) {
      chainAddressEdit->setText(address);
    }
    if (balanceAddressEdit->text().isEmpty()) {
      balanceAddressEdit->setText(address);
    }
    if (exportAddressEdit->text().isEmpty()) {
      exportAddressEdit->setText(address);
    }
    if (historyAddressEdit->text().isEmpty()) {
      historyAddressEdit->setText(address);
    }
  });
}

void MainWindow::wireActions() {
  // Reserved for future menu/actions.
}

void MainWindow::handleListAddresses(const QString& output) {
  QStringList lines = output.split('\n', Qt::SkipEmptyParts);
  QStringList addresses;
  for (const QString& line : lines) {
    QString trimmed = line.trimmed();
    if (trimmed.startsWith("New address:")) {
      QString addr = trimmed.section(':', 1).trimmed();
      if (!addr.isEmpty()) {
        addresses << addr;
      }
      continue;
    }
    if (trimmed.startsWith("D") && trimmed.length() >= 10) {
      addresses << trimmed;
    }
  }
  if (!addresses.isEmpty()) {
    addressList->clear();
    addressList->addItems(addresses);
  }
}

void MainWindow::handleBalanceOutput(const QString& output) {
  QStringList lines = output.split('\n', Qt::SkipEmptyParts);
  for (const QString& line : lines) {
    if (line.startsWith("Balance of")) {
      int idx = line.lastIndexOf(":");
      if (idx >= 0) {
        QString value = line.mid(idx + 1).trimmed();
        balanceValueEdit->setText(value);
        return;
      }
    }
  }
}

void MainWindow::handleHistoryOutput(const QString& output) {
  historyTable->setRowCount(0);
  QStringList lines = output.split('\n', Qt::SkipEmptyParts);
  for (const QString& line : lines) {
    if (!line.startsWith("TX ")) {
      continue;
    }
    QStringList parts = line.split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 7) {
      continue;
    }
    int row = historyTable->rowCount();
    historyTable->insertRow(row);

    QString height = parts[1];
    QString timestamp = parts[2];
    QString txid = parts[3];
    QString received = parts[4];
    QString sent = parts[5];
    QString net = parts[6];

    QDateTime dt = QDateTime::fromSecsSinceEpoch(timestamp.toLongLong());
    QString timeText = dt.toString("yyyy-MM-dd HH:mm:ss");

    historyTable->setItem(row, 0, new QTableWidgetItem(height));
    historyTable->setItem(row, 1, new QTableWidgetItem(timeText));
    historyTable->setItem(row, 2, new QTableWidgetItem(txid));
    historyTable->setItem(row, 3, new QTableWidgetItem(received));
    historyTable->setItem(row, 4, new QTableWidgetItem(sent));
    historyTable->setItem(row, 5, new QTableWidgetItem(net));
  }
}

void MainWindow::startNode() {
  if (!ensureDconPath()) {
    return;
  }
  if (nodeProcess) {
    QMessageBox::information(this, "Node running", "Node is already running.");
    return;
  }

  QString port = nodePortEdit->text().trimmed();
  if (port.isEmpty()) {
    QMessageBox::warning(this, "Missing port", "Please enter a port.");
    return;
  }

  QStringList args = {"startnode", "-port", port};
  QString peers = nodePeersEdit->text().trimmed();
  QString miner = nodeMinerEdit->text().trimmed();
  if (!peers.isEmpty()) {
    args << "-peers" << peers;
  }
  if (!miner.isEmpty()) {
    args << "-miner" << miner;
  }
  if (!dataDir().isEmpty()) {
    args << "-datadir" << dataDir();
  }

  nodeProcess = new QProcess(this);
  nodeProcess->setProgram(dconPath());
  nodeProcess->setArguments(args);

  connect(nodeProcess, &QProcess::readyReadStandardOutput, this, [this]() {
    QString chunk = nodeProcess->readAllStandardOutput();
    if (!chunk.trimmed().isEmpty()) {
      appendLog(chunk);
    }
  });

  connect(nodeProcess, &QProcess::readyReadStandardError, this, [this]() {
    QString chunk = nodeProcess->readAllStandardError();
    if (!chunk.trimmed().isEmpty()) {
      appendLog(QString("ERROR: %1").arg(chunk));
    }
  });

  connect(nodeProcess,
          QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
          this, [this](int, QProcess::ExitStatus) {
            appendLog("Node process stopped.");
            nodeProcess->deleteLater();
            nodeProcess = nullptr;
          });

  nodeProcess->start();
  appendLog("Node process started.");
}

void MainWindow::stopNode() {
  if (!nodeProcess) {
    QMessageBox::information(this, "Node not running", "Node is not running.");
    return;
  }
  nodeProcess->terminate();
  if (!nodeProcess->waitForFinished(1500)) {
    nodeProcess->kill();
  }
}
