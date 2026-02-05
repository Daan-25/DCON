#include "MainWindow.h"

#include <QAction>
#include <QApplication>
#include <QClipboard>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QAbstractItemView>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFont>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QSize>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QStyleFactory>
#include <QTextStream>
#include <QToolBar>
#include <QSplitter>
#include <QTableWidgetItem>
#include <QVBoxLayout>

#include <memory>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent), nodeProcess(nullptr) {
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

QString MainWindow::peersFilePath() const {
  QString dir = dataDir();
  if (!dir.isEmpty()) {
    return QDir(dir).filePath("peers.dat");
  }

  QString binPath = dconPath();
  if (!binPath.isEmpty()) {
    QFileInfo info(binPath);
    if (info.exists()) {
      QString candidate = QDir(info.absolutePath()).filePath("peers.dat");
      if (QFileInfo::exists(candidate)) {
        return candidate;
      }
    }
  }

  return QDir::currentPath() + "/peers.dat";
}

QString MainWindow::chainFilePath() const {
  QString dir = dataDir();
  if (!dir.isEmpty()) {
    return QDir(dir).filePath("dcon.db");
  }

  QString binPath = dconPath();
  if (!binPath.isEmpty()) {
    QFileInfo info(binPath);
    if (info.exists()) {
      QString candidate = QDir(info.absolutePath()).filePath("dcon.db");
      if (QFileInfo::exists(candidate)) {
        return candidate;
      }
    }
  }

  return QDir::currentPath() + "/dcon.db";
}

int MainWindow::readChainHeight() const {
  QFile file(chainFilePath());
  if (!file.exists() || !file.open(QIODevice::ReadOnly)) {
    return -1;
  }
  if (file.size() < 4) {
    return -1;
  }
  unsigned char buf[4];
  if (file.read(reinterpret_cast<char*>(buf), sizeof(buf)) != sizeof(buf)) {
    return -1;
  }
  uint32_t count = static_cast<uint32_t>(buf[0]) |
                   (static_cast<uint32_t>(buf[1]) << 8) |
                   (static_cast<uint32_t>(buf[2]) << 16) |
                   (static_cast<uint32_t>(buf[3]) << 24);
  if (count == 0) {
    return -1;
  }
  return static_cast<int>(count) - 1;
}

void MainWindow::refreshPeerStatus() {
  if (!connectionsLabel) {
    return;
  }
  bool running = nodeProcess && nodeProcess->state() != QProcess::NotRunning;
  QString path = peersFilePath();
  QFile file(path);
  if (!file.exists() || !file.open(QIODevice::ReadOnly | QIODevice::Text)) {
    connectionsLabel->setText("Connections: 0");
    connectionsLabel->setToolTip(QString());
    if (peersTable) {
      peersTable->setRowCount(0);
    }
    if (!running) {
      knownPeers.clear();
    }
    refreshChainHeight();
    return;
  }

  QTextStream in(&file);
  int knownCount = 0;
  int activeCount = 0;
  QString lastPeer;
  QSet<QString> currentPeers;
  QSet<QString> activePeers;
  if (peersTable) {
    peersTable->setRowCount(0);
  }
  qint64 now = QDateTime::currentSecsSinceEpoch();
  const qint64 activeWindowSeconds = 120;
  auto fmtTs = [](const QString& value) -> QString {
    bool ok = false;
    qint64 ts = value.toLongLong(&ok);
    if (!ok || ts <= 0) {
      return "-";
    }
    return QDateTime::fromSecsSinceEpoch(ts).toString("yyyy-MM-dd HH:mm:ss");
  };

  while (!in.atEnd()) {
    QString line = in.readLine().trimmed();
    if (line.isEmpty()) {
      continue;
    }
    QString peer = line.section('|', 0, 0).trimmed();
    QString lastSeenRaw = line.section('|', 1, 1).trimmed();
    QString lastSuccessRaw = line.section('|', 2, 2).trimmed();
    QString lastSeen = fmtTs(lastSeenRaw);
    QString lastSuccess = fmtTs(lastSuccessRaw);
    QString attempts = line.section('|', 3, 3).trimmed();
    if (!peer.isEmpty()) {
      knownCount++;
      lastPeer = peer;
      currentPeers.insert(peer);
      if (running) {
        bool ok = false;
        qint64 lastSuccessTs = lastSuccessRaw.toLongLong(&ok);
        if (ok && lastSuccessTs > 0 && (now - lastSuccessTs) <= activeWindowSeconds) {
          activeCount++;
          activePeers.insert(peer);
        }
      }
      if (peersTable) {
        int row = peersTable->rowCount();
        peersTable->insertRow(row);
        peersTable->setItem(row, 0, new QTableWidgetItem(peer));
        peersTable->setItem(row, 1, new QTableWidgetItem(lastSeen));
        peersTable->setItem(row, 2, new QTableWidgetItem(lastSuccess));
        peersTable->setItem(row, 3, new QTableWidgetItem(attempts));
      }
    }
  }
  if (running) {
    connectionsLabel->setText(QString("Connections: %1").arg(activeCount));
  } else {
    connectionsLabel->setText("Connections: 0");
  }
  if (knownCount > 0) {
    connectionsLabel->setToolTip(QString("Known peers: %1").arg(knownCount));
  } else {
    connectionsLabel->setToolTip(QString());
  }

  if (running && !activePeers.isEmpty()) {
    QStringList newPeers;
    for (const QString& peer : activePeers) {
      if (!knownPeers.contains(peer)) {
        newPeers << peer;
      }
    }
    if (!newPeers.isEmpty()) {
      QString message = QString("Connected to %1").arg(newPeers.join(", "));
      statusBar()->showMessage(message, 4000);
      appendLog(message);
    }
    knownPeers = activePeers;
  } else if (!running) {
    knownPeers.clear();
  }
  refreshChainHeight();
}

void MainWindow::refreshChainHeight() {
  if (!heightLabel) {
    return;
  }
  int height = readChainHeight();
  if (height >= 0) {
    heightLabel->setText(QString("Height: %1").arg(height));
  } else {
    heightLabel->setText("Height: -");
  }
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
  setWindowTitle("DCON Core - Wallet");
  resize(1024, 720);

  QApplication::setStyle(QStyleFactory::create("Fusion"));

  QPalette palette;
  palette.setColor(QPalette::Window, QColor("#f6f6f6"));
  palette.setColor(QPalette::WindowText, QColor("#111827"));
  palette.setColor(QPalette::Base, QColor("#ffffff"));
  palette.setColor(QPalette::AlternateBase, QColor("#f3f4f6"));
  palette.setColor(QPalette::Text, QColor("#111827"));
  palette.setColor(QPalette::Button, QColor("#e5e7eb"));
  palette.setColor(QPalette::ButtonText, QColor("#111827"));
  palette.setColor(QPalette::Highlight, QColor("#f7931a"));
  palette.setColor(QPalette::HighlightedText, QColor("#111827"));
  QApplication::setPalette(palette);

  QFont appFont;
  appFont.setFamilies({"Segoe UI", "Noto Sans", "Helvetica Neue"});
  appFont.setPointSize(10);
  QApplication::setFont(appFont);

  auto* central = new QWidget();
  central->setObjectName("Central");
  auto* rootLayout = new QVBoxLayout(central);
  setCentralWidget(central);

  setStyleSheet(R"(
    QMainWindow { background: #f6f6f6; }
    QWidget#Central { background: #f6f6f6; }
    QGroupBox { background: #ffffff; border: 1px solid #c8c8c8; border-radius: 6px; margin-top: 16px; font-weight: 600; }
    QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
    QToolBar { background: #f2f2f2; border-bottom: 1px solid #c8c8c8; }
    QMenuBar { background: #f2f2f2; border-bottom: 1px solid #c8c8c8; }
    QMenu { background: #ffffff; border: 1px solid #c8c8c8; }
    QStatusBar { background: #f2f2f2; border-top: 1px solid #c8c8c8; }
    QLineEdit, QTextEdit, QListWidget, QTableWidget {
      background: #ffffff; border: 1px solid #c8c8c8; border-radius: 4px; padding: 4px;
    }
    QHeaderView::section { background: #f3f4f6; border: none; padding: 4px; }
    QPushButton { background: #f7931a; color: #111827; border: none; border-radius: 4px; padding: 6px 10px; font-weight: 600; }
    QPushButton:hover { background: #f9a13a; }
    QPushButton:disabled { background: #d1d5db; color: #6b7280; }
  )");

  // Menu bar
  auto* fileMenu = menuBar()->addMenu("File");
  QAction* quitAction = fileMenu->addAction("Quit");
  connect(quitAction, &QAction::triggered, this, &QWidget::close);

  auto* settingsMenu = menuBar()->addMenu("Settings");
  QAction* optionsAction = settingsMenu->addAction("Options");

  auto* toolsMenu = menuBar()->addMenu("Tools");
  QAction* networkAction = toolsMenu->addAction("Network");
  QAction* debugAction = toolsMenu->addAction("Debug log");

  auto* helpMenu = menuBar()->addMenu("Help");
  QAction* aboutAction = helpMenu->addAction("About");
  connect(aboutAction, &QAction::triggered, this, [this]() {
    QMessageBox::information(this, "About DCON Core",
                             "DCON Core Wallet\nA Bitcoin-like prototype wallet.");
  });

  // Toolbar
  auto* toolbar = new QToolBar("Navigation");
  toolbar->setMovable(false);
  toolbar->setToolButtonStyle(Qt::ToolButtonTextUnderIcon);
  toolbar->setIconSize(QSize(24, 24));
  addToolBar(toolbar);

  QAction* overviewAction =
      toolbar->addAction(style()->standardIcon(QStyle::SP_ComputerIcon), "Overview");
  QAction* sendAction =
      toolbar->addAction(style()->standardIcon(QStyle::SP_ArrowForward), "Send");
  QAction* receiveAction =
      toolbar->addAction(style()->standardIcon(QStyle::SP_ArrowBack), "Receive");
  QAction* txAction =
      toolbar->addAction(style()->standardIcon(QStyle::SP_FileDialogDetailedView),
                         "Transactions");

  // Shared widgets
  dconPathEdit = new QLineEdit();
  dataDirEdit = new QLineEdit();
  logView = new QTextEdit();
  logView->setReadOnly(true);

  addressList = new QListWidget();
  exportAddressEdit = new QLineEdit();

  chainAddressEdit = new QLineEdit();
  balanceAddressEdit = new QLineEdit();
  availableValueLabel = new QLabel("0");
  pendingValueLabel = new QLabel("0");
  totalValueLabel = new QLabel("0");
  QFont balanceFont = availableValueLabel->font();
  balanceFont.setBold(true);
  availableValueLabel->setFont(balanceFont);
  pendingValueLabel->setFont(balanceFont);
  totalValueLabel->setFont(balanceFont);
  availableValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
  pendingValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
  totalValueLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
  recentTable = new QTableWidget(0, 3);
  overviewSyncLabel = new QLabel("out of sync");
  recentSyncLabel = new QLabel("out of sync");
  overviewSyncLabel->setStyleSheet("color: #b91c1c; font-weight: 600;");
  recentSyncLabel->setStyleSheet("color: #b91c1c; font-weight: 600;");

  historyAddressEdit = new QLineEdit();
  historyTable = new QTableWidget(0, 6);
  historyTable->setHorizontalHeaderLabels(
      {"Height", "Time", "TxID", "Received", "Sent", "Net"});
  historyTable->horizontalHeader()->setStretchLastSection(true);
  historyTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
  historyTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  historyTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  historyTable->setAlternatingRowColors(true);

  sendFromEdit = new QLineEdit();
  sendToEdit = new QLineEdit();
  sendAmountEdit = new QLineEdit();
  sendFeeEdit = new QLineEdit();
  sendFeeMode = new QComboBox();
  sendPeersEdit = new QLineEdit();
  sendMineCheck = new QCheckBox("Mine immediately (local)");
  sendMineCheck->setChecked(true);

  nodePortEdit = new QLineEdit();
  nodePeersEdit = new QLineEdit();
  nodeMinerEdit = new QLineEdit();
  peersTable = new QTableWidget(0, 4);

  QString defaultBin = QDir(QCoreApplication::applicationDirPath())
                           .filePath("../../build/dcon");
  dconPathEdit->setText(QDir::cleanPath(defaultBin));
  dconPathEdit->setPlaceholderText("Path to dcon binary");
  dataDirEdit->setPlaceholderText("Optional data directory");

  exportAddressEdit->setPlaceholderText("Address to export");
  chainAddressEdit->setPlaceholderText("Genesis reward address");
  balanceAddressEdit->setPlaceholderText("Address");
  historyAddressEdit->setPlaceholderText("Address");
  sendFromEdit->setPlaceholderText("From address");
  sendToEdit->setPlaceholderText("To address");
  sendAmountEdit->setPlaceholderText("Amount");
  sendFeeEdit->setPlaceholderText("auto");
  sendPeersEdit->setPlaceholderText("127.0.0.1:3002,127.0.0.1:3003");
  nodePortEdit->setPlaceholderText("3001");
  nodePeersEdit->setPlaceholderText("127.0.0.1:3002,127.0.0.1:3003");
  nodeMinerEdit->setPlaceholderText("Miner address (optional)");

  sendFeeMode->addItems({"Auto", "Fee", "Fee rate"});

  // Pages
  pages = new QStackedWidget();
  rootLayout->addWidget(pages);

  overviewPage = new QWidget();
  sendPage = new QWidget();
  receivePage = new QWidget();
  transactionsPage = new QWidget();
  networkPage = new QWidget();
  settingsPage = new QWidget();
  debugPage = new QWidget();

  pages->addWidget(overviewPage);
  pages->addWidget(sendPage);
  pages->addWidget(receivePage);
  pages->addWidget(transactionsPage);
  pages->addWidget(networkPage);
  pages->addWidget(settingsPage);
  pages->addWidget(debugPage);
  pages->setCurrentWidget(overviewPage);

  // Overview page
  auto* overviewLayout = new QHBoxLayout(overviewPage);
  auto* leftPanel = new QWidget();
  auto* leftLayout = new QVBoxLayout(leftPanel);

  auto* balanceGroup = new QGroupBox("Balances");
  auto* balanceLayout = new QGridLayout(balanceGroup);
  auto* overviewRefreshBtn = new QPushButton("Refresh");
  auto* balanceHeader = new QHBoxLayout();
  balanceHeader->addStretch();
  balanceHeader->addWidget(overviewSyncLabel);
  balanceLayout->addLayout(balanceHeader, 0, 0, 1, 3);
  balanceLayout->addWidget(new QLabel("Address"), 1, 0);
  balanceLayout->addWidget(balanceAddressEdit, 1, 1);
  balanceLayout->addWidget(overviewRefreshBtn, 1, 2);
  balanceLayout->addWidget(new QLabel("Available"), 2, 0);
  balanceLayout->addWidget(availableValueLabel, 2, 1, 1, 2);
  balanceLayout->addWidget(new QLabel("Pending"), 3, 0);
  balanceLayout->addWidget(pendingValueLabel, 3, 1, 1, 2);
  balanceLayout->addWidget(new QLabel("Total"), 4, 0);
  balanceLayout->addWidget(totalValueLabel, 4, 1, 1, 2);

  auto* chainGroup = new QGroupBox("Blockchain");
  auto* chainLayout = new QGridLayout(chainGroup);
  auto* createChainBtn = new QPushButton("Create Genesis");
  chainLayout->addWidget(new QLabel("Genesis address"), 0, 0);
  chainLayout->addWidget(chainAddressEdit, 0, 1);
  chainLayout->addWidget(createChainBtn, 0, 2);

  leftLayout->addWidget(balanceGroup);
  leftLayout->addWidget(chainGroup);
  leftLayout->addStretch(1);

  auto* recentGroup = new QGroupBox("Recent transactions");
  auto* recentLayout = new QVBoxLayout(recentGroup);
  auto* recentHeader = new QHBoxLayout();
  recentHeader->addStretch();
  recentHeader->addWidget(recentSyncLabel);
  recentLayout->addLayout(recentHeader);
  recentTable->setHorizontalHeaderLabels({"Time", "TxID", "Net"});
  recentTable->horizontalHeader()->setStretchLastSection(true);
  recentTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
  recentTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
  recentTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  recentTable->setAlternatingRowColors(true);
  recentTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  recentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  recentLayout->addWidget(recentTable);

  overviewLayout->addWidget(leftPanel, 1);
  overviewLayout->addWidget(recentGroup, 2);

  // Send page
  auto* sendLayout = new QVBoxLayout(sendPage);
  auto* sendGroup = new QGroupBox("Send DCON");
  auto* sendForm = new QGridLayout(sendGroup);
  auto* estimateFeeBtn = new QPushButton("Estimate Fee");
  auto* sendBtn = new QPushButton("Send Transaction");

  sendForm->addWidget(new QLabel("From"), 0, 0);
  sendForm->addWidget(sendFromEdit, 0, 1, 1, 2);
  sendForm->addWidget(new QLabel("To"), 1, 0);
  sendForm->addWidget(sendToEdit, 1, 1, 1, 2);
  sendForm->addWidget(new QLabel("Amount"), 2, 0);
  sendForm->addWidget(sendAmountEdit, 2, 1, 1, 2);
  sendForm->addWidget(new QLabel("Fee mode"), 3, 0);
  sendForm->addWidget(sendFeeMode, 3, 1);
  sendForm->addWidget(sendFeeEdit, 3, 2);
  sendForm->addWidget(estimateFeeBtn, 3, 3);
  sendForm->addWidget(new QLabel("Peers (optional)"), 4, 0);
  sendForm->addWidget(sendPeersEdit, 4, 1, 1, 2);
  sendForm->addWidget(sendMineCheck, 5, 1, 1, 2);

  auto* sendBtnRow = new QHBoxLayout();
  sendBtnRow->addStretch();
  sendBtnRow->addWidget(sendBtn);
  sendForm->addLayout(sendBtnRow, 6, 0, 1, 4);

  sendLayout->addWidget(sendGroup);
  sendLayout->addStretch(1);

  // Receive page
  auto* receiveLayout = new QVBoxLayout(receivePage);
  auto* walletGroup = new QGroupBox("Receiving addresses");
  auto* walletLayout = new QVBoxLayout(walletGroup);
  auto* walletButtonRow = new QHBoxLayout();
  auto* createWalletBtn = new QPushButton("New Address");
  auto* listWalletsBtn = new QPushButton("Refresh Addresses");
  auto* copyAddressBtn = new QPushButton("Copy");
  walletButtonRow->addWidget(createWalletBtn);
  walletButtonRow->addWidget(listWalletsBtn);
  walletButtonRow->addWidget(copyAddressBtn);
  walletButtonRow->addStretch();
  walletLayout->addLayout(walletButtonRow);
  walletLayout->addWidget(addressList);

  auto* exportRow = new QHBoxLayout();
  auto* exportWalletBtn = new QPushButton("Export Wallet");
  exportRow->addWidget(exportAddressEdit);
  exportRow->addWidget(exportWalletBtn);
  walletLayout->addLayout(exportRow);

  auto* importWalletBtn = new QPushButton("Import Wallet");
  walletLayout->addWidget(importWalletBtn);

  receiveLayout->addWidget(walletGroup);
  receiveLayout->addStretch(1);

  // Transactions page
  auto* historyLayout = new QVBoxLayout(transactionsPage);
  auto* historyGroup = new QGroupBox("Transactions");
  auto* historyGroupLayout = new QVBoxLayout(historyGroup);
  auto* historyRow = new QHBoxLayout();
  auto* historyBtn = new QPushButton("Load History");
  historyRow->addWidget(historyAddressEdit);
  historyRow->addWidget(historyBtn);
  historyGroupLayout->addLayout(historyRow);
  historyGroupLayout->addWidget(historyTable);
  historyLayout->addWidget(historyGroup);

  // Network page
  auto* networkLayout = new QVBoxLayout(networkPage);
  auto* nodeGroup = new QGroupBox("Node");
  auto* nodeLayout = new QGridLayout(nodeGroup);
  startNodeBtn = new QPushButton("Start Node");
  stopNodeBtn = new QPushButton("Stop Node");

  nodeLayout->addWidget(new QLabel("Port"), 0, 0);
  nodeLayout->addWidget(nodePortEdit, 0, 1, 1, 2);
  nodeLayout->addWidget(new QLabel("Peers"), 1, 0);
  nodeLayout->addWidget(nodePeersEdit, 1, 1, 1, 2);
  nodeLayout->addWidget(new QLabel("Miner"), 2, 0);
  nodeLayout->addWidget(nodeMinerEdit, 2, 1, 1, 2);
  nodeLayout->addWidget(startNodeBtn, 3, 1);
  nodeLayout->addWidget(stopNodeBtn, 3, 2);

  networkLayout->addWidget(nodeGroup);
  auto* peersGroup = new QGroupBox("Peers");
  auto* peersLayout = new QVBoxLayout(peersGroup);
  peersTable->setHorizontalHeaderLabels({"Address", "Last Seen", "Last Success", "Attempts"});
  peersTable->horizontalHeader()->setStretchLastSection(true);
  peersTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
  peersTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
  peersTable->horizontalHeader()->setSectionResizeMode(2, QHeaderView::ResizeToContents);
  peersTable->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
  peersTable->setSelectionBehavior(QAbstractItemView::SelectRows);
  peersTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
  peersTable->setAlternatingRowColors(true);
  peersLayout->addWidget(peersTable);
  networkLayout->addWidget(peersGroup);
  networkLayout->addStretch(1);

  // Settings page
  auto* settingsLayout = new QVBoxLayout(settingsPage);
  auto* pathGroup = new QGroupBox("Binary & Data");
  auto* pathLayout = new QGridLayout(pathGroup);
  auto* browseBin = new QPushButton("Browse...");
  auto* browseData = new QPushButton("Browse...");

  pathLayout->addWidget(new QLabel("DCON binary"), 0, 0);
  pathLayout->addWidget(dconPathEdit, 0, 1);
  pathLayout->addWidget(browseBin, 0, 2);
  pathLayout->addWidget(new QLabel("Data dir"), 1, 0);
  pathLayout->addWidget(dataDirEdit, 1, 1);
  pathLayout->addWidget(browseData, 1, 2);
  settingsLayout->addWidget(pathGroup);
  settingsLayout->addStretch(1);

  // Debug page
  auto* debugLayout = new QVBoxLayout(debugPage);
  auto* logGroup = new QGroupBox("Debug Log");
  auto* logLayout = new QVBoxLayout(logGroup);
  logLayout->addWidget(logView);
  debugLayout->addWidget(logGroup);

  // Status bar
  nodeStatusLabel = new QLabel("Node: Stopped");
  syncStatusLabel = new QLabel("Disconnected");
  connectionsLabel = new QLabel("Connections: 0");
  heightLabel = new QLabel("Height: -");
  syncProgress = new QProgressBar();
  syncProgress->setRange(0, 100);
  syncProgress->setValue(0);
  syncProgress->setFixedWidth(160);
  statusBar()->addWidget(syncStatusLabel, 1);
  statusBar()->addPermanentWidget(nodeStatusLabel);
  statusBar()->addPermanentWidget(syncProgress);
  statusBar()->addPermanentWidget(heightLabel);
  statusBar()->addPermanentWidget(connectionsLabel);

  peerStatusTimer = new QTimer(this);
  peerStatusTimer->setInterval(3000);
  connect(peerStatusTimer, &QTimer::timeout, this, [this]() { refreshPeerStatus(); });

  auto updateFeeMode = [this]() {
    QString mode = sendFeeMode->currentText();
    if (mode == "Auto") {
      sendFeeEdit->setText("auto");
      sendFeeEdit->setEnabled(false);
    } else {
      if (sendFeeEdit->text().trimmed() == "auto") {
        sendFeeEdit->clear();
      }
      sendFeeEdit->setEnabled(true);
      sendFeeEdit->setPlaceholderText(mode == "Fee" ? "0.0001" : "5");
    }
  };
  updateFeeMode();
  connect(sendFeeMode, QOverload<int>::of(&QComboBox::currentIndexChanged), this,
          [updateFeeMode](int) { updateFeeMode(); });

  updateNodeStatus(false);
  refreshPeerStatus();

  // Navigation actions
  connect(overviewAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(overviewPage); });
  connect(sendAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(sendPage); });
  connect(receiveAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(receivePage); });
  connect(txAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(transactionsPage); });
  connect(networkAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(networkPage); });
  connect(debugAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(debugPage); });
  connect(optionsAction, &QAction::triggered, this,
          [this]() { pages->setCurrentWidget(settingsPage); });

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

  connect(copyAddressBtn, &QPushButton::clicked, this, [this]() {
    QListWidgetItem* item = addressList->currentItem();
    if (!item) {
      QMessageBox::information(this, "No selection",
                               "Select an address first.");
      return;
    }
    QApplication::clipboard()->setText(item->text());
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

  connect(overviewRefreshBtn, &QPushButton::clicked, this, [this]() {
    QString address = balanceAddressEdit->text().trimmed();
    if (address.isEmpty()) {
      QMessageBox::warning(this, "Missing address",
                           "Please enter an address.");
      return;
    }
    QStringList balanceArgs = {"getbalance", "-address", address};
    if (!dataDir().isEmpty()) {
      balanceArgs << "-datadir" << dataDir();
    }
    runCommand(balanceArgs, [this](const QString& output) { handleBalanceOutput(output); });

    QStringList historyArgs = {"txhistory", "-address", address};
    if (!dataDir().isEmpty()) {
      historyArgs << "-datadir" << dataDir();
    }
    runCommand(historyArgs, [this](const QString& output) { handleHistoryOutput(output); });
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

  connect(estimateFeeBtn, &QPushButton::clicked, this, [this]() {
    QStringList args = {"estimatefee"};
    if (!dataDir().isEmpty()) {
      args << "-datadir" << dataDir();
    }
    runCommand(args, [this](const QString& output) {
      QStringList lines = output.split('\n', Qt::SkipEmptyParts);
      for (const QString& line : lines) {
        if (line.startsWith("Estimated fee rate:")) {
          QString value = line.section(':', 1).trimmed();
          value = value.section(' ', 0, 0).trimmed();
          if (!value.isEmpty()) {
            sendFeeMode->setCurrentText("Fee rate");
            sendFeeEdit->setText(value);
          }
        }
      }
    });
  });

  connect(sendBtn, &QPushButton::clicked, this, [this]() {
    QString from = sendFromEdit->text().trimmed();
    QString to = sendToEdit->text().trimmed();
    QString amount = sendAmountEdit->text().trimmed();
    QString peers = sendPeersEdit->text().trimmed();
    QString feeMode = sendFeeMode->currentText();
    QString feeValue = sendFeeEdit->text().trimmed();

    if (from.isEmpty() || to.isEmpty() || amount.isEmpty()) {
      QMessageBox::warning(this, "Missing fields",
                           "From, To, and Amount are required.");
      return;
    }

    QStringList args = {"send", "-from", from, "-to", to, "-amount", amount,
                        "-mine", sendMineCheck->isChecked() ? "true" : "false"};

    if (feeMode == "Auto") {
      args << "-fee" << "auto";
    } else if (feeMode == "Fee") {
      if (feeValue.isEmpty()) {
        QMessageBox::warning(this, "Missing fee",
                             "Enter a fee amount.");
        return;
      }
      args << "-fee" << feeValue;
    } else {
      if (feeValue.isEmpty()) {
        QMessageBox::warning(this, "Missing fee rate",
                             "Enter a fee rate.");
        return;
      }
      args << "-feerate" << feeValue;
    }

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
    } else if (sendToEdit->text().isEmpty()) {
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
        if (availableValueLabel) {
          availableValueLabel->setText(value);
        }
        if (pendingValueLabel) {
          pendingValueLabel->setText("0");
        }
        if (totalValueLabel) {
          totalValueLabel->setText(value);
        }
        return;
      }
    }
  }
}

void MainWindow::handleHistoryOutput(const QString& output) {
  historyTable->setRowCount(0);
  if (recentTable) {
    recentTable->setRowCount(0);
  }
  QStringList lines = output.split('\n', Qt::SkipEmptyParts);
  int recentCount = 0;
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
    auto* netItem = new QTableWidgetItem(net);
    netItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    if (net.startsWith('-')) {
      netItem->setForeground(QColor("#b91c1c"));
    } else if (net != "0" && net != "0.0" && net != "0.00") {
      netItem->setForeground(QColor("#15803d"));
    } else {
      netItem->setForeground(QColor("#6b7280"));
    }
    historyTable->setItem(row, 5, netItem);

    if (recentTable && recentCount < 5) {
      int rrow = recentTable->rowCount();
      recentTable->insertRow(rrow);
      recentTable->setItem(rrow, 0, new QTableWidgetItem(timeText));
      recentTable->setItem(rrow, 1, new QTableWidgetItem(txid));
      auto* recentNetItem = new QTableWidgetItem(net);
      recentNetItem->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
      if (net.startsWith('-')) {
        recentNetItem->setForeground(QColor("#b91c1c"));
      } else if (net != "0" && net != "0.0" && net != "0.00") {
        recentNetItem->setForeground(QColor("#15803d"));
      } else {
        recentNetItem->setForeground(QColor("#6b7280"));
      }
      recentTable->setItem(rrow, 2, recentNetItem);
      recentCount++;
    }
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
            updateNodeStatus(false);
          });

  nodeProcess->start();
  appendLog("Node process started.");
  updateNodeStatus(true);
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
  updateNodeStatus(false);
}

void MainWindow::updateNodeStatus(bool running) {
  if (!nodeStatusLabel) {
    return;
  }
  if (running) {
    QString port = nodePortEdit ? nodePortEdit->text().trimmed() : QString();
    QString label = port.isEmpty() ? "Node: Running" : QString("Node: Running on %1").arg(port);
    nodeStatusLabel->setText(label);
    nodeStatusLabel->setStyleSheet("color: #0f6d0f; font-weight: 600;");
    if (syncStatusLabel) {
      syncStatusLabel->setText("Synchronizing with network...");
      syncStatusLabel->setStyleSheet("color: #b45309; font-weight: 600;");
    }
    if (overviewSyncLabel) {
      overviewSyncLabel->setText("out of sync");
    }
    if (recentSyncLabel) {
      recentSyncLabel->setText("out of sync");
    }
    if (syncProgress) {
      syncProgress->setRange(0, 0);
      syncProgress->setFormat("Syncing");
    }
    if (peerStatusTimer && !peerStatusTimer->isActive()) {
      peerStatusTimer->start();
    }
    refreshPeerStatus();
  } else {
    nodeStatusLabel->setText("Node: Stopped");
    nodeStatusLabel->setStyleSheet("color: #6b7280; font-weight: 600;");
    if (syncStatusLabel) {
      syncStatusLabel->setText("Disconnected");
      syncStatusLabel->setStyleSheet("color: #6b7280; font-weight: 600;");
    }
    if (overviewSyncLabel) {
      overviewSyncLabel->setText("out of sync");
    }
    if (recentSyncLabel) {
      recentSyncLabel->setText("out of sync");
    }
    if (syncProgress) {
      syncProgress->setRange(0, 100);
      syncProgress->setValue(0);
      syncProgress->setFormat("Offline");
    }
    if (peerStatusTimer && peerStatusTimer->isActive()) {
      peerStatusTimer->stop();
    }
    if (connectionsLabel) {
      connectionsLabel->setText("Connections: 0");
      connectionsLabel->setToolTip(QString());
    }
  }
  if (startNodeBtn) {
    startNodeBtn->setEnabled(!running);
  }
  if (stopNodeBtn) {
    stopNodeBtn->setEnabled(running);
  }
}
