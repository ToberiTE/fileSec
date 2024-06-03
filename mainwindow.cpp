#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QLabel>
#include <windows.h>
#include <bcrypt.h>

#define STATUS_SUCCESS 0x00000000L
#define AES_BLOCK_SIZE 16

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    connect(ui->browseFilesButton, &QPushButton::clicked, this, &MainWindow::browseFilesButton_clicked);
    connect(ui->encryptSelectedFileButton, &QPushButton::clicked, this, &MainWindow::encryptSelectedFileButton_clicked);
    connect(ui->decryptSelectedFileButton, &QPushButton::clicked, this, &MainWindow::decryptSelectedFileButton_clicked);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::browseFilesButton_clicked()
{
    QString fileName = QFileDialog::getOpenFileName(this, tr("Open files"), "", tr("All Files (*)"));
    if (!fileName.isEmpty())
    {
        ui->selectedFileLabel->setText(fileName);
    }
}

void MainWindow::encryptSelectedFileButton_clicked()
{
    QString fileName = ui->selectedFileLabel->text();
    if(fileName.isEmpty())
    {
        ui->statusLabel->setText("No file selected.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        return;
    }

    if(encryptDecryptFile(true, fileName))
    {
        ui->statusLabel->setText("File encrypted successfully!");
        ui->statusLabel->setStyleSheet("QLabel { color : lightgreen; }");
    }
}

void MainWindow::decryptSelectedFileButton_clicked()
{
    QString fileName = ui->selectedFileLabel->text();
    if (fileName.isEmpty())
    {
        ui->statusLabel->setText("No file selected.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        return;
    }

    if (encryptDecryptFile(false, fileName))
    {
        ui->statusLabel->setText("File decrypted successfully!");
        ui->statusLabel->setStyleSheet("QLabel { color : lightgreen; }");
    }
}

bool MainWindow::encryptDecryptFile(bool encrypt, const QString &filePath)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) != STATUS_SUCCESS) {
        return false;
    }

    wchar_t chainingMode[] = BCRYPT_CHAIN_MODE_CBC;
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PUCHAR)chainingMode, sizeof(chainingMode), 0);

    BCRYPT_KEY_HANDLE hKey = NULL;
    UCHAR key[16] = {0x01}; // key
    UCHAR iv[16] = {0x01};  // IV
    if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, key, sizeof(key), 0) != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return false;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadWrite)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    QByteArray fileData = file.readAll();
    file.close();

    if (encrypt && filePath.endsWith(".enc")) {
        ui->statusLabel->setText("File is already encrypted.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    if (!encrypt && !filePath.endsWith(".enc")) {
        ui->statusLabel->setText("File is not encrypted.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    if (encrypt) {
        int paddingLength = AES_BLOCK_SIZE - (fileData.size() % AES_BLOCK_SIZE);
        fileData.append(paddingLength, static_cast<char>(paddingLength));
    }

    ULONG dataLen = fileData.size();
    ULONG bufferLen = dataLen + (encrypt ? AES_BLOCK_SIZE - (dataLen % AES_BLOCK_SIZE) : 0);
    QByteArray buffer(bufferLen, 0);
    ULONG resultLen = 0;

    NTSTATUS status = encrypt ?
                          BCryptEncrypt(hKey, (PUCHAR)fileData.data(), dataLen, NULL, iv, sizeof(iv), (PUCHAR)buffer.data(), buffer.size(), &resultLen, 0) :
                          BCryptDecrypt(hKey, (PUCHAR)fileData.data(), dataLen, NULL, iv, sizeof(iv), (PUCHAR)buffer.data(), buffer.size(), &resultLen, 0);

    if (status != STATUS_SUCCESS) {
        ui->statusLabel->setText(encrypt ? "Encryption failed!" : "Decryption failed!");
        ui->statusLabel->setStyleSheet("QLabel { color : red; }");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    if (!encrypt) {
        int paddingLength = buffer[resultLen - 1];
        resultLen -= paddingLength;
    }

    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    if (file.write(buffer.data(), resultLen) != resultLen) {
        file.close();
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    file.close();

    QString newFilePath = filePath;

    if (encrypt) {
        newFilePath += ".enc";
    } else {
        newFilePath.chop(4);
    }

    if (!QFile::rename(filePath, newFilePath)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        BCryptDestroyKey(hKey);
        return false;
    }

    ui->selectedFileLabel->setText(newFilePath);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    BCryptDestroyKey(hKey);
    return true;
}
