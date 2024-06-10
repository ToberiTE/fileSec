#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileDialog>
#include <QInputDialog>
#include <windows.h>
#include <bcrypt.h>

#define STATUS_SUCCESS 0x00000000L
#define AES_BLOCK_SIZE 16
#define KEY_SIZE 32
#define SALT_SIZE 16
#define PBKDF2_ITERATIONS 10000

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

    QString passphrase = ui->passphraseEdit->text();
    if (passphrase.isEmpty()) {
        ui->statusLabel->setText("Passphrase is required.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        return;
    }

    if(encryptDecryptFile(true, fileName, passphrase))
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

    QString passphrase = ui->passphraseEdit->text();
    if (passphrase.isEmpty()) {
        ui->statusLabel->setText("Passphrase is required.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        return;
    }

    if (encryptDecryptFile(false, fileName, passphrase))
    {
        ui->statusLabel->setText("File decrypted successfully!");
        ui->statusLabel->setStyleSheet("QLabel { color : lightgreen; }");
    }
}

bool MainWindow::encryptDecryptFile(bool encrypt, const QString &filePath, const QString &passphrase)
{
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    UCHAR salt[SALT_SIZE] = {0};
    UCHAR key[KEY_SIZE] = {0};
    UCHAR iv[AES_BLOCK_SIZE] = {0};
    NTSTATUS status;
    UCHAR derivedKey[KEY_SIZE];

    // Open RNG algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (status != STATUS_SUCCESS) {
        return 0;
    }

    // Generate a random salt for encryption
    if (encrypt) {
        status = BCryptGenRandom(hAlg, salt, SALT_SIZE, 0);
        if (status != STATUS_SUCCESS) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return 0;
        }
    }
    else {
        // Read the salt from the file if decrypting
        QFile file(filePath);
        if (!file.open(QIODevice::ReadOnly)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }
        file.read(reinterpret_cast<char*>(salt), SALT_SIZE);
        file.read(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
        file.close();
    }

    // Open PBKDF2 algorithm provider
    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA512_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (status != STATUS_SUCCESS) {
        return 0;
    }

    // Derive the key using PBKDF2.
    status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)passphrase.utf16(), passphrase.size() * 2, salt, SALT_SIZE, PBKDF2_ITERATIONS, derivedKey, KEY_SIZE, 0);
    if (status != STATUS_SUCCESS) {
        ui->statusLabel->setText("Invalid passphrase!");
        ui->statusLabel->setStyleSheet("QLabel { color : red; }");
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    memcpy(iv, salt, AES_BLOCK_SIZE);

    // Import the derived key into a key handle for use with encryption/decryption
    BCRYPT_KEY_DATA_BLOB_HEADER keyBlobHeader;
    keyBlobHeader.dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
    keyBlobHeader.dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
    keyBlobHeader.cbKeyData = KEY_SIZE;

    QByteArray keyBlob;
    keyBlob.append(reinterpret_cast<char*>(&keyBlobHeader), sizeof(keyBlobHeader));
    keyBlob.append(reinterpret_cast<char*>(derivedKey), KEY_SIZE);

    status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if(status != STATUS_SUCCESS)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    status = BCryptImportKey(hAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL, 0,
                             reinterpret_cast<PUCHAR>(keyBlob.data()), keyBlob.size(), 0);
    if (status != STATUS_SUCCESS) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // File error handling
    QFile file(filePath);
    if (!file.open(QIODevice::ReadWrite)) {
        ui->statusLabel->setText("Failed to open file.");
        ui->statusLabel->setStyleSheet("QLabel { color : red; }");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    QByteArray fileData = file.readAll();
    file.close();

    // Info message already encrypted
    if (encrypt && filePath.endsWith(".enc")) {
        ui->statusLabel->setText("File is already encrypted.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Info message not encrypted
    if (!encrypt && !filePath.endsWith(".enc")) {
        ui->statusLabel->setText("File is not encrypted.");
        ui->statusLabel->setStyleSheet("QLabel { color : yellow; }");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Add padding
    if (encrypt) {
        int paddingLength = AES_BLOCK_SIZE - (fileData.size() % AES_BLOCK_SIZE);
        fileData.append(paddingLength, static_cast<char>(paddingLength));
    }

    ULONG dataLen = fileData.size() - (encrypt ? 0 : SALT_SIZE + AES_BLOCK_SIZE);
    ULONG bufferLen = dataLen + (encrypt ? AES_BLOCK_SIZE - (dataLen % AES_BLOCK_SIZE) : 0);
    QByteArray buffer(bufferLen, 0);

    status = encrypt ?
                 BCryptEncrypt(hKey, (PUCHAR)fileData.data() + (encrypt ? 0 : SALT_SIZE + AES_BLOCK_SIZE), dataLen, NULL, iv, AES_BLOCK_SIZE, (PUCHAR)buffer.data(), buffer.size(), &dataLen, 0) :
                 BCryptDecrypt(hKey, (PUCHAR)fileData.data() + SALT_SIZE + AES_BLOCK_SIZE, dataLen, NULL, iv, AES_BLOCK_SIZE, (PUCHAR)buffer.data(), buffer.size(), &dataLen, 0);

    if (status != STATUS_SUCCESS) {
        ui->statusLabel->setText(encrypt ? "Encryption failed!" : "Decryption failed!");
        ui->statusLabel->setStyleSheet("QLabel { color : red; }");
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    //Remove padding
    if (!encrypt) {
        int paddingLength = buffer[dataLen - 1];
        buffer.remove(dataLen - paddingLength, paddingLength);
        dataLen -= paddingLength;

    }

    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    // Write the salt and IV to the beginning of the file during encryption
    if (encrypt) {
        file.write(reinterpret_cast<char*>(salt), SALT_SIZE);
        file.write(reinterpret_cast<char*>(iv), AES_BLOCK_SIZE);
    }

    if (file.write(buffer.data(), dataLen) != dataLen) {

        file.close();
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    file.close();

    // Rename file with new file extension
    QString newFilePath = filePath;

    if (encrypt) {
        newFilePath += ".enc";
    } else {
        newFilePath.chop(4);
    }

    if (!QFile::rename(filePath, newFilePath)) {
        BCryptDestroyKey(hKey);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return 0;
    }

    ui->selectedFileLabel->setText(newFilePath);
    BCryptDestroyKey(hKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return 1;
}
