#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <minwindef.h>
#include <bcrypt.h>

QT_BEGIN_NAMESPACE
namespace Ui {
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void browseFilesButton_clicked();
    void encryptSelectedFileButton_clicked();
    void decryptSelectedFileButton_clicked();
    bool encryptDecryptFile(bool, const QString &, const QString &);

private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
