// HOW THIS PROGRAM WORKS
// Think of this app as a school notebook with a lock and several screens.
// 1. main() starts diagnostics; runApplication() starts Qt and checks the saved records.
// 2. LoginDialog checks a password and decides whether the person is Head,
//    Professor, or Student. Accounts needing setup must finish it before entering.
// 3. MainWindow builds the dashboard for that role. Button clicks run small
//    actions that open forms, display grades, manage records, or show personal tasks.
// 4. Student holds marks and calculates averages. FileIO checks and converts
//    records. Storage reads files and safely replaces them when a save succeeds.
// 5. Logout closes the dashboard and returns to login; closing the app ends it.
// Records in memory are the app's working copy. Files keep records after it closes.
// Many edit forms use a copy, so closing without accepting leaves the live data alone.
// 
// WORDS USED IN THE COMMENTS
// A function is a named set of steps, like a recipe. Inputs are what it receives;
// a return value is the answer it gives back. true means yes; false means no.
// if chooses steps when a condition is true. for and while repeat steps.
// return ends the function and sends its answer to the caller. An early return
// often stops an action when the input is wrong or the person cancels.
// int holds whole numbers, double holds decimal numbers, and string holds text.
// A byte is a small piece of data; a pointer tells code where an object is.
// nullptr means a pointer has no object. Empty strings and lists contain nothing.
// A class describes an object; its constructor sets up a new object. A struct also
// groups related information, such as a course's code, units, year, and semester.
// A vector is a list. A map looks up a value by a key, like finding a name in an index.
// A pair holds two values; a tuple here holds three. const prevents changes through
// that value or reference. An & reference shares an existing object instead of copying it.
// Qt is the library that makes windows, buttons, tables, and input boxes.
// A widget is a screen control. A layout arranges controls. A dialog is a small
// window that asks for input or shows information. accept() reports success;
// reject() reports cancellation. Accepting a form does not itself write a file.
// connect() links an event, such as a click, to an action. A lambda is a little
// function written where it is used. [this] lets it use the current object's data.
// QSignalBlocker pauses change notifications while code fills a control, so those
// updates are not mistaken for user edits. Qt deletes child widgets with their
// parent, and tables take ownership of the cell items placed inside them.
// JSON is labeled text for saving records; CSV is text arranged for a spreadsheet.
// A hash is a fingerprint, not encryption. Password checks compare fingerprints
// calculated with the same saved random salt and work count.
// GWA means General Weighted Average. Courses with more units count more.
// In this app's grade scale, smaller positive numbers are better; zero means missing.
// The notes describe this file. Tablet layout helper implementations live in a
// separate library, so their internal steps cannot be explained from this source.
// 
// These Qt headers bring in tools for screens, controls, layouts, and user events.
#include <QApplication>
#include <QMainWindow>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGridLayout>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QHeaderView>
#include <QMessageBox>
#include <QLabel>
#include <QDialog>
#include <QIntValidator>
#include <QTextEdit>
#include <QListWidget>
#include <QStackedWidget>
#include <QFrame>
#include <QComboBox>
#include <QDateEdit>
#include <QScreen>
#include <QScrollArea>
#include <QStandardPaths>
#include <QSignalBlocker>
#include <QStyledItemDelegate>
#include <QKeyEvent>
#include <QFocusEvent>
#include <QToolTip>
#include <QDoubleValidator>
#include <QLocale>
#ifdef V3_TABLET_UI
// Tablet support is included only when the build defines V3_TABLET_UI.
// prepareMain() and Dialogs::eventFilter() are provided by libTabletLayout.so,
// preserved from the original APK. This file declares their interfaces.
namespace Tablet {
    // Give the external layout helper the main window to adapt for tablet use.
    // Its detailed resizing and arrangement rules are in the separate library.
    void prepareMain(QMainWindow* window);
    // Watch application events so the external tablet library can adapt dialogs.
    class Dialogs : public QObject {
    public:
        // Create the event watcher without a parent; main() keeps it alive while the app runs.
        Dialogs() : QObject(nullptr) {}
        // Use Qt's normal cleanup when this event watcher goes out of scope.
        ~Dialogs() override = default;
    protected:
        // Qt sends watched objects and their events here. The external library decides
        // whether to handle an event or let normal processing continue.
        bool eventFilter(QObject* object, QEvent* event) override;
    };
}
#endif
// These Qt headers supply file access, JSON, locks, hashing, time, and background work.
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QSaveFile>
#include <QLockFile>
#include <QCryptographicHash>
#include <QMessageAuthenticationCode>
#include <QRandomGenerator>
#include <QDateTime>
#include <QTimer>
#include <QThread>
#include <QProgressBar>
#include <QCloseEvent>
#include <QScopedValueRollback>
// These C++ headers supply lists, lookup tables, sorting, text formatting, and math.
#include <set>
#include <limits>
#include <stdexcept>
#include <vector>
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <map>
#include <tuple>
#include <cmath>
#include <functional>

// Windows keeps a durable crash log beside the EXE. It records program steps
// and crash addresses, never passwords, recovery answers, or their hashes.
#ifdef Q_OS_WIN
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <csignal>
#include <exception>
#endif
namespace StartupTrace {
#ifdef Q_OS_WIN
    HANDLE logFile = INVALID_HANDLE_VALUE;
    // Flush each fixed message so a crash does not erase the clue.
    void note(const char* message) {
        if (logFile == INVALID_HANDLE_VALUE) return;
        DWORD written;
        WriteFile(logFile, message, DWORD(lstrlenA(message)), &written, nullptr);
        WriteFile(logFile, "\r\n", 2, &written, nullptr);
        FlushFileBuffers(logFile);
    }
    // Observe serious Windows exceptions without hiding or handling the failure.
    // A module name and offset identify the failing instruction for later diagnosis.
    LONG CALLBACK exception(EXCEPTION_POINTERS* information) {
        const DWORD code = information->ExceptionRecord->ExceptionCode;
        if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_ILLEGAL_INSTRUCTION
            || code == EXCEPTION_STACK_OVERFLOW || code == 0xC0000374 || code == 0xC0000409) {
            char line[512]{}; wsprintfA(line, "Windows exception: 0x%08lx", code); note(line);
            MEMORY_BASIC_INFORMATION memory{}; char module[MAX_PATH]{};
            const void* location = information->ExceptionRecord->ExceptionAddress;
            if (VirtualQuery(location, &memory, sizeof(memory))) {
                GetModuleFileNameA(HMODULE(memory.AllocationBase), module, MAX_PATH);
                const char* name = module;
                for (const char* p = module; *p; ++p) if (*p == '\\' || *p == '/') name = p + 1;
                const auto offset = reinterpret_cast<ULONG_PTR>(location) - reinterpret_cast<ULONG_PTR>(memory.AllocationBase);
                wsprintfA(line, "Crash location: %s + 0x%08lx%08lx", name, DWORD(offset >> 32), DWORD(offset)); note(line);
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // Leave a clue when the C or C++ runtime ends the program unexpectedly.
    void aborted(int) { note("C runtime aborted the application."); }
    void terminated() { note("An uncaught C++ exception terminated the application."); std::abort(); }
    // Open the log before Qt starts. A read-only EXE folder uses Windows TEMP instead.
    void start() {
        wchar_t path[32768]{};
        DWORD length = GetModuleFileNameW(nullptr, path, 32768);
        if (length && length < 32768) {
            wchar_t* filename = path;
            for (wchar_t* p = path; *p; ++p) if (*p == L'\\' || *p == L'/') filename = p + 1;
            if (filename - path + 32 < 32768) {
                lstrcpyW(filename, L"startup-diagnostic.log");
                logFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            }
        }
        if (logFile == INVALID_HANDLE_VALUE && GetTempPathW(32700, path)) {
            lstrcatW(path, L"StudentManagementV4-startup.log");
            logFile = CreateFileW(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        }
        note("--- Starting Windows security-timer build ---");
        AddVectoredExceptionHandler(1, exception);
        std::signal(SIGABRT, aborted); std::set_terminate(terminated);
    }
#else
    // Other platforms do not need a Windows crash file.
    void note(const char*) {}
    void start() {}
#endif
}

// Allow standard C++ names such as vector and string without the std:: prefix.
using namespace std;

// Name the three account roles so permission checks read like ordinary words.
enum UserRole { ROLE_HEAD, ROLE_PROFESSOR, ROLE_STUDENT };
// Student IDs are positive whole numbers with at most nine digits.
constexpr int MAX_STUDENT_ID = 999999999;
// Keep one version number for the application title, metadata, and team screen.
constexpr const char* APP_VERSION = "4.0.2";

// Security shares password rules across login, account setup, and password resets.
// Passwords are stored as salted hashes; recovery answers are normalized first.
namespace Security {
#ifndef SECURITY_ITERATIONS
// Use 600,000 hashing rounds unless the build supplied SECURITY_ITERATIONS.
// More rounds add work to each guess; they also make a normal login take longer.
#define SECURITY_ITERATIONS 600000
#endif
    // Check a proposed password's length: accept 8 to 256 Unicode code points.
    // For example, a plain seven-letter password fails. This checks length only;
    // it does not check the password against a list of common words.
    bool validPassword(const QString& text) {
        const auto length = text.toUcs4().size();
        return length >= 8 && length <= 256;
    }

    // Turn password bytes, salt bytes, and a round count into a 32-byte fingerprint.
    // Like mixing ingredients many times, the same inputs always give the same result.
    // This is the single-block PBKDF2-HMAC-SHA256 calculation: make the first HMAC
    // from the salt plus block number 1, then repeatedly hash the previous result.
    // XOR is a bit-by-bit mixing step that combines each round into the final bytes. The caller
    // supplies the rounds.
    // A salt is extra random data that makes equal passwords produce different hashes.
    QByteArray derive(const QByteArray& password, const QByteArray& salt, int rounds) {
        QMessageAuthenticationCode mac(QCryptographicHash::Sha256, password);
        mac.addData(salt + QByteArray("\0\0\0\1", 4));
        QByteArray u = mac.result(), result = u;
        char* combined = result.data();
        // Reuse the same HMAC helper each round; XOR each new block into the result.
        for (int i = 1; i < rounds; ++i) {
            mac.reset(); mac.addData(u); u = mac.result();
            const char* block = u.constData();
            for (int j = 0; j < result.size(); ++j) combined[j] ^= block[j];
        }
        return result;
    }

    // A waiting window keeps the person informed while a slow security check runs.
    class BusyDialog : public QDialog {
    public:
        // Build a small modal waiting dialog with a moving progress bar.
        // Modal means other app windows cannot be used until this dialog finishes.
        // The bar keeps moving while the timer works through the hashing rounds.
        BusyDialog() : QDialog(QApplication::activeWindow()) {
            setWindowTitle("Account Security"); setWindowModality(Qt::ApplicationModal);
            setWindowFlags(windowFlags() & ~Qt::WindowCloseButtonHint);
            auto layout = new QVBoxLayout(this);
            layout->addWidget(new QLabel("Please wait while account security is checked.", this));
            auto progress = new QProgressBar(this); progress->setRange(0, 0); layout->addWidget(progress);
        }
        // Ignore Cancel or Escape requests; all hashing rounds must finish first.
        void reject() override {}
        // Ignore window-close events; the completed calculation closes this dialog.
        void closeEvent(QCloseEvent* event) override { event->ignore(); }
    };
    // Return the same fingerprint as derive(), choosing how to do the work.
    // Short jobs and calls outside the screen thread can finish directly.
    // For longer screen-thread jobs, a timer mixes at most 1,000 rounds per tick.
    // Qt gets time between batches to redraw the waiting window and handle events.
    // Everything stays on one thread, avoiding the worker-to-dialog shutdown handoff.
    // All requested hashing rounds still run before the fingerprint is returned.
    QByteArray calculate(const QByteArray& password, const QByteArray& salt, int rounds) {
        auto application = QCoreApplication::instance();
        if (!application || rounds <= 1000 || QThread::currentThread() != application->thread()) return derive(password, salt, rounds);
        StartupTrace::note("Security: preparing timer-driven hash.");
        QMessageAuthenticationCode mac(QCryptographicHash::Sha256, password);
        mac.addData(salt + QByteArray("\0\0\0\1", 4));
        QByteArray u = mac.result(), result = u;
        char* combined = result.data();
        int completed = 1;
        BusyDialog busy; QTimer timer;
        QObject::connect(&timer, &QTimer::timeout, &busy, [&] {
            const int stop = min(rounds, completed + 1000);
            for (; completed < stop; ++completed) {
                mac.reset(); mac.addData(u); u = mac.result();
                const char* block = u.constData();
                for (int j = 0; j < result.size(); ++j) combined[j] ^= block[j];
            }
            if (completed == rounds) {
                timer.stop(); StartupTrace::note("Security: all hash rounds completed."); busy.accept();
            }
        });
        // Closing this temporary window must not shut down the whole application.
        const bool quitOnClose = QApplication::quitOnLastWindowClosed();
        QApplication::setQuitOnLastWindowClosed(false);
        StartupTrace::note("Security: opening waiting dialog.");
        timer.start(0); busy.exec(); timer.stop();
        QApplication::setQuitOnLastWindowClosed(quitOnClose);
        // Never return a partly calculated fingerprint after interrupted shutdown.
        if (completed != rounds) throw runtime_error("Account security was interrupted. Please try again.");
        StartupTrace::note("Security: waiting dialog finished.");
        return result;
    }

    // Check whether saved text has the exact hash format this app expects.
    // It must have four $-separated fields: algorithm, rounds, salt, and fingerprint.
    // Rounds must be written canonically and be between SECURITY_ITERATIONS and
    // 1,000,000. The salt needs 32 lowercase hex characters; the digest needs 64.
    // This checks the shape of the stored value, not whether a password matches it.
    bool isHash(const string& value) {
        const auto parts = QString::fromStdString(value).split('$');
        if (parts.size() != 4 || parts[0] != "pbkdf2-sha256") return false;
        bool ok = false; int rounds = parts[1].toInt(&ok);
        // This small checker accepts only the required number of lowercase hexadecimal digits.
        auto hex = [](const QString& text, int length) {
            if (text.size() != length) return false;
            for (QChar c : text) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
            return true;
        };
        return ok && parts[1] == QString::number(rounds) && rounds >= SECURITY_ITERATIONS && rounds <= 1000000
            && hex(parts[2], 32) && hex(parts[3], 64);
    }

    // Hash a new password or normalized answer with a fresh random 16-byte salt.
    // Save the algorithm name, work count, salt, and fingerprint together as text.
    // verify() needs those details to check later guesses. The original secret is
    // not part of the returned text; hashing does not provide a way to read it back.
    string hash(const string& value) {
        StartupTrace::note("Security: generating random salt.");
        QByteArray salt(16, '\0');
        for (int i = 0; i < 16; i += 4) {
            quint32 random = QRandomGenerator::system()->generate();
            for (int j = 0; j < 4; ++j) salt[i+j] = char(random >> (8*j));
        }
        StartupTrace::note("Security: random salt ready.");
        return ("pbkdf2-sha256$" + QByteArray::number(SECURITY_ITERATIONS) + "$" + salt.toHex() + "$"
            + calculate(QByteArray::fromStdString(value), salt, SECURITY_ITERATIONS).toHex()).toStdString();
    }

    // Remove spaces at the ends and fold letter case in a recovery answer.
    // For example, '  CAT  ' and 'cat' are checked the same way. Passwords do not
    // use this rule: their spaces and uppercase letters remain significant.
    string answerText(const string& value) {
        return QString::fromStdString(value).trimmed().toCaseFolded().toStdString();
    }

    // Check typed text against a saved hash; reject an invalid saved format first.
    // Read its salt and rounds, calculate the typed text's fingerprint, and compare
    // all digest bytes before returning true or false. Recovery callers normalize
    // answers first; password callers pass the password exactly as it was typed.
    bool verify(const string& typed, const string& stored) {
        if (!isHash(stored)) return false;
        auto parts = QByteArray::fromStdString(stored).split('$');
        QByteArray actual = calculate(QByteArray::fromStdString(typed), QByteArray::fromHex(parts[2]), parts[1].toInt());
        QByteArray expected = QByteArray::fromHex(parts[3]);
        unsigned difference = 0;
        for (int i = 0; i < expected.size(); ++i) difference |= unsigned(static_cast<unsigned char>(actual[i] ^ expected[i]));
        return difference == 0;
    }
}

// Storage is the file-handling layer. It remembers a loaded file's fingerprint
// and refuses to overwrite a file that changed since that particular copy was read.
// FileIO handles record rules; this layer handles bytes, locks, and replacement.
namespace Storage {
    // Keep the most recent storage problem so a caller can show it to the person.
    QString lastError;
    // Remember whether a file snapshot is valid, existed when read, and looked like
    // current JSON, plus its SHA-256 fingerprint. This describes a read, not a backup.
    struct Revision { bool valid = false; bool exists = false; QByteArray digest; bool json = false; };
    // Use the full filename and the record collection's address as a lookup key.
    // Two different working copies of the same file therefore track separate snapshots.
    using Key = pair<QString, const void*>;
    map<Key, Revision> revisions;

    // Turn a relative filename into a full path using the app's current data folder.
    QString path(const string& filename) { return QFileInfo(QString::fromStdString(filename)).absoluteFilePath(); }
    // Remember an error message and return false so the calling steps can stop.
    bool fail(const QString& message) { lastError = message; return false; }
    // Show lastError in an error dialog attached to parent, then return false.
    bool report(QWidget* parent = nullptr) {
        QMessageBox::critical(parent, "Storage Error", lastError); return false;
    }

    // Read every byte of filename into data and remember the file's fingerprint for owner.
    // owner identifies the in-memory collection that will later save this file.
    // If allowMissing is true, an absent file becomes a valid empty starting point.
    // Read failures return false. Successfully reading bytes does not prove that their
    // record contents are valid; FileIO checks those next.
    bool read(const string& filename, QByteArray& data, const void* owner, bool allowMissing = false) {
        const QString name = path(filename); Revision revision;
        revisions[{name, owner}] = revision;
        // Start with an invalid snapshot so a failed read cannot leave permission to save.
        revision.exists = QFileInfo::exists(name);
        if (!revision.exists) {
            if (!allowMissing) return fail("Missing file: " + name);
            data.clear(); revision.valid = true; revisions[{name, owner}] = revision; return true;
        }
        QFile file(name);
        if (!file.open(QIODevice::ReadOnly)) return fail("Cannot read " + name + ": " + file.errorString());
        data = file.readAll();
        if (file.error() != QFileDevice::NoError) return fail("Read failed: " + name);
        revision.valid = true;
        revision.json = data.trimmed().startsWith('{');
        revision.digest = QCryptographicHash::hash(data, QCryptographicHash::Sha256);
        revisions[{name, owner}] = revision;
        return true;
    }

    // Mark this owner's loaded snapshot invalid and record what was wrong.
    // Later saves of that snapshot are blocked. The error says the original file
    // was kept because this validation step does not rewrite the file.
    bool invalid(const string& filename, const void* owner, const QString& detail) {
        revisions[{path(filename), owner}].valid = false;
        return fail(QString::fromStdString(filename) + ": " + detail + ". Original file was kept.");
    }

    // Save a complete replacement of filename and return whether it succeeded.
    // First acquire a file lock, then compare its existence and fingerprint with
    // the owner's successful read. Reject a changed file or a previous failed load.
    // QSaveFile writes a temporary file and commits it as one replacement, helping
    // avoid half-written records. A successful commit updates the owner's fingerprint.
    // If the file already exists, this working copy must have loaded it first.
    bool write(const string& filename, const QByteArray& data, const void* owner) {
        const QString name = path(filename);
        QLockFile lock(name + ".lock");
        if (!lock.tryLock(0)) return fail("Another operation is using " + name);
        auto found = revisions.find({name, owner});
        bool exists = QFileInfo::exists(name);
        if (found == revisions.end()) {
            if (exists) return fail("Load this file successfully before saving: " + name);
        } else {
            if (!found->second.valid) return fail("Saving blocked after a failed load: " + name);
            if (exists != found->second.exists) return fail("File changed outside this window. Reopen the app: " + name);
            if (exists) {
                QFile file(name);
                if (!file.open(QIODevice::ReadOnly)) return fail("Cannot check " + name);
                auto digest = QCryptographicHash::hash(file.readAll(), QCryptographicHash::Sha256);
                if (file.error() != QFileDevice::NoError || digest != found->second.digest)
                    return fail("File changed outside this window. Reopen the app: " + name);
            }
        }
        QSaveFile output(name); output.setDirectWriteFallback(false);
        if (!output.open(QIODevice::WriteOnly)) return fail("Cannot save " + name + ": " + output.errorString());
        if (output.write(data) != data.size()) { output.cancelWriting(); return fail("Write failed: " + name); }
        // Disable direct-write fallback: if safe temporary replacement is unavailable, fail the
        // save.
        output.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
        if (!output.commit()) return fail("Save failed: " + name + ": " + output.errorString());
        revisions[{name, owner}] = {true, true, QCryptographicHash::hash(data, QCryptographicHash::Sha256), data.trimmed().startsWith('{')};
        return true;
    }

    // Ask whether this owner's valid snapshot still needs conversion to JSON.
    // An accepted missing file or old text file returns true; a current JSON file
    // returns false. This function checks the remembered read and writes nothing.
    bool needsMigration(const string& filename, const void* owner) {
        auto found = revisions.find({path(filename), owner});
        return found != revisions.end() && found->second.valid && !found->second.json;
    }

    // Save report or CSV bytes with the same lock-and-fingerprint checks as records.
    // Read any existing export first using a short-lived owner, attempt replacement,
    // then remove that temporary tracking entry. Return whether the save worked.
    bool exportFile(const string& filename, const QByteArray& data) {
        QByteArray previous; int owner = 0;
        if (!read(filename, previous, &owner, true)) return false;
        bool saved = write(filename, data, &owner);
        revisions.erase({path(filename), &owner}); return saved;
    }

    // Read digit-only text as a positive whole number no larger than maximum.
    // On success, put it in value and return true. Empty text, signs, fractions,
    // extra letters, overflow, and zero fail. This does not trim spaces for the caller.
    bool integer(const string& text, int& value, int maximum = numeric_limits<int>::max()) {
        if (text.empty()) return false;
        for (char c : text) if (c < '0' || c > '9') return false;
        bool ok; qlonglong number = QString::fromStdString(text).toLongLong(&ok);
        if (!ok || number <= 0 || number > maximum) return false;
        value = int(number); return true;
    }
    // Accept a finite grade of zero (missing) or 1 through 5; reject other numbers.
    bool grade(double value) { return isfinite(value) && (value == 0 || (value >= 1 && value <= 5)); }
    // Parse one complete grade field into value, then apply grade().
    // Reject empty text and spaces at either end. true means the conversion and
    // range check both passed; callers must not use a failed conversion as a grade.
    bool number(const string& text, double& value) {
        if (text.empty() || QString::fromStdString(text).trimmed().toStdString() != text) return false;
        bool ok; value = QString::fromStdString(text).toDouble(&ok); return ok && grade(value);
    }
    // Read a JSON number as a positive C++ int and return true when it fits.
    // Reject nonnumbers, fractions, zero, infinity, and values beyond the int limit.
    // Unlike text conversion, this expects an actual numeric field in JSON.
    bool jsonInteger(const QJsonValue& input, int& value) {
        if (!input.isDouble()) return false;
        double n = input.toDouble();
        if (!isfinite(n) || n <= 0 || n > numeric_limits<int>::max() || floor(n) != n) return false;
        value = int(n); return true;
    }
    // Read an optional whole-number field, using fallback when its key is absent.
    // If present, it must be a finite whole number between minimum and maximum.
    // Put the accepted number in value. This lets older files omit newer fields
    // while still rejecting a present field with the wrong type or range.
    bool integerField(const QJsonObject& row, const char* key, int& value, int fallback, int minimum, int maximum) {
        value = fallback;
        if (!row.contains(key)) return true;
        const auto field = row.value(key);
        if (!field.isDouble()) return false;
        const double number = field.toDouble();
        if (!isfinite(number) || floor(number) != number || number < minimum || number > maximum) return false;
        value = int(number); return true;
    }
    // Cut an old text row into a list at each delimiter, keeping empty pieces.
    // For example, 'A||B' becomes 'A', '', 'B' when the delimiter is '|'.
    // Keeping empty fields lets the file loader notice missing required values.
    vector<string> split(const string& line, char delimiter) {
        vector<string> fields; size_t start = 0;
        while (true) {
            size_t end = line.find(delimiter, start);
            fields.push_back(line.substr(start, end == string::npos ? end : end-start));
            if (end == string::npos) return fields;
            start = end + 1;
        }
    }
    // Return true when text contains something besides surrounding whitespace; leave it
    // unchanged.
    bool text(const string& value) { return !QString::fromStdString(value).trimmed().isEmpty(); }
    // Read a JSON field as an ordinary C++ string.
    // A missing or non-string value becomes empty here; strings() must check required types.
    string stringValue(const QJsonObject& row, const char* key) { return row.value(key).toString().toStdString(); }
    // Check every named field is a JSON string; false identifies a missing or wrongly typed
    // field.
    bool strings(const QJsonObject& row, initializer_list<const char*> fields) {
        for (auto key : fields) if (!row.value(key).isString()) return false;
        return true;
    }

    // Pack records into JSON bytes labeled with version 4 and kind, such as 'students'.
    // Those labels let the reader distinguish a student file from a curriculum file.
    // This builds bytes only; Storage::write() performs the actual save.
    QByteArray document(const QString& kind, const QJsonArray& records) {
        return QJsonDocument(QJsonObject{{"version", 4}, {"kind", kind}, {"records", records}}).toJson();
    }
    // Parse JSON bytes and check the outer version, kind, and records array.
    // On success, put the array in rows and return true. Individual records still
    // need their own checks; valid JSON syntax alone does not mean valid school data.
    bool records(const QByteArray& data, const QString& kind, QJsonArray& rows) {
        QJsonParseError error; auto doc = QJsonDocument::fromJson(data, &error);
        if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
        auto object = doc.object();
        if (object.value("version") != QJsonValue(4) || object.value("kind") != QJsonValue(kind) || !object.value("records").isArray()) return false;
        rows = object.value("records").toArray(); return true;
    }
    // Treat text beginning with '{' or '[' after trimming as an attempted JSON file.
    // This chooses which reader to try; malformed JSON still fails the next checks.
    bool isJson(const QByteArray& data) { return data.trimmed().startsWith('{') || data.trimmed().startsWith('['); }

    // Wrap a spreadsheet field in double quotes and double any quote inside it.
    // This keeps a name such as 'Solis, Raphael' together in one CSV column.
    // The function returns escaped text; the export caller adds commas between columns.
    string csv(const string& text) {
        string result = "\"";
        for (char c : text) { result += c; if (c == '"') result += '"'; }
        return result + "\"";
    }
    // Declare the account-specific task filename helper; its steps appear after FileIO.
    string taskFilename(UserRole role, int id, const string& username);
}

// One curriculum entry: its course code, credit units, semester, and year level.
// A course code may recur in another year or semester; all three identify an entry.
struct MasterSubject {
    // The subject's short name, such as CS101.
    string code;
    // Credit units are the course's weight when calculating an average.
    int units;
    // Semester 1 or 2; old entries with no semester are treated as semester 1.
    int semester = 1;
    // Year 1 through 4, or 0 for a subject from an old file with no year assigned.
    int year = 0;
};

// Turn years 1 through 4 into readable labels; other values display as 'Unassigned'.
inline QString yearText(int year) {
    static const QStringList levels{"1st Year", "2nd Year", "3rd Year", "4th Year"};
    return year >= 1 && year <= 4 ? levels[year - 1] : "Unassigned";
}
// Build and return a year dropdown containing only 1st through 4th Year.
// Each label stores its numeric year as item data. Clamp the initial selection
// to that range so the dropdown always starts on an available choice.
inline QComboBox* makeYearCombo(QWidget* parent, int year = 1) {
    auto* combo = new QComboBox(parent);
    for (int level = 1; level <= 4; ++level) combo->addItem(yearText(level), level);
    combo->setCurrentIndex(clamp(year, 1, 4) - 1); return combo;
}
// Return the subjects that apply to the requested year, preserving list order.
// Include that year's entries and old year-0 entries. If both share the same
// semester and code, keep the assigned entry instead of its unassigned duplicate.
// This filters a copy of the list; it does not change the master curriculum.
inline vector<MasterSubject> curriculumForYear(const vector<MasterSubject>& catalog, int year) {
    set<pair<int, string>> assigned;
    for (const auto& subject : catalog) if (subject.year == year) assigned.insert({subject.semester, subject.code});
    vector<MasterSubject> result;
    for (const auto& subject : catalog)
        if (subject.year == year || (subject.year == 0 && !assigned.count({subject.semester, subject.code}))) result.push_back(subject);
    return result;
}

// Show '2nd Semester' for 2 and '1st Semester' otherwise; callers supply valid semester numbers.
inline QString semesterText(int semester) { return semester == 2 ? "2nd Semester" : "1st Semester"; }

// Create a semester dropdown with labels and numeric values 1 and 2.
// Select semester - 1 because Qt counts item positions from zero.
inline QComboBox* makeSemesterCombo(QWidget* parent, int semester = 1) {
    auto* combo = new QComboBox(parent);
    combo->addItem("1st Semester", 1); combo->addItem("2nd Semester", 2);
    combo->setCurrentIndex(semester - 1);
    return combo;
}

// Trim the program name and make letters uppercase: ' bsis ' becomes 'BSIS'.
inline QString normalizeProgram(const QString& value) { return value.trimmed().toUpper(); }
// Clean and check a section name, returning empty text when it is invalid.
// Allow 1 to 8 letters or digits. A digits-only section must be 1 through 99
// and is padded to two digits, so '4' becomes '04'. Letter sections become uppercase.
inline QString normalizeSection(const QString& value) {
    const QString section = value.trimmed().toUpper();
    static const QRegularExpression allowed("^[A-Z0-9]{1,8}$");
    if (!allowed.match(section).hasMatch()) return {};
    static const QRegularExpression numeric("^[0-9]+$");
    if (numeric.match(section).hasMatch()) {
        bool ok = false; int number = section.toInt(&ok);
        return ok && number > 0 && number <= 99 ? QString::number(number).rightJustified(2, '0') : QString();
    }
    return section;
}
// Build a class label such as BSIS-2-04 from program, year, and section.
// Clean the names and reject invalid parts. Years 1 through 6 are accepted here
// so old records remain readable; new-class controls and ensureClassGroup()
// limit newly created groups to years 1 through 4.
inline QString classGroupCode(const QString& program, int year, const QString& section) {
    const QString code = normalizeProgram(program), groupSection = normalizeSection(section);
    static const QRegularExpression allowed("^[A-Z][A-Z0-9]{0,15}$");
    if (!allowed.match(code).hasMatch() || year < 1 || year > 6 || groupSection.isEmpty()) return {};
    return code + "-" + QString::number(year) + "-" + groupSection;
}
// Keep the three parts of a class group together; its display code is built when needed.
struct ClassGroup {
    string program; int year = 0; string section;
    // Return this group's normalized label, or empty text when its parts are invalid.
    QString code() const { return classGroupCode(QString::fromStdString(program), year, QString::fromStdString(section)); }
};

// One personal task includes its description, priority, optional course, due date, and semester.
struct TodoItem {
    // The work to do, as typed by the person.
    string task;
    // The stored priority label, including its colored symbol.
    string priority;
    // Student tasks name a course; general staff tasks leave this empty.
    string course;
    // A calendar due date; an invalid or absent date is displayed as 'No due date'.
    QDate dueDate;
    // Course tasks use semester 1 or 2; a general task uses 0.
    int semester = 0;
};

// One course's midterm and final marks on the 1-to-5 scale; zero means no mark yet.
struct CourseGrade {
    // The midterm mark, or zero when missing.
    double midterm = 0.0;
    // The final mark, or zero when missing.
    double finalGrade = 0.0;

    // Return the course result without changing either mark.
    // Average both recorded marks, use the one recorded mark when only one exists,
    // or return zero when both are missing. For example, 1.50 and 2.00 give 1.75.
    double getSubjectGrade() const {
        if (midterm > 0 && finalGrade > 0) return (midterm + finalGrade) / 2.0;
        if (midterm > 0) return midterm;
        if (finalGrade > 0) return finalGrade;
        return 0.0;
    }
};

// A saved year's notebook page: its curriculum snapshot and its course marks.
// Keeping the old units lets historical averages use the units saved for that year.
struct AcademicYearRecord {
    // Save the list of courses and units that applied when the year was archived.
    vector<MasterSubject> catalog;
    // Look up that year's marks by {semester, course code}.
    map<pair<int, string>, CourseGrade> grades;
};

// A professor's account holds hashed secrets and flags telling login whether setup is complete.
struct ProfAccount {
    // password and secAnswer contain hashes; secQuestion is readable recovery-question text.
    string password, secQuestion, secAnswer;
    // firstLogin requires setup; recoveryConfigured records whether recovery was configured.
    bool firstLogin = true, recoveryConfigured = false;
    // Create a professor account from a password, setup flags, and optional recovery details.
    // Hash new secrets; when stored is true, reuse hashes already checked by a loader.
    // Recovery is marked ready only when setup is complete and question and answer exist.
    // Constructing the account does not write it to the professor file.
    ProfAccount(string pass = "", bool first = true, string question = "", string answer = "", bool stored = false, bool ready = true)
        : password(pass.empty() ? "" : (stored ? pass : Security::hash(pass))), secQuestion(question),
          secAnswer(answer.empty() ? "" : (stored ? answer : Security::hash(Security::answerText(answer)))), firstLogin(first),
          recoveryConfigured(ready && !first && !question.empty() && !answer.empty()) {}
    // Allow recovery only when setup is complete, a question has real text, and the
    // answer has a valid hash format. This checks readiness, not a typed answer.
    bool hasRecovery() const { return recoveryConfigured && !firstLogin && !QString::fromStdString(secQuestion).trimmed().isEmpty() && Security::isHash(secAnswer); }
};

// The Head account stores hashed password/answer, a readable question, and security setup flags.
struct HeadAccount {
    string password, question, answer;
    // Fresh accounts start needing setup; loading old defaults can also require setup.
    bool firstLogin = true, recoveryConfigured = false;
};

// Display a positive average with two decimal places, or 'N/A' when missing.
// This formats text only; calculations keep the original double precision.
inline QString fmtGwa(double val) {
    return (val > 0) ? QString::number(val, 'f', 2) : "N/A";
}

// Grading converts freshly typed percentages to the app's 1-to-5 grade scale.
// Saved marks are already on that scale and are not converted again unless edited.
namespace Grading {
    // Store the original percentage in extra table data, separate from the displayed grade.
    constexpr int PercentageRole = Qt::UserRole + 1;

    // Convert percentage text into grade; optionally also return the numeric percentage.
    // Blank text clears the grade (0) and reports percentage -1 to mean no score.
    // Accept plain decimals from 0 through 100, with an optional leading '+';
    // reject exponents, group separators, minus signs, and other characters.
    // Cutoffs are 97/94/91/88/85/82/79/76/75 for grades
    // 1/1.25/1.50/1.75/2/2.25/2.50/2.75/3; below 75 gives 5.
    // A score of 0 is a recorded failing score (5), different from a blank missing mark.
    // Return false for bad input; callers then keep the previous saved mark.
    bool fromPercentage(const QString& text, double& grade, double* percentage = nullptr) {
        const QString value = text.trimmed();
        if (value.isEmpty()) { grade = 0; if (percentage) *percentage = -1; return true; }
        QString decimal = value; if (decimal.startsWith('+')) decimal.remove(0, 1);
        bool hasDigit = false, hasPoint = false;
        for (QChar character : decimal) {
            if (character >= '0' && character <= '9') hasDigit = true;
            else if (character == '.' && !hasPoint) hasPoint = true;
            else return false;
        }
        if (!hasDigit) return false;
        const int point = decimal.indexOf('.');
        const QString wholeText = point < 0 ? decimal : decimal.left(point);
        bool ok = false; const int whole = wholeText.isEmpty() ? 0 : wholeText.toInt(&ok);
        if ((!wholeText.isEmpty() && !ok) || whole < 0 || whole > 100) return false;
        if (whole == 100 && point >= 0)
            for (QChar character : decimal.mid(point + 1)) if (character != '0') return false;
        const double score = value.toDouble(&ok);
        if (!ok || !isfinite(score) || score < 0 || score > 100) return false;
        if (percentage) *percentage = score;
        // Use the decimal text's whole-number part for integer cutoffs.
        // For example, 96.999 stays below 97 even if floating-point conversion rounds it.
        grade = whole >= 97 ? 1.00 : whole >= 94 ? 1.25 : whole >= 91 ? 1.50 : whole >= 88 ? 1.75
              : whole >= 85 ? 2.00 : whole >= 82 ? 2.25 : whole >= 79 ? 2.50 : whole >= 76 ? 2.75
              : whole >= 75 ? 3.00 : 5.00;
        return true;
    }

    // A table delegate is the helper Qt uses when somebody edits a cell.
    // This one accepts percentages, remembers the typed score, and displays its grade.
    class PercentageDelegate : public QStyledItemDelegate {
    public:
        // Use Qt's existing delegate constructors; no extra setup is needed at construction.
        using QStyledItemDelegate::QStyledItemDelegate;
        // Make and return the one-line percentage editor when a grade cell is opened.
        // Configure decimal input from 0 to 100 without thousands separators, and add
        // a hint that clearing the box removes the mark. Final checks use fromPercentage().
        QWidget* createEditor(QWidget* parent, const QStyleOptionViewItem&, const QModelIndex&) const override {
            auto* input = new QLineEdit(parent); input->setObjectName("percentageGradeEditor");
            auto* validator = new QDoubleValidator(0, 100, 1000, input);
            validator->setNotation(QDoubleValidator::StandardNotation);
            QLocale numericLocale = QLocale::c(); numericLocale.setNumberOptions(QLocale::RejectGroupSeparator);
            validator->setLocale(numericLocale); input->setValidator(validator);
            input->setInputMethodHints(Qt::ImhFormattedNumbersOnly); input->setMinimumHeight(46);
            input->setPlaceholderText("0–100; blank clears the grade");
            return input;
        }
        // Fill the editor with a remembered percentage if available; otherwise use the
        // saved grade text. Clear 'N/A', remember the initial text, and mark it untouched.
        // This prevents opening and closing an old grade from converting it as a percentage.
        void setEditorData(QWidget* editor, const QModelIndex& index) const override {
            auto* input = qobject_cast<QLineEdit*>(editor); if (!input) return;
            const QVariant score = index.data(PercentageRole);
            QString text = score.isValid() ? score.toString() : index.data(Qt::EditRole).toString();
            if (text == "N/A") text.clear();
            input->setText(text); input->setProperty("originalGradeInput", text);
            input->setModified(false); input->selectAll();
        }
        // Return true when the user modified the editor or its text differs from the initial
        // text.
        static bool changed(const QLineEdit* input) {
            return input->isModified() || input->text() != input->property("originalGradeInput").toString();
        }
        // Accept untouched editor text as-is; validate changed text with fromPercentage().
        // This keeps existing 1-to-5 grades safe when the editor is opened without an edit.
        static bool validInput(const QLineEdit* input) {
            double grade; return !changed(input) || fromPercentage(input->text(), grade);
        }
        // Show a nearby input hint and select the bad text so it is easy to replace.
        static void showInputError(QLineEdit* input) {
            QToolTip::showText(input->mapToGlobal(QPoint(0, input->height())),
                "Enter a score from 0 to 100, including decimals. Leave it blank to clear the grade.", input);
            input->selectAll();
        }
        // Save an edited percentage into the table model after checking it.
        // Ignore an untouched editor. Remember the raw score silently in PercentageRole,
        // then set the visible 1-to-5 grade; that visible change triggers the grade handler.
        // Blank input clears the remembered percentage and displays 'N/A'.
        void setModelData(QWidget* editor, QAbstractItemModel* model, const QModelIndex& index) const override {
            auto* input = qobject_cast<QLineEdit*>(editor); if (!input || !changed(input)) return;
            double grade, score;
            if (!fromPercentage(input->text(), grade, &score)) { showInputError(input); return; }
            {
                QSignalBlocker blocker(model);
                model->setData(index, score < 0 ? QVariant() : QVariant(input->text().trimmed()), PercentageRole);
            }
            model->setData(index, fmtGwa(grade), Qt::EditRole);
        }
        // Watch editor key and focus events before Qt's usual processing.
        // Enter and Tab commit valid input; Tab moves to the next cell and Shift+Tab
        // or Backtab moves to the previous one. Invalid input shows a hint and is blocked.
        // On focus loss, also check edited text and explicitly commit a cleared box.
        // Pass other events to Qt's normal delegate handler.
        bool eventFilter(QObject* object, QEvent* event) override {
            auto* input = qobject_cast<QLineEdit*>(object);
            if (input && event->type() == QEvent::KeyPress) {
                const auto* key = static_cast<QKeyEvent*>(event);
                if (key->key() == Qt::Key_Return || key->key() == Qt::Key_Enter
                    || key->key() == Qt::Key_Tab || key->key() == Qt::Key_Backtab) {
                    if (!validInput(input)) { showInputError(input); return true; }
                    auto hint = QAbstractItemDelegate::NoHint;
                    if (key->key() == Qt::Key_Tab)
                        hint = key->modifiers().testFlag(Qt::ShiftModifier) ? QAbstractItemDelegate::EditPreviousItem : QAbstractItemDelegate::EditNextItem;
                    else if (key->key() == Qt::Key_Backtab) hint = QAbstractItemDelegate::EditPreviousItem;
                    emit commitData(input); emit closeEditor(input, hint); return true;
                }
            }
            if (input && event->type() == QEvent::FocusOut
                && static_cast<QFocusEvent*>(event)->reason() != Qt::PopupFocusReason && changed(input)) {
                if (!validInput(input)) { showInputError(input); return true; }
                if (input->text().trimmed().isEmpty()) {
                    emit commitData(input); emit closeEditor(input, QAbstractItemDelegate::NoHint); return true;
                }
            }
            return QStyledItemDelegate::eventFilter(object, event);
        }
    };
}

// Apply a button's background, text color, padding, rounded corners, and minimum height.
inline void styleBtn(QPushButton* btn, const QString& bg, const QString& fg = "#000", int padding = 12) {
    btn->setMinimumHeight(46);
    btn->setStyleSheet(QString("background-color: %1; color: %2; font-weight: bold; padding: %3px; border-radius: 6px;").arg(bg, fg).arg(padding));
}

// Build the shared dark stylesheet and apply it only if the app's style differs.
// The CSS-like rules set fonts, control colors, focus borders, tables, and dialogs.
// A raw string keeps those multiline rules readable; no record data is changed.
inline void applyGlobalDarkTheme() {
    const QString theme = QStringLiteral(R"(
        QWidget { background-color: #121218; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; font-size: 18px; }
        QLineEdit, QComboBox, QDateEdit { background-color: #1e1e2d; border: 1px solid #33334d; border-radius: 6px; padding: 10px; min-height: 26px; color: #fff; }
        QLineEdit:focus, QComboBox:focus, QDateEdit:focus { border: 1px solid #00d2ff; }
        QPushButton { min-height: 26px; }
        QTableWidget, QListWidget { background-color: #1e1e2d; border: 1px solid #2a2a3c; border-radius: 8px; gridline-color: #2a2a3c; color: #fff; }
        QHeaderView::section { background-color: #252538; color: #00d2ff; font-weight: bold; border: none; padding: 10px; }
        QCalendarWidget QAbstractItemView { background-color: #1e1e2d; color: #fff; selection-background-color: #00d2ff; selection-color: #000; }
        QTableWidget::item:selected { background-color: #00d2ff; color: #000; }
        QDialog { background-color: #1a1a24; }
    )");
    if (qApp && qApp->styleSheet() != theme) qApp->setStyleSheet(theme);
}

// Count courses with recorded results and those with results above 3.00.
struct AcademicSummary {
    int recorded = 0, failures = 0;
    // Turn the counts into readable academic status.
    // No recorded results means pending; 1 to 3 failures means warning; 4 or more
    // means failed. Otherwise show passed, with extra wording when detailed is true.
    // Unrecorded courses are not counted as passed or failed.
    string status(bool detailed = false) const {
        if (!recorded) return "PENDING / NO GRADES";
        if (failures > 3) return "FAILED";
        if (failures) return "ACADEMIC WARNING";
        return detailed ? "PASSED (Good Standing)" : "PASSED";
    }
};

// Group the three display strings for a course's midterm, final, and combined result.
struct GradeText { QString midterm, finalGrade, subject; };
// Format all three course marks together, using 'N/A' for missing marks.
inline GradeText gradeText(const CourseGrade& grade) {
    return {fmtGwa(grade.midterm), fmtGwa(grade.finalGrade), fmtGwa(grade.getSubjectGrade())};
}

// Create and return a labeled button, then apply the shared button styling.
// The parent owns the button; the caller adds it to a layout and connects its action.
inline QPushButton* makeButton(const QString& text, QWidget* parent, const QString& color,
                              const QString& foreground = "#000", int padding = 12) {
    auto* button = new QPushButton(text, parent);
    styleBtn(button, color, foreground, padding);
    return button;
}

// Create a one-line input that hides typed characters, and return it to the caller.
// Masking protects what appears on screen; Security handles hashes for file storage.
inline QLineEdit* makePasswordInput(QWidget* parent) {
    auto* input = new QLineEdit(parent);
    input->setEchoMode(QLineEdit::Password);
    return input;
}

// Add Cancel and a labeled Save button beneath a form, returning the Save button.
// Cancel is already connected to reject(). The caller connects Save to its own
// validation or accept action, because each form has different rules.
inline QPushButton* addDialogButtons(QDialog* dialog, QVBoxLayout* layout, const QString& saveText) {
    auto* buttons = new QHBoxLayout;
    auto* save = makeButton(saveText, dialog, "#00d2ff");
    auto* cancel = makeButton("Cancel", dialog, "#33334d", "#fff");
    buttons->addWidget(cancel); buttons->addWidget(save); layout->addLayout(buttons);
    QObject::connect(cancel, &QPushButton::clicked, dialog, &QDialog::reject);
    return save;
}

// Set a table's column labels, readable row heights, and scrolling behavior.
// Columns fit their contents and the last column uses spare width.
// When readOnly is true, disable user edits; otherwise callers decide which cells
// can be edited. This arranges the table without supplying any records.
inline void prepareTable(QTableWidget* table, const QStringList& headers, bool readOnly = false) {
    table->setColumnCount(headers.size()); table->setHorizontalHeaderLabels(headers);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setMinimumSectionSize(72);
    table->verticalHeader()->setDefaultSectionSize(48);
    table->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    table->setVerticalScrollMode(QAbstractItemView::ScrollPerPixel);
    if (readOnly) table->setEditTriggers(QAbstractItemView::NoEditTriggers);
}

// Create a text cell with editing disabled; its table takes ownership when it is inserted.
inline QTableWidgetItem* readOnlyItem(const QString& text) {
    auto* item = new QTableWidgetItem(text);
    item->setFlags(item->flags() & ~Qt::ItemIsEditable);
    return item;
}

// Student is one student's in-memory record: identity, class, account security,
// current marks, year history, and cached averages. Getters read these values;
// setters change the working copy. FileIO saves the record when the caller asks.
class Student {
private:
    // A fixed student ID identifies the record even when table rows are sorted or filtered.
    int id;
    // The full name, kept as ordinary text.
    string name;
    // Assigned year level; zero means this older account has no year set.
    int year = 0;
    // The student's section and program make up the rest of the class assignment.
    string section, program;
    // The latest overall weighted average for the selected semester.
    // It is included in saved JSON, but is recalculated from course marks on dashboard load.
    double gwa;
    // Cached midterm average in memory; it is recalculated and is not a separate saved JSON
    // field.
    double midtermGwa;
    // Cached final average in memory; it is recalculated and is not a separate saved JSON field.
    double finalsGwa;
    // A salted password hash, used for checking logins rather than displaying the original
    // password.
    string password;
    // Require security setup on the next login when this is true.
    bool firstLogin;
    // Remember whether recovery was configured; hasRecovery() checks all readiness conditions.
    bool recoveryConfigured;
    // Readable question text shown when the student asks to recover a password.
    string secQuestion;
    // Hash of the normalized recovery answer; the original answer is not saved.
    string secAnswer;
    // Current-year marks indexed by {semester, course code}.
    // For example, {1, 'CS101'} and {2, 'CS101'} are two separate entries.
    map<pair<int, string>, CourseGrade> grades;
    // Saved past-year records indexed by year number.
    map<int, AcademicYearRecord> academicYears;

public:
    // Create a student with identity, starting GWA, and account security values.
    // Midterm and final caches start at zero. New secrets are hashed; stored=true
    // reuses hashes already validated by the loader. Class and marks are set separately.
    // The constructor creates a working record and does not save a file.
    Student(int sId, string sName, double sGwa, string sPass,
            bool fLogin = true, string q = "", string a = "", bool stored = false, bool ready = true)
        : id(sId), name(sName), gwa(sGwa), midtermGwa(0.0), finalsGwa(0.0),
          password(stored ? sPass : Security::hash(sPass)),
          firstLogin(fLogin), recoveryConfigured(ready && !fLogin && !q.empty() && !a.empty()),
          secQuestion(q), secAnswer(a.empty() ? "" : (stored ? a : Security::hash(Security::answerText(a)))) {}

    // Return the fixed numeric student ID so callers can find the correct record.
    int getId() const { return id; }
    // Read the name through a const reference, avoiding a copy and preventing changes through it.
    const string& getName() const { return name; }
    // Return the assigned year, or zero when no year is set.
    int getYear() const { return year; }
    // Read the section name without copying or changing it.
    const string& getSection() const { return section; }
    // Set the raw year and section while reading an older record.
    // This does not normalize them, set the program, move grade history, or save a file.
    void setYearSection(int value, const string& text) { year = value; section = text; }
    // Read the program name without copying or changing it.
    const string& getProgram() const { return program; }
    // Build the normalized class label; an empty result means the assignment is incomplete or
    // invalid.
    QString getClassGroup() const { return classGroupCode(QString::fromStdString(program), year, QString::fromStdString(section)); }
    // Set year, program, and section, normalizing the two names.
    // When changing academic years, callers must use changeGradeYear() first to
    // archive and restore marks; this setter only updates the class assignment.
    void setClassGroup(int level, const string& courseProgram, const string& classSection) {
        year = level; program = normalizeProgram(QString::fromStdString(courseProgram)).toStdString();
        section = normalizeSection(QString::fromStdString(classSection)).toStdString();
    }
    // Return the cached overall GWA; zero means no recorded course results for its last
    // calculation.
    double getGwa() const { return gwa; }
    // Return the cached midterm GWA from the last calculation; this getter does no math or file
    // reading.
    double getMidtermGwa() const { return midtermGwa; }
    // Return the cached final GWA from the last calculation; this getter does no math or file
    // reading.
    double getFinalsGwa() const { return finalsGwa; }
    // Read the saved-format password hash for login checks or serialization, without copying it.
    const string& getPassword() const { return password; }
    // Return whether this account must complete security setup on login.
    bool isFirstLogin() const { return firstLogin; }
    // Read the recovery question; the caller decides when it may be shown.
    const string& getSecQuestion() const { return secQuestion; }
    // Read the answer hash for verification or saving; it does not reveal the original answer.
    const string& getSecAnswer() const { return secAnswer; }
    // Read the current semester/course lookup map without copying it or allowing changes through
    // it.
    const map<pair<int, string>, CourseGrade>& getGrades() const { return grades; }
    // Read the year-history lookup map without copying it or allowing changes through it.
    const map<int, AcademicYearRecord>& getAcademicYears() const { return academicYears; }
    // Insert or replace one year-history record in memory.
    // The loader checks its contents first; this setter itself does not validate or save.
    void setAcademicYearRecord(int level, const AcademicYearRecord& record) { academicYears[level] = record; }

    // Use the assigned year for grade calculations, falling back to year 1 for an unassigned old
    // account.
    int gradeYear() const { return year > 0 ? year : 1; }
    // Return the curriculum for a requested year.
    // Use the current master list for this student's current grade year, and that
    // year's archived list for another year. Without an archive, return an empty list.
    vector<MasterSubject> catalogForYear(int level, const vector<MasterSubject>& currentCatalog) const {
        if (level == gradeYear()) return curriculumForYear(currentCatalog, level);
        const auto found = academicYears.find(level);
        return found == academicYears.end() ? vector<MasterSubject>() : curriculumForYear(found->second.catalog, level);
    }
    // Build and return a viewing copy for a requested year and semester.
    // Copy this student; for a different year, replace the copy's marks with history
    // or an empty map. Set the copy's year and recalculate its averages with that
    // year's catalog. The real student's assignment, marks, and averages stay unchanged.
    Student forAcademicYear(int level, const vector<MasterSubject>& currentCatalog, int semester) const {
        Student view = *this;
        if (level != gradeYear()) {
            const auto found = academicYears.find(level);
            view.grades = found == academicYears.end() ? map<pair<int, string>, CourseGrade>() : found->second.grades;
        }
        view.year = level;
        view.recalculateGWA(catalogForYear(level, currentCatalog), semester);
        return view;
    }
    // Prepare marks for a move to another year; do nothing if the year is unchanged.
    // Archive the outgoing year's filtered curriculum and current marks together,
    // then restore the destination year's saved marks, or clear them if it has no history.
    // The caller must update the class year next and save the student afterward.
    void changeGradeYear(int level, const vector<MasterSubject>& currentCatalog) {
        if (level == gradeYear()) return;
        academicYears[gradeYear()] = {curriculumForYear(currentCatalog, gradeYear()), grades};
        const auto found = academicYears.find(level);
        grades = found == academicYears.end() ? map<pair<int, string>, CourseGrade>() : found->second.grades;
    }

    // Look up marks by both semester and course code without inserting a new entry.
    // Return a shared zero-filled CourseGrade if none exists; callers can read it
    // as missing marks but cannot change it through this const reference.
    const CourseGrade& gradeFor(const string& code, int semester = 1) const {
        static const CourseGrade missing;
        auto found = grades.find({semester, code});
        return found == grades.end() ? missing : found->second;
    }
    // Summarize recorded courses for this student's year and the requested semester.
    // Use each course's combined result; count positive results and failures above 3.
    // Return counts for status displays and exports; missing results are skipped.
    AcademicSummary academicSummary(const vector<MasterSubject>& catalog, int semester = 1) const {
        AcademicSummary summary;
        for (const auto& subject : curriculumForYear(catalog, gradeYear())) {
            if (subject.semester != semester) continue;
            double grade = gradeFor(subject.code, semester).getSubjectGrade();
            if (grade > 0) { ++summary.recorded; if (grade > 3.0) ++summary.failures; }
        }
        return summary;
    }

    // Replace the name in memory; the caller validates input and saves the changed student.
    void setName(const string& newName) { name = newName; }
    // Hash and replace the password in memory; the caller checks length and saves the record.
    void setPassword(const string& newPass) { password = Security::hash(newPass); }
    // Set the next-login setup flag; this changes memory and does not write a file.
    void setFirstLogin(bool status) { firstLogin = status; }
    // Store the question and hash the answer after trimming and folding its case.
    // Mark recovery as configured; firstLogin must also be false before recovery
    // is available. The caller validates the form and saves the account.
    void setSecurityQA(const string& q, const string& a) {
        secQuestion = q; secAnswer = Security::hash(Security::answerText(a)); recoveryConfigured = true;
    }
    // Return true only after setup is complete, the question has text, and the answer hash is
    // valid.
    bool hasRecovery() const { return recoveryConfigured && !firstLogin && !QString::fromStdString(secQuestion).trimmed().isEmpty() && Security::isHash(secAnswer); }
    // Insert or replace both marks at {semester, code}; other semester entries stay separate.
    // Callers validate the 1-to-5 marks, recalculate averages, and save when appropriate.
    void setTermGrades(const string& code, double midterm, double finalGrade, int semester = 1) { grades[{semester, code}] = {midterm, finalGrade}; }
    // Erase this semester/course entry if it exists; callers recalculate and save afterward.
    void removeGrade(const string& code, int semester = 1) { grades.erase({semester, code}); }

    // Recalculate three weighted averages for this student's year and one semester.
    // For each course, multiply a recorded grade by its units, add those products,
    // and divide by the units that had a recorded grade. Missing marks do not count.
    // Calculate midterm, final, and combined-course averages separately.
    // Example: grade 1 with 3 units and grade 2 with 1 unit give
    // (1*3 + 2*1) / (3+1) = 1.25. More units give a course more influence.
    // Update the caches in memory; this function does not save a file.
    void recalculateGWA(const vector<MasterSubject>& catalog, int semester = 1) {
        // Keep separate grade-times-units totals and recorded-unit totals for each of the three
        // averages.
        double totalSubject = 0, totalMidterm = 0, totalFinal = 0;
        double unitsSubject = 0, unitsMidterm = 0, unitsFinal = 0;
        // Use the student's year-filtered curriculum, then skip other semesters and nonpositive
        // units.
        for (const auto& sub : curriculumForYear(catalog, gradeYear())) {
            if (sub.units <= 0 || sub.semester != semester) continue;
            const auto& grade = gradeFor(sub.code, semester);
            // Only a positive recorded mark contributes its grade-times-units and its course
            // units.
            if (grade.midterm > 0) { totalMidterm += grade.midterm * sub.units; unitsMidterm += sub.units; }
            if (grade.finalGrade > 0) { totalFinal += grade.finalGrade * sub.units; unitsFinal += sub.units; }
            double subject = grade.getSubjectGrade();
            if (subject > 0) { totalSubject += subject * sub.units; unitsSubject += sub.units; }
        }
        // Divide each total by its recorded units; use zero when none exist to avoid division by
        // zero.
        midtermGwa = unitsMidterm > 0 ? totalMidterm / unitsMidterm : 0.0;
        finalsGwa = unitsFinal > 0 ? totalFinal / unitsFinal : 0.0;
        gwa = unitsSubject > 0 ? totalSubject / unitsSubject : 0.0;
    }
};

// FileIO translates between school records and file text, checking the record rules.
// Top-level loaders build temporary collections and replace live data only after
// the complete load succeeds. Savers validate before calling Storage::write().
// A failed operation returns false and leaves an error message for the caller.
struct FileIO {
    // Read optional past-year pages from one student's JSON row into that student.
    // A missing academicYears field is allowed for old files. Check unique year numbers,
    // course entries, units, semesters, and mark ranges before accepting each page.
    // Year numbers 1 through 6 preserve old history; subject years are 0 through 4.
    // The caller supplies a temporary student, so a failed load cannot spoil the live roster.
    static bool loadAcademicYears(const QJsonObject& row, Student& student) {
        if (!row.contains("academicYears")) return true;
        if (!row.value("academicYears").isArray()) return false;
        set<int> years;
        for (const auto& value : row.value("academicYears").toArray()) {
            if (!value.isObject()) return false;
            const auto record = value.toObject(); int year;
            if (!Storage::jsonInteger(record.value("year"), year) || year > 6 || !years.insert(year).second
                || !record.value("catalog").isArray() || !record.value("grades").isArray()) return false;
            // Track distinct subject {year, semester, code} entries and distinct mark {semester,
            // code} entries.
            AcademicYearRecord history; set<tuple<int, int, string>> subjects; set<pair<int, string>> courses;
            for (const auto& subjectValue : record.value("catalog").toArray()) {
                if (!subjectValue.isObject()) return false;
                const auto subject = subjectValue.toObject(); int units, semester, subjectYear;
                const string code = Storage::stringValue(subject, "code");
                if (!Storage::strings(subject, {"code"}) || !Storage::text(code)
                    || !Storage::jsonInteger(subject.value("units"), units)
                    || !Storage::integerField(subject, "semester", semester, 1, 1, 2)
                    || !Storage::integerField(subject, "year", subjectYear, 0, 0, 4)
                    || !subjects.insert({subjectYear, semester, code}).second) return false;
                history.catalog.push_back({code, units, semester, subjectYear});
            }
            for (const auto& gradeValue : record.value("grades").toArray()) {
                if (!gradeValue.isObject()) return false;
                const auto grade = gradeValue.toObject(); int semester;
                const string code = Storage::stringValue(grade, "code");
                if (!Storage::strings(grade, {"code"}) || !Storage::text(code)
                    || !Storage::integerField(grade, "semester", semester, 1, 1, 2)
                    || !courses.insert({semester, code}).second
                    || !grade.value("midterm").isDouble() || !grade.value("final").isDouble()
                    || !Storage::grade(grade.value("midterm").toDouble())
                    || !Storage::grade(grade.value("final").toDouble())) return false;
                history.grades[{semester, code}] = {grade.value("midterm").toDouble(), grade.value("final").toDouble()};
            }
            student.setAcademicYearRecord(year, history);
        }
        return true;
    }
    // Convert a student's year-history pages into the supplied JSON array.
    // Check year ranges, duplicate subject entries, units, and marks while building it.
    // Return false on bad history; the student saver then stops before writing a file.
    // This helper builds JSON only and does not commit the history by itself.
    static bool saveAcademicYears(const Student& student, QJsonArray& years) {
        for (const auto& entry : student.getAcademicYears()) {
            if (entry.first < 1 || entry.first > 6) return Storage::fail("Invalid academic year; save cancelled");
            QJsonArray catalog, grades; set<tuple<int, int, string>> codes;
            for (const auto& subject : entry.second.catalog) {
                if (subject.year < 0 || subject.year > 4 || subject.semester < 1 || subject.semester > 2 || !Storage::text(subject.code) || subject.units <= 0
                    || !codes.insert({subject.year, subject.semester, subject.code}).second)
                    return Storage::fail("Invalid academic year curriculum; save cancelled");
                catalog.append(QJsonObject{{"year", subject.year}, {"semester", subject.semester}, {"code", QString::fromStdString(subject.code)}, {"units", subject.units}});
            }
            for (const auto& course : entry.second.grades) {
                if (course.first.first < 1 || course.first.first > 2 || !Storage::text(course.first.second)
                    || !Storage::grade(course.second.midterm) || !Storage::grade(course.second.finalGrade))
                    return Storage::fail("Invalid academic year grade; save cancelled");
                grades.append(QJsonObject{{"code", QString::fromStdString(course.first.second)}, {"semester", course.first.first},
                    {"midterm", course.second.midterm}, {"final", course.second.finalGrade}});
            }
            years.append(QJsonObject{{"year", entry.first}, {"catalog", catalog}, {"grades", grades}});
        }
        return true;
    }

    // Load the student file as version-4 JSON or older delimiter-separated text.
    // Read bytes and validate IDs, names, account fields, class parts, grades, and history.
    // Reject repeated IDs and repeated {semester, course code} marks within a student.
    // Older records receive defaults for missing newer fields; old plaintext secrets
    // are hashed in memory, and accounts needing new security details require setup.
    // Only replace list after all rows pass. allowMissing permits a fresh empty roster.
    static bool loadStudents(const string& filename, vector<Student>& list, bool allowMissing = false) {
        QByteArray data; if (!Storage::read(filename, data, &list, allowMissing)) return false;
        vector<Student> loaded; set<int> ids;
        // This short error helper blocks saves of the failed snapshot and records a useful
        // reason.
        auto bad = [&](const QString& detail) { return Storage::invalid(filename, &list, detail); };
        QJsonArray rows;
        if (Storage::isJson(data)) {
            if (!Storage::records(data, "students", rows)) return bad("Invalid student document/version");
            for (const auto& value : rows) {
                if (!value.isObject()) return bad("Student record must be an object");
                auto row = value.toObject(); int id;
                if (!Storage::jsonInteger(row.value("id"), id) || id > MAX_STUDENT_ID || !ids.insert(id).second
                    || !Storage::strings(row, {"name", "password", "question", "answer"})
                    || !row.value("firstLogin").isBool() || !row.value("recoveryConfigured").isBool()
                    || !row.value("grades").isArray() || !row.value("gwa").isDouble() || !Storage::grade(row.value("gwa").toDouble()))
                    return bad("Invalid or duplicate student record");
                string name = Storage::stringValue(row, "name"), pass = Storage::stringValue(row, "password");
                string question = Storage::stringValue(row, "question"), answer = Storage::stringValue(row, "answer");
                bool first = row.value("firstLogin").toBool(), ready = row.value("recoveryConfigured").toBool();
                if (!Storage::text(name) || !Security::isHash(pass) || (!answer.empty() && !Security::isHash(answer))
                    || (ready && (first || !Storage::text(question) || !Security::isHash(answer)))) return bad("Invalid student credentials");
                // Construct a temporary student from validated hashes, then load its class and
                // course marks.
                Student student(id, name, row.value("gwa").toDouble(), pass, first, question, answer, true, ready);
                int year;
                if (!Storage::integerField(row, "year", year, 0, 0, 6)
                    || (row.contains("section") && !row.value("section").isString())) return bad("Invalid student year or section");
                const string savedSection = Storage::stringValue(row, "section");
                student.setYearSection(year, savedSection);
                if (row.contains("program") && !row.value("program").isString()) return bad("Invalid student program");
                QString program = row.value("program").toString();
                QString section = QString::fromStdString(savedSection);
                if (program.trimmed().isEmpty()) {
                    // Some older files packed program, year, and section into one Section field.
                    // Split labels such as BSIS-3A or BSIS-2-04 into their separate class parts.
                    static const QRegularExpression legacy("^([A-Za-z][A-Za-z0-9]*)-([1-6])-?([A-Za-z0-9]+)$");
                    auto match = legacy.match(section);
                    if (match.hasMatch()) {
                        program = match.captured(1); section = match.captured(3);
                        if (!year) year = match.captured(2).toInt();
                    }
                }
                if (!program.trimmed().isEmpty()) {
                    if (classGroupCode(program, year, section).isEmpty()) return bad("Invalid student class group");
                    student.setClassGroup(year, program.toStdString(), section.toStdString());
                }
                set<pair<int, string>> codes;
                for (auto grade : row.value("grades").toArray()) {
                    if (!grade.isObject()) return bad("Invalid course for student " + QString::number(id));
                    auto course = grade.toObject(); string code = Storage::stringValue(course, "code"); int semester;
                    if (!Storage::integerField(course, "semester", semester, 1, 1, 2)
                        || !Storage::strings(course, {"code"}) || !Storage::text(code) || !codes.insert({semester, code}).second
                        || !course.value("midterm").isDouble() || !course.value("final").isDouble()
                        || !Storage::grade(course.value("midterm").toDouble()) || !Storage::grade(course.value("final").toDouble()))
                        return bad("Invalid course for student " + QString::number(id));
                    student.setTermGrades(code, course.value("midterm").toDouble(), course.value("final").toDouble(), semester);
                }
                if (!loadAcademicYears(row, student)) return bad("Invalid academic year history for student " + QString::number(id));
                loaded.push_back(student);
            }
        } else {
            // Read old pipe-separated rows. An explicit 0/1 setup flag distinguishes the
            // account format from grade-only rows; field count by itself would be ambiguous.
            int lineNumber = 0;
            for (auto raw : data.split('\n')) {
                ++lineNumber; if (raw.endsWith('\r')) raw.chop(1); if (raw.trimmed().isEmpty()) continue;
                auto fields = Storage::split(raw.toStdString(), '|'); int id; double gwa;
                auto invalidLine = [&] { return bad("Invalid student line " + QString::number(lineNumber)); };
                if (fields.size() < 3 || !Storage::integer(fields[0], id, MAX_STUDENT_ID) || !ids.insert(id).second
                    // Remember which old row failed so the displayed error can identify its line
                    // number.
                    || !Storage::text(fields[1]) || !Storage::number(fields[2], gwa)) return invalidLine();
                bool accountFormat = fields.size() >= 7 && (fields[4] == "0" || fields[4] == "1");
                string pass = "temp" + to_string(id), question, answer;
                bool first = true, ready = false; size_t start = 3;
                if (accountFormat) {
                    pass = fields[3]; first = fields[4] == "1"; question = fields[5]; answer = fields[6]; start = 7;
                    if (pass.empty()) return invalidLine();
                    first = first || !Security::validPassword(QString::fromStdString(pass));
                    ready = !first && Storage::text(question) && Storage::text(answer) && answer != "Default";
                    if (!ready) first = true;
                }
                // Check old course marks before spending time hashing the account's secrets.
                // Old two-part course data uses its one mark for both terms; three parts keep
                // separate midterm and final marks. Legacy courses default to semester 1.
                map<string, CourseGrade> grades;
                for (size_t i = start; i < fields.size(); ++i) {
                    auto course = Storage::split(fields[i], ','); double mid, final;
                    if ((course.size() != 2 && course.size() != 3) || !Storage::text(course[0])
                        || grades.count(course[0]) || !Storage::number(course[1], mid)) return invalidLine();
                    final = mid;
                    if (course.size() == 3 && !Storage::number(course[2], final)) return invalidLine();
                    grades[course[0]] = {mid, final};
                }
                Student student(id, fields[1], gwa, pass, first, question, answer, false, ready);
                for (const auto& course : grades) student.setTermGrades(course.first, course.second.midterm, course.second.finalGrade);
                loaded.push_back(student);
            }
        }
        list = std::move(loaded); return true;
    // Replace the caller's roster only after every temporary student has passed validation.
    }

    // Validate and save the complete roster as labeled version-4 JSON.
    // Store identity/class data, password and answer hashes, setup state, overall
    // GWA, course marks, and year history. Midterm/final GWA caches are not separate
    // saved fields; they are recalculated from marks when needed.
    // JSON keeps punctuation and line breaks inside text fields without splitting rows.
    // Use the roster's address to match the file snapshot checked by Storage.
    static bool saveStudents(const string& filename, const vector<Student>& list) {
        QJsonArray rows; set<int> ids;
        for (const auto& student : list) {
            if (student.getId() <= 0 || student.getId() > MAX_STUDENT_ID || !ids.insert(student.getId()).second || !Storage::text(student.getName())
                || student.getYear() < 0 || student.getYear() > 6
                || (!student.getProgram().empty() && student.getClassGroup().isEmpty())
                || !Security::isHash(student.getPassword()) || (!student.getSecAnswer().empty() && !Security::isHash(student.getSecAnswer())) || !Storage::grade(student.getGwa())) return Storage::fail("Invalid student; save cancelled");
            QJsonArray grades;
            for (const auto& course : student.getGrades()) {
                if (course.first.first < 1 || course.first.first > 2 || !Storage::text(course.first.second)
                    || !Storage::grade(course.second.midterm) || !Storage::grade(course.second.finalGrade))
                    return Storage::fail("Invalid course grade; save cancelled");
                grades.append(QJsonObject{{"code", QString::fromStdString(course.first.second)}, {"semester", course.first.first},
                    {"midterm", course.second.midterm}, {"final", course.second.finalGrade}});
            }
            QJsonArray academicYears;
            if (!saveAcademicYears(student, academicYears)) return false;
            rows.append(QJsonObject{{"id", student.getId()}, {"name", QString::fromStdString(student.getName())},
                {"program", QString::fromStdString(student.getProgram())}, {"year", student.getYear()}, {"section", QString::fromStdString(student.getSection())}, {"gwa", student.getGwa()},
                {"password", QString::fromStdString(student.getPassword())}, {"firstLogin", student.isFirstLogin()},
                {"recoveryConfigured", student.hasRecovery()}, {"question", QString::fromStdString(student.getSecQuestion())},
                {"answer", QString::fromStdString(student.getSecAnswer())}, {"grades", grades}, {"academicYears", academicYears}});
        }
        return Storage::write(filename, Storage::document("students", rows), &list);
    }

    // Load class groups from their JSON file; an absent or empty file gives an empty list.
    // Clean program and section names, check years and unique group codes, and build
    // a temporary list. Preserve legacy years through 6 when reading existing groups.
    // Replace groups only after the full file passes; a bad record blocks later saving.
    static bool loadClassGroups(const string& filename, vector<ClassGroup>& groups) {
        QByteArray bytes; if (!Storage::read(filename, bytes, &groups, true)) return false;
        if (bytes.isEmpty()) { groups.clear(); return true; }
        QJsonArray rows;
        if (!Storage::records(bytes, "class-groups", rows)) return Storage::invalid(filename, &groups, "Invalid class group data");
        vector<ClassGroup> loaded; set<QString> codes;
        for (const auto& value : rows) {
            if (!value.isObject()) return Storage::invalid(filename, &groups, "Invalid class group");
            const auto row = value.toObject(); int year;
            if (!Storage::strings(row, {"program", "section"}) || !Storage::integerField(row, "year", year, 0, 1, 6))
                return Storage::invalid(filename, &groups, "Invalid class group fields");
            ClassGroup group{normalizeProgram(row["program"].toString()).toStdString(), year, normalizeSection(row["section"].toString()).toStdString()};
            if (group.code().isEmpty() || !codes.insert(group.code()).second) return Storage::invalid(filename, &groups, "Invalid or duplicate class group");
            loaded.push_back(group);
        }
        groups = std::move(loaded); return true;
    }
    // Check class group codes are valid and unique, then save the complete group list.
    // The low-level code validator preserves old years through 6; the new-class form
    // and ensureClassGroup() enforce the 1-to-4 limit when a new group is created.
    static bool saveClassGroups(const string& filename, const vector<ClassGroup>& groups) {
        QJsonArray rows; set<QString> codes;
        for (const auto& group : groups) {
            if (group.code().isEmpty() || !codes.insert(group.code()).second) return Storage::fail("Invalid or duplicate class group");
            rows.append(QJsonObject{{"program", QString::fromStdString(group.program)}, {"year", group.year}, {"section", QString::fromStdString(group.section)}});
        }
        return Storage::write(filename, Storage::document("class-groups", rows), &groups);
    }

    // Load professor accounts into a temporary username lookup map.
    // Check current JSON types, unique names, reserved name 'Head', and hash formats.
    // For old text rows, hash plaintext secrets and require setup if recovery details
    // or password length are insufficient. Replace profs only when all rows pass.
    // allowMissing is used to start an empty professor list on a fresh installation.
    static bool loadProfessors(const string& filename, map<string, ProfAccount>& profs, bool allowMissing = false) {
        QByteArray data; if (!Storage::read(filename, data, &profs, allowMissing)) return false;
        map<string, ProfAccount> loaded; QJsonArray rows;
        // Report malformed professor data through the shared invalid-snapshot helper.
        auto bad = [&](const QString& detail) { return Storage::invalid(filename, &profs, detail); };
        if (Storage::isJson(data)) {
            if (!Storage::records(data, "professors", rows)) return bad("Invalid professor document/version");
            for (const auto& value : rows) {
                if (!value.isObject()) return bad("Invalid professor record");
                auto row = value.toObject();
                if (!Storage::strings(row, {"username", "password", "question", "answer"})
                    || !row.value("firstLogin").isBool() || !row.value("recoveryConfigured").isBool()) return bad("Incomplete professor record");
                string user = Storage::stringValue(row, "username"), pass = Storage::stringValue(row, "password");
                string question = Storage::stringValue(row, "question"), answer = Storage::stringValue(row, "answer");
                bool first = row.value("firstLogin").toBool(), ready = row.value("recoveryConfigured").toBool();
                if (!Storage::text(user) || user == "Head" || loaded.count(user) || !Security::isHash(pass)
                    || (!answer.empty() && !Security::isHash(answer)) || (ready && (first || !Storage::text(question) || !Security::isHash(answer))))
                    return bad("Invalid or duplicate professor credentials");
                loaded.emplace(user, ProfAccount(pass, first, question, answer, true, ready));
            }
        } else {
            int lineNumber = 0;
            for (auto raw : data.split('\n')) {
                ++lineNumber; if (raw.endsWith('\r')) raw.chop(1); if (raw.trimmed().isEmpty()) continue;
                auto fields = Storage::split(raw.toStdString(), '|');
                if ((fields.size() != 2 && fields.size() != 5) || !Storage::text(fields[0]) || fields[0] == "Head"
                    || fields[1].empty() || loaded.count(fields[0]) || (fields.size() == 5 && fields[2] != "0" && fields[2] != "1"))
                    return bad("Invalid professor line " + QString::number(lineNumber));
                bool first = fields.size() == 2 || fields[2] == "1";
                string question = fields.size() == 5 ? fields[3] : "", answer = fields.size() == 5 ? fields[4] : "";
                first = first || !Security::validPassword(QString::fromStdString(fields[1]));
                // Old default or incomplete recovery details require the professor to set up
                // security again.
                bool ready = !first && Storage::text(question) && Storage::text(answer) && answer != "Computer Science";
                loaded.emplace(fields[0], ProfAccount(fields[1], !ready, question, answer, false, ready));
            }
        }
        profs = std::move(loaded); return true;
    }

    // Check usernames and secret hash formats, then save all professor accounts as JSON.
    // Include setup flags and recovery question text; hasRecovery() supplies actual
    // recovery readiness. Return the protected file writer's success or failure.
    static bool saveProfessors(const string& filename, const map<string, ProfAccount>& profs) {
        QJsonArray rows;
        for (const auto& entry : profs) {
            const auto& account = entry.second;
            if (!Storage::text(entry.first) || entry.first == "Head" || !Security::isHash(account.password)
                || (!account.secAnswer.empty() && !Security::isHash(account.secAnswer))) return Storage::fail("Invalid professor; save cancelled");
            rows.append(QJsonObject{{"username", QString::fromStdString(entry.first)}, {"password", QString::fromStdString(account.password)},
                {"firstLogin", account.firstLogin}, {"recoveryConfigured", account.hasRecovery()},
                {"question", QString::fromStdString(account.secQuestion)}, {"answer", QString::fromStdString(account.secAnswer)}});
        }
        return Storage::write(filename, Storage::document("professors", rows), &profs);
    }

    // Read and validate the one Head account, accepting current JSON or an old text row.
    // When a file is absent and allowMissing is true, return a blank account needing setup.
    // Old default secrets or short passwords require new setup; plaintext values are
    // hashed during loading. Replace account only after its record passes all checks.
    static bool loadHead(const string& filename, HeadAccount& account, bool allowMissing = false) {
        QByteArray data; if (!Storage::read(filename, data, &account, allowMissing)) return false;
        if (data.isEmpty() && allowMissing && !QFileInfo::exists(Storage::path(filename))) { account = HeadAccount(); return true; }
        // This local error action records a damaged Head account and prevents saving that
        // snapshot.
        auto bad = [&] { return Storage::invalid(filename, &account, "Invalid head account"); };
        HeadAccount loaded; QJsonArray rows;
        if (Storage::isJson(data)) {
            if (!Storage::records(data, "head", rows) || rows.size() != 1 || !rows[0].isObject()) return bad();
            auto row = rows[0].toObject();
            if (!Storage::strings(row, {"password", "question", "answer"})
                || !row.value("firstLogin").isBool() || !row.value("recoveryConfigured").isBool()) return bad();
            loaded = {Storage::stringValue(row, "password"), Storage::stringValue(row, "question"), Storage::stringValue(row, "answer"),
                row.value("firstLogin").toBool(), row.value("recoveryConfigured").toBool()};
            if (!Security::isHash(loaded.password) || (!loaded.answer.empty() && !Security::isHash(loaded.answer))
                || (loaded.recoveryConfigured && (loaded.firstLogin || !Storage::text(loaded.question) || !Security::isHash(loaded.answer)))) return bad();
        } else {
            QByteArray line = data.trimmed(); if (line.contains('\n') || line.contains('\r')) return bad();
            auto fields = Storage::split(line.toStdString(), '|');
            if (fields.size() != 3 || fields[0].empty() || !Storage::text(fields[1]) || !Storage::text(fields[2])) return bad();
            bool first = fields[0] == "schoolhead" || fields[2] == "schoolhead" || fields[2] == "Default" || !Security::validPassword(QString::fromStdString(fields[0]));
            loaded = {Security::hash(fields[0]), fields[1], Security::hash(Security::answerText(fields[2])), first, !first};
        }
        account = loaded; return true;
    }
    // Validate the Head account's hashes and recovery consistency, then save one JSON record.
    // Recovery cannot be configured while first-login setup is still pending.
    // Storage performs the lock, outside-change check, and complete file replacement.
    static bool saveHead(const string& filename, const HeadAccount& account) {
        if (!Security::isHash(account.password) || (!account.answer.empty() && !Security::isHash(account.answer))
            || (account.recoveryConfigured && (account.firstLogin || !Storage::text(account.question) || !Security::isHash(account.answer))))
            return Storage::fail("Invalid head credentials; save cancelled");
        QJsonArray rows{QJsonObject{{"password", QString::fromStdString(account.password)}, {"question", QString::fromStdString(account.question)},
            {"answer", QString::fromStdString(account.answer)}, {"firstLogin", account.firstLogin}, {"recoveryConfigured", account.recoveryConfigured}}};
        return Storage::write(filename, Storage::document("head", rows), &account);
    }

    // Load the curriculum as JSON or old code|units rows, using a temporary list.
    // Check positive whole-number units and unique {year, semester, course code} entries.
    // The same code can belong to different years or semesters. Missing year defaults
    // to 0 (unassigned); missing semester defaults to 1 so older records still work.
    // Replace catalog only after the whole file passes; allowMissing supports first use.
    static bool loadCatalog(const string& filename, vector<MasterSubject>& catalog, bool allowMissing = false) {
        QByteArray data; if (!Storage::read(filename, data, &catalog, allowMissing)) return false;
        vector<MasterSubject> loaded; set<tuple<int, int, string>> codes; QJsonArray rows;
        // Mark the curriculum snapshot unsafe to save when a subject or document is invalid.
        auto bad = [&] { return Storage::invalid(filename, &catalog, "Invalid or duplicate curriculum subject"); };
        if (Storage::isJson(data)) {
            if (!Storage::records(data, "curriculum", rows)) return bad();
            for (auto value : rows) {
                if (!value.isObject()) return bad();
                auto row = value.toObject(); int units, semester, year; string code = Storage::stringValue(row, "code");
                if (!Storage::integerField(row, "year", year, 0, 0, 4)
                    || !Storage::integerField(row, "semester", semester, 1, 1, 2)
                    || !Storage::strings(row, {"code"}) || !Storage::text(code) || !codes.insert({year, semester, code}).second
                    || !Storage::jsonInteger(row.value("units"), units)) return bad();
                loaded.push_back({code, units, semester, year});
            }
        } else {
            for (auto raw : data.split('\n')) {
                if (raw.endsWith('\r')) raw.chop(1); if (raw.trimmed().isEmpty()) continue;
                auto fields = Storage::split(raw.toStdString(), '|'); int units;
                if (fields.size() != 2 || !Storage::text(fields[0]) || !codes.insert({0, 1, fields[0]}).second || !Storage::integer(fields[1], units)) return bad();
                loaded.push_back({fields[0], units});
            }
        }
        catalog = std::move(loaded); return true;
    }
    // Check and save every curriculum entry's year, semester, code, and units as JSON.
    // Year 0 keeps unassigned old subjects; assigned years are 1 through 4.
    // Reject a repeated {year, semester, code} entry and nonpositive units before writing.
    static bool saveCatalog(const string& filename, const vector<MasterSubject>& catalog) {
        QJsonArray rows; set<tuple<int, int, string>> codes;
        for (const auto& subject : catalog) {
            if (subject.year < 0 || subject.year > 4 || subject.semester < 1 || subject.semester > 2 || !Storage::text(subject.code) || subject.units <= 0
                || !codes.insert({subject.year, subject.semester, subject.code}).second) return Storage::fail("Invalid curriculum; save cancelled");
            rows.append(QJsonObject{{"year", subject.year}, {"semester", subject.semester}, {"code", QString::fromStdString(subject.code)}, {"units", subject.units}});
        }
        return Storage::write(filename, Storage::document("curriculum", rows), &catalog);
    }

    // Load this account's tasks into a temporary list; missing files start empty.
    // JSON rows check text fields, course/semester pairing, and exact ISO calendar dates.
    // Old priority|task rows are also accepted; a row without a priority gets Medium.
    // Replace tasks after a successful complete load. A failure keeps the previous list.
    static bool loadTasks(const string& filename, vector<TodoItem>& tasks) {
        QByteArray data; if (!Storage::read(filename, data, &tasks, true)) return false;
        vector<TodoItem> loaded; QJsonArray rows;
        // Record an invalid task document and block saving the failed file snapshot.
        auto bad = [&] { return Storage::invalid(filename, &tasks, "Invalid task record"); };
        if (Storage::isJson(data)) {
            if (!Storage::records(data, "tasks", rows)) return bad();
            for (auto value : rows) {
                if (!value.isObject()) return bad();
                auto row = value.toObject();
                if (!Storage::strings(row, {"task", "priority"}) || !Storage::text(Storage::stringValue(row, "task"))) return bad();
                if ((row.contains("course") && !row.value("course").isString())
                    || (row.contains("dueDate") && !row.value("dueDate").isString())) return bad();
                string course = Storage::stringValue(row, "course"); int semester;
                // A general task has no course and semester 0; a course task must have semester 1
                // or 2.
                if (!Storage::integerField(row, "semester", semester, course.empty() ? 0 : 1, 0, 2)
                    || (course.empty() ? semester != 0 : semester == 0 || !Storage::text(course))) return bad();
                const QString dateText = row.value("dueDate").toString();
                const QDate dueDate = QDate::fromString(dateText, Qt::ISODate);
                if (!dateText.isEmpty() && (!dueDate.isValid() || dueDate.toString(Qt::ISODate) != dateText)) return bad();
                loaded.push_back({Storage::stringValue(row, "task"), Storage::stringValue(row, "priority"), course, dueDate, semester});
            }
        } else {
            for (auto raw : data.split('\n')) {
                if (raw.endsWith('\r')) raw.chop(1); if (raw.trimmed().isEmpty()) continue;
                // In old rows, split at the first pipe only so later pipes remain part of the
                // task text.
                int pipe = raw.indexOf('|');
                loaded.push_back({(pipe < 0 ? raw : raw.mid(pipe+1)).toStdString(), pipe < 0 ? "🟡 Medium" : raw.left(pipe).toStdString()});
            }
        }
        tasks = std::move(loaded); return true;
    }
    // Check task text and course/semester pairing, then save the full list as JSON.
    // Include priority and a date string when available. JSON preserves punctuation
    // and line breaks in task descriptions. Return whether protected replacement succeeds.
    static bool saveTasks(const string& filename, const vector<TodoItem>& tasks) {
        QJsonArray rows;
        for (const auto& task : tasks) {
            if (!Storage::text(task.task) || (task.course.empty() ? task.semester != 0
                : task.semester < 1 || task.semester > 2 || !Storage::text(task.course))) return Storage::fail("Invalid task; save cancelled");
            rows.append(QJsonObject{{"task", QString::fromStdString(task.task)}, {"priority", QString::fromStdString(task.priority)},
                {"course", QString::fromStdString(task.course)}, {"semester", task.semester}, {"dueDate", task.dueDate.toString(Qt::ISODate)}});
        }
        return Storage::write(filename, Storage::document("tasks", rows), &tasks);
    }
};

// Choose a separate task filename for each account.
// Head uses todo_head.txt; a student uses todo_ID.txt. For professors, reuse a
// safe existing legacy username filename, otherwise use a SHA-256 username suffix.
// Safety checks avoid forbidden filename characters and reserved-name collisions.
// This only chooses a path name; it does not load or save the tasks.
string Storage::taskFilename(UserRole role, int id, const string& username) {
    if (role == ROLE_HEAD) return "todo_head.txt";
    if (role == ROLE_STUDENT) return "todo_" + to_string(id) + ".txt";
    const QString name = QString::fromStdString(username);
    bool safe = !name.isEmpty();
    for (QChar c : name) if (c.unicode() < 32 || QString("<>:\"/\\|?*").contains(c)) safe = false;
    string oldName = "todo_" + username + ".txt";
    bool digitsOnly = true;
    for (char c : username) if (c < '0' || c > '9') digitsOnly = false;
    safe = safe && name.compare("head", Qt::CaseInsensitive) != 0 && !digitsOnly && !name.startsWith("prof_", Qt::CaseInsensitive);
    if (safe && QDir::current().entryList(QDir::Files).contains(QString::fromStdString(oldName))) return oldName;
    return "todo_prof_" + QCryptographicHash::hash(QByteArray::fromStdString(username), QCryptographicHash::Sha256).toHex().toStdString() + ".txt";
}

// Keep recovery attempt counts on disk so reopening the app does not clear them.
namespace RecoveryLimit {
    // Update the recovery limit for the given account and whether its answer was correct.
    // Lock the attempt operation, load its JSON file, and find the hashed account key.
    // Reject attempts during a lockout. Five wrong answers create a 300-second lockout;
    // after it expires, the failure count starts over. A correct answer removes the entry.
    // Persist the result and return whether the update succeeded. A wrong answer
    // can still return true here; the caller separately checks the correct flag.
    bool attempt(const string& account, bool correct) {
        QLockFile lock(Storage::path("recovery_limits.json") + ".attempt.lock");
        if (!lock.tryLock(0)) return Storage::fail("Recovery is busy. Try again shortly.");
        QByteArray data; int owner = 0;
        if (!Storage::read("recovery_limits.json", data, &owner, true)) return false;
        QJsonObject limits;
        if (!data.isEmpty()) {
            QJsonParseError error; auto document = QJsonDocument::fromJson(data, &error);
            if (error.error != QJsonParseError::NoError || !document.isObject()) return Storage::fail("Recovery attempt file is damaged. Contact the administrator.");
            limits = document.object();
        }
        // Hash the role/account identifier for its JSON key so different accounts keep separate
        // counts.
        QString key = QString::fromLatin1(QCryptographicHash::hash(QByteArray::fromStdString(account), QCryptographicHash::Sha256).toHex());
        if (limits.contains(key) && !limits.value(key).isObject()) return Storage::fail("Invalid recovery attempt record.");
        QJsonObject record = limits.value(key).toObject();
        qint64 now = QDateTime::currentSecsSinceEpoch();
        double until = record.value("until").toDouble(); int failures = record.value("failures").toInt();
        if (!record.isEmpty() && (!record.value("until").isDouble() || !record.value("failures").isDouble()
            || !isfinite(until) || until < 0 || floor(until) != until || failures < 0 || failures > 5 || record.value("failures").toDouble() != failures)) return Storage::fail("Invalid recovery attempt record.");
        // An active lockout stops even a correct answer; the person must wait for the timeout.
        if (until > now) return Storage::fail("Too many incorrect answers. Try again in five minutes.");
        if (until > 0) failures = 0;
        if (correct) limits.remove(key);
        else { ++failures; limits[key] = QJsonObject{{"failures", failures}, {"until", failures >= 5 ? double(now + 300) : 0.0}}; }
        bool saved = Storage::write("recovery_limits.json", QJsonDocument(limits).toJson(), &owner);
        Storage::revisions.erase({Storage::path("recovery_limits.json"), &owner}); return saved;
    }
}

// This form collects a new password and recovery details; callers decide when setup is required.
class SetupSecurityDialog : public QDialog {
private:
    // Keep pointers to the four inputs so validation and getters can read their current text.
    QLineEdit *newPassInput, *confirmPassInput, *customQuestionInput, *answerInput;
    // A dropdown has four preset questions plus a fifth option for typing a custom question.
    QComboBox *questionCombo;

public:
    // Build the security setup form and choose help/button text from titleStr.
    // Create hidden password/answer inputs, password confirmation, and recovery questions.
    // Only show the custom-question field when its option is selected. Save calls
    // handleSave(); Cancel rejects the form. The caller hashes and saves accepted values.
    SetupSecurityDialog(QWidget* parent = nullptr, const QString& titleStr = "Mandatory Security Setup") : QDialog(parent) {
        setWindowTitle(titleStr);
        setMinimumWidth(520);

        QVBoxLayout* layout = new QVBoxLayout(this);
        // Use the title to distinguish changing security settings, creating Head, and mandatory
        // setup.
        const bool changingPassword = titleStr.startsWith("Change", Qt::CaseInsensitive);
        const bool creatingAccount = titleStr.startsWith("Create", Qt::CaseInsensitive);
        const QString help = changingPassword
            ? "Update your password and recovery information.\nChoose Cancel to keep your current settings."
            : creatingAccount ? "Create your administrator password and recovery question."
            : "Complete account setup with a new password and recovery question.";
        QLabel* infoLabel = new QLabel(help, this);
        infoLabel->setAlignment(Qt::AlignCenter); infoLabel->setWordWrap(true);
        layout->addWidget(infoLabel);

        // Arrange each label beside its input; the vertical outer layout stacks the form and
        // buttons.
        QFormLayout* formLayout = new QFormLayout();
        newPassInput = makePasswordInput(this);
        confirmPassInput = makePasswordInput(this);

        questionCombo = new QComboBox(this);
        questionCombo->addItems({"What is the name of your first school?", "What is your mother's maiden name?",
                                 "What is your favorite childhood pet's name?", "What city were you born in?", "Write custom question..."});

        customQuestionInput = new QLineEdit(this); customQuestionInput->setPlaceholderText("Type custom question here"); customQuestionInput->hide();
        answerInput = makePasswordInput(this); answerInput->setPlaceholderText("Security Answer (case-insensitive)");

        formLayout->addRow("New Password:", newPassInput);
        formLayout->addRow("Confirm Password:", confirmPassInput);
        formLayout->addRow("Security Question:", questionCombo);
        formLayout->addRow("", customQuestionInput);
        formLayout->addRow("Security Answer:", answerInput);
        layout->addLayout(formLayout);

        auto* saveBtn = addDialogButtons(this, layout, changingPassword ? "Save Changes" : creatingAccount ? "Create Account" : "Save & Complete Setup");

        // When the fifth question is selected, reveal the custom text box; hide it for preset
        // questions.
        connect(questionCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), [this](int idx){
            customQuestionInput->setVisible(idx == 4);
        });
        connect(saveBtn, &QPushButton::clicked, this, &SetupSecurityDialog::handleSave);
    }

    // Return the password exactly as typed, including spaces and letter case; the caller hashes
    // it.
    string getPassword() const { return newPassInput->text().toStdString(); }
    // Return the preset question or trimmed custom question, depending on the dropdown selection.
    string getQuestion() const { return (questionCombo->currentIndex() == 4) ? customQuestionInput->text().trimmed().toStdString() : questionCombo->currentText().toStdString(); }
    // Return the answer with end spaces removed; the caller also folds its case before hashing.
    string getAnswer() const { return answerInput->text().trimmed().toStdString(); }

private:
    // Check password length, matching confirmation, and nonempty question/answer.
    // Show a warning and leave the form open if anything is wrong.
    // accept() reports valid input to the caller; it does not write credentials to disk.
    void handleSave() {
        if (!Security::validPassword(newPassInput->text())) { QMessageBox::warning(this, "Weak Password", "Password must contain 8 to 256 characters."); return; }
        if (newPassInput->text() != confirmPassInput->text()) { QMessageBox::warning(this, "Mismatch", "Passwords do not match!"); return; }
        if (getQuestion().empty() || getAnswer().empty()) { QMessageBox::warning(this, "Input Required", "Please complete all security fields."); return; }
        StartupTrace::note("Setup: input validated; accepting form.");
        accept();
    }
};

// Password recovery finds an account's question, verifies its answer, and changes
// its in-memory password. LoginDialog saves afterward and can undo a failed save.
class ForgotPasswordDialog : public QDialog {
private:
    // Recovery dropdown positions are 0=Student, 1=Professor, and 2=Head.
    QComboBox* roleCombo;
    QLineEdit *idOrUserInput, *answerInput, *newPassInput, *confirmPassInput;
    QLabel* questionDisplay;
    QPushButton* resetPassBtn;

    // Share the login dialog's live account collections by reference instead of copying them.
    vector<Student>& roster;
    map<string, ProfAccount>& profAccounts;
    HeadAccount& headAccount;
    // Remember the fetched answer hash and professor name to detect a changed recovery target.
    string targetAnswer, targetProfUser;
    // Keep a small undo function containing the previous account, used if saving the reset fails.
    function<void()> undoPassword;
    // Remember the target ID and role; -1 means no account has been fetched yet.
    int targetStudentId = -1, targetRole = -1;
    // Keep the exact trimmed identifier used to fetch the current question.
    string targetInput;

public:
    // Build the role/identifier lookup and password-recovery form around shared account data.
    // Reset starts disabled until a configured account's question is fetched.
    // Changing role or identifier clears the target. Fetch and Reset run separate handlers;
    // Back to Login cancels the dialog. This constructor does not reset any password.
    ForgotPasswordDialog(vector<Student>& st, map<string, ProfAccount>& profs, HeadAccount& head, QWidget* parent = nullptr)
        : QDialog(parent), roster(st), profAccounts(profs), headAccount(head) {

        setWindowTitle("Password Recovery");
        setMinimumWidth(540);

        QVBoxLayout* layout = new QVBoxLayout(this);
        QLabel* header = new QLabel("Reset Forgotten Password", this);
        header->setStyleSheet("font-size: 22px; font-weight: bold; color: #00d2ff;");
        header->setAlignment(Qt::AlignCenter);
        layout->addWidget(header);

        QFormLayout* form = new QFormLayout();
        roleCombo = new QComboBox(this); roleCombo->addItems({"Student", "Professor", "Head Admin"});
        idOrUserInput = new QLineEdit(this); idOrUserInput->setPlaceholderText("Enter Student ID or Username");

        auto* fetchQuestionBtn = makeButton("Fetch Security Question", this, "#2e86de", "#fff", 6);
        questionDisplay = new QLabel("Click 'Fetch Security Question' above.", this);
        questionDisplay->setTextFormat(Qt::PlainText); questionDisplay->setWordWrap(true); questionDisplay->setStyleSheet("color: #70a1ff; font-weight: bold; margin-top: 5px;");

        answerInput = makePasswordInput(this); answerInput->setPlaceholderText("Security Answer");
        newPassInput = makePasswordInput(this);
        confirmPassInput = makePasswordInput(this);

        form->addRow("Account Role:", roleCombo);
        form->addRow("ID / Username:", idOrUserInput);
        form->addRow("", fetchQuestionBtn);
        form->addRow("Security Question:", questionDisplay);
        form->addRow("Your Answer:", answerInput);
        form->addRow("New Password:", newPassInput);
        form->addRow("Confirm Password:", confirmPassInput);
        layout->addLayout(form);

        QHBoxLayout* btnLayout = new QHBoxLayout();
        auto* backToLoginBtn = makeButton("Back to Login", this, "#33334d", "#fff", 10);
        resetPassBtn = makeButton("Reset Password Now", this, "#00d2ff", "#000", 10);
        btnLayout->addWidget(backToLoginBtn);
        btnLayout->addWidget(resetPassBtn);
        layout->addLayout(btnLayout);

        // Enable reset only after fetching; wire account changes to invalidate any previously
        // fetched target.
        resetPassBtn->setEnabled(false);
        connect(roleCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this](int) { invalidateTarget(); });
        connect(idOrUserInput, &QLineEdit::textChanged, this, [this](const QString&) { invalidateTarget(); });
        connect(fetchQuestionBtn, &QPushButton::clicked, this, &ForgotPasswordDialog::handleFetchQuestion);
        connect(resetPassBtn, &QPushButton::clicked, this, &ForgotPasswordDialog::handleResetPassword);
        connect(backToLoginBtn, &QPushButton::clicked, this, &QDialog::reject);
    }

    // Return the recovery role number so LoginDialog knows which account file must be saved.
    int recoveredRole() const { return targetRole; }
    // Run the saved undo action if present, restoring the account after a failed password save.
    void restoreAccount() { if (undoPassword) undoPassword(); }

private:
    // Clear any old target, then find the selected account using its ID or username.
    // Only allow accounts with completed recovery setup. Remember their identity and
    // answer hash, display the stored question, and enable Reset. No answer is revealed.
    // An invalid ID or unavailable account leaves recovery disabled and shows a message.
    void handleFetchQuestion() {
        invalidateTarget();
        string input = idOrUserInput->text().trimmed().toStdString();
        int role = roleCombo->currentIndex();
        string question;
        if (role == 0) {
            int id;
            if (!Storage::integer(input, id, MAX_STUDENT_ID)) { QMessageBox::warning(this, "Invalid ID", "Enter a positive Student ID of up to 9 digits."); return; }
            auto found = find_if(roster.begin(), roster.end(), [id](const Student& student) { return student.getId() == id; });
            if (found == roster.end() || !found->hasRecovery()) { unavailable(); return; }
            targetStudentId = id; question = found->getSecQuestion(); targetAnswer = found->getSecAnswer();
        } else if (role == 1) {
            auto found = profAccounts.find(input);
            if (found == profAccounts.end() || !found->second.hasRecovery()) { unavailable(); return; }
            targetProfUser = input; question = found->second.secQuestion; targetAnswer = found->second.secAnswer;
        } else if (role == 2 && input == "Head" && headAccount.recoveryConfigured && !headAccount.firstLogin) {
            question = headAccount.question; targetAnswer = headAccount.answer;
        } else { unavailable(); return; }
        targetInput = input; targetRole = role;
        questionDisplay->setText(QString::fromStdString(question));
        resetPassBtn->setEnabled(true);
    }

    // Forget the fetched identity, answer hash, and undo action.
    // Reset the question prompt and disable Reset so another account cannot accidentally
    // use the previous account's question or verification state.
    void invalidateTarget() {
        targetRole = -1; targetStudentId = -1;
        targetInput.clear(); targetProfUser.clear(); targetAnswer.clear(); undoPassword = {};
        questionDisplay->setText("Fetch the question for this account."); resetPassBtn->setEnabled(false);
    }
    // Clear the target and show that the account was not found or its security setup is
    // incomplete.
    void unavailable() {
        invalidateTarget();
        QMessageBox::warning(this, "Recovery Unavailable", "Account not found or security setup is incomplete. Contact your administrator.");
    }

    // Reset only the account whose question was fetched.
    // Recheck the selected identity, recovery readiness, and unchanged answer hash;
    // validate the new password and confirmation. Normalize and verify the answer,
    // then update the persistent wrong-answer limit. Stop on lockout or a wrong answer.
    // Before changing a password hash, keep an undo action for that account.
    // Accept the dialog on success; LoginDialog must save or restore the account.
    void handleResetPassword() {
        if (targetRole < 0 || targetRole != roleCombo->currentIndex() || targetInput != idOrUserInput->text().trimmed().toStdString()) {
            invalidateTarget(); QMessageBox::warning(this, "Step Required", "Fetch this account's security question first."); return;
        }
        // Find the target again in the current collections; do not rely on an earlier pointer
        // staying valid.
        Student* student = nullptr; ProfAccount* professor = nullptr;
        string currentAnswer;
        if (targetRole == 0) {
            auto found = find_if(roster.begin(), roster.end(), [this](const Student& row) { return row.getId() == targetStudentId; });
            if (found == roster.end() || !found->hasRecovery()) { unavailable(); return; }
            student = &*found; currentAnswer = student->getSecAnswer();
        } else if (targetRole == 1) {
            auto found = profAccounts.find(targetProfUser);
            if (found == profAccounts.end() || !found->second.hasRecovery()) { unavailable(); return; }
            professor = &found->second; currentAnswer = professor->secAnswer;
        } else {
            if (!headAccount.recoveryConfigured || headAccount.firstLogin) { unavailable(); return; }
            currentAnswer = headAccount.answer;
        }
        // If recovery details changed after Fetch, require a new lookup instead of checking the
        // stale answer.
        if (currentAnswer != targetAnswer) { unavailable(); return; }
        if (!Security::validPassword(newPassInput->text()) || newPassInput->text() != confirmPassInput->text()) {
            QMessageBox::warning(this, "Password Error", "Use 8 to 256 characters and matching confirmation."); return;
        }
        // Check the normalized answer, then persist the attempt outcome before allowing a
        // password change.
        bool correct = Security::verify(Security::answerText(answerInput->text().toStdString()), currentAnswer);
        if (!RecoveryLimit::attempt(to_string(targetRole) + ":" + (targetRole == 0 ? to_string(targetStudentId) : targetInput), correct)) { Storage::report(this); return; }
        if (!correct) { QMessageBox::critical(this, "Incorrect Answer", "The security answer is incorrect."); return; }
        // After successful verification, keep the old account before replacing its password hash.
        string password = newPassInput->text().toStdString();
        if (student) {
            // For a student undo, capture the old record and find it again by fixed ID before
            // restoring it.
            undoPassword = [this, id = targetStudentId, previous = *student] {
                auto found = find_if(roster.begin(), roster.end(), [id](const Student& row) { return row.getId() == id; });
                if (found != roster.end()) *found = previous;
            };
            student->setPassword(password);
        } else if (professor) {
            // For a professor undo, capture the username and old account and restore that map
            // entry.
            undoPassword = [this, user = targetProfUser, previous = *professor] { profAccounts.at(user) = previous; };
            professor->password = Security::hash(password);
        } else {
            // For a Head undo, capture the old Head record and restore it directly.
            undoPassword = [this, previous = headAccount] { headAccount = previous; };
            headAccount.password = Security::hash(password);
        }
        accept();
    }
};

// Collect a proposed professor username and password; the Head dashboard creates and saves the
// account.
class AddProfDialog : public QDialog {
private:
    QLineEdit *userInput, *passInput;

public:
    // Build the professor registration form with a username, masked password, and buttons.
    // Save checks nonempty username and password length before accepting.
    // The caller still checks duplicate/reserved usernames and persists the new account.
    AddProfDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Add Professor Account"); setMinimumWidth(500);
        QVBoxLayout* layout = new QVBoxLayout(this);
        QFormLayout* form = new QFormLayout();

        userInput = new QLineEdit(this); userInput->setPlaceholderText("e.g. prof_smith");
        passInput = makePasswordInput(this);
        form->addRow("Username:", userInput); form->addRow("Password:", passInput);
        layout->addLayout(form);

        auto* saveBtn = addDialogButtons(this, layout, "Create Account");

        // On Create Account, reject missing names or passwords outside 8 to 256 characters;
        // otherwise accept.
        connect(saveBtn, &QPushButton::clicked, this, [this] {
            if (userInput->text().trimmed().isEmpty() || !Security::validPassword(passInput->text())) { QMessageBox::warning(this, "Input Error", "Enter a username and a password of 8 to 256 characters."); return; }
            accept();
        });
    }

    // Return the username with surrounding whitespace removed for the caller's duplicate check.
    string getUsername() const { return userInput->text().trimmed().toStdString(); }
    // Return the password exactly as entered; validation occurs when the form is accepted.
    string getPassword() const { return passInput->text().toStdString(); }
};

// Ask for a replacement password; the authorized dashboard action performs and saves the reset.
class ResetAccountPasswordDialog : public QDialog {
private:
    QLineEdit* newPassInput;

public:
    // Show the target account name and a suggested replacement password in a masked input.
    // Escape the name before inserting it into a rich-text label. Save checks length;
    // Cancel leaves the action unaccepted. The caller hashes and persists the replacement.
    ResetAccountPasswordDialog(const string& accName, const string& defaultPass, QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Reset Account Password"); setMinimumWidth(520);
        QVBoxLayout* layout = new QVBoxLayout(this);
        QLabel* info = new QLabel(QString("Resetting Password for: <b>%1</b>").arg(QString::fromStdString(accName).toHtmlEscaped()), this);
        info->setAlignment(Qt::AlignCenter); layout->addWidget(info);

        QFormLayout* form = new QFormLayout();
        newPassInput = makePasswordInput(this); newPassInput->setText(QString::fromStdString(defaultPass));
        form->addRow("New Password:", newPassInput); layout->addLayout(form);

        auto* saveBtn = addDialogButtons(this, layout, "Reset Password");

        // On Reset Password, require 8 to 256 characters before reporting accepted input.
        connect(saveBtn, &QPushButton::clicked, this, [this] {
            if (!Security::validPassword(newPassInput->text())) { QMessageBox::warning(this, "Password Error", "Use 8 to 256 characters."); return; }
            accept();
        });
    }

    // Return the proposed replacement password exactly; this getter performs no reset or hashing.
    string getNewPassword() const { return newPassInput->text().toStdString(); }
};

// Edit the shared announcement. Although the UI calls it a class announcement,
// the app stores one notice for everyone rather than a separate notice per class.
class EditAnnouncementDialog : public QDialog {
private:
    QTextEdit* announcementInput;

public:
    // Build a multiline announcement editor starting with currentText.
    // Post accepts the edited text; Cancel rejects it. The dashboard reads the getter
    // and saves the shared notice only after acceptance.
    EditAnnouncementDialog(const string& currentText, QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Post Class Announcement"); setMinimumSize(600, 380);
        QVBoxLayout* layout = new QVBoxLayout(this);
        QLabel* label = new QLabel("Post an announcement visible to all enrolled students:", this);
        label->setStyleSheet("font-weight: bold; color: #00d2ff;"); layout->addWidget(label);

        // Set plain text so notice content is treated as words rather than HTML formatting.
        announcementInput = new QTextEdit(this); announcementInput->setPlainText(QString::fromStdString(currentText));
        layout->addWidget(announcementInput);

        auto* saveBtn = addDialogButtons(this, layout, "Post Announcement");

        // Post reports acceptance immediately; the caller handles the actual notice save.
        connect(saveBtn, &QPushButton::clicked, this, &QDialog::accept);
    }

    // Return the full announcement with only surrounding whitespace removed; keep internal line
    // breaks.
    string getAnnouncement() const { return announcementInput->toPlainText().trimmed().toStdString(); }
};

// LoginDialog guards access to the dashboard and handles mandatory security setup.
// It shares the student roster, loads staff accounts, and records identity after success.
class LoginDialog : public QDialog {
private:
    // Share main()'s student roster so accepted account setup can update and save it.
    vector<Student>& roster;
    // Keep this login dialog's loaded username-to-professor account map.
    map<string, ProfAccount> profAccounts;
    // Keep the Head account read from validated storage.
    HeadAccount headAccount;
    // Resolve these database names in the data folder chosen by main().
    const string profFilename = "professors.txt", headFilename = "head_admin.txt";

    QStackedWidget* formStack;
    QLineEdit *studentIdInput, *studentPassInput, *profUser, *profPass;
    QLabel* modeTitle;
    QPushButton *toggleModeBtn, *forgotPassBtn;

    // Fill login identity only after verification succeeds; main() reads it only after accept().
    UserRole loggedRole;
    int loggedStudentId = -1;
    string loggedProfUser;
    // Ignore repeated login/recovery clicks while hashing or a security form is still active.
    bool authInProgress = false;

public:
    // Load the Head and professor accounts, throwing an error if either load fails.
    // Build separate student and staff login pages in a stack, plus mode-switch and
    // recovery buttons. Student IDs get a nine-digit validator; secrets are masked.
    // Connect each login button to its checker. This constructor does not log anyone in.
    LoginDialog(vector<Student>& stList, QWidget* parent = nullptr) : QDialog(parent), roster(stList) {
        if (!FileIO::loadHead(headFilename, headAccount) || !FileIO::loadProfessors(profFilename, profAccounts)) throw runtime_error(Storage::lastError.toStdString());
        setWindowTitle("System Login"); setMinimumSize(540, 480);

        QVBoxLayout* mainLayout = new QVBoxLayout(this); mainLayout->setContentsMargins(25, 25, 25, 25);
        modeTitle = new QLabel("Student Portal Access", this);
        modeTitle->setStyleSheet("font-size: 26px; font-weight: bold; color: #00d2ff;"); modeTitle->setAlignment(Qt::AlignCenter);
        mainLayout->addWidget(modeTitle);

        // A stack keeps both forms but shows one at a time; index 0 is student and index 1 is
        // staff.
        formStack = new QStackedWidget(this);

        // Students provide a fixed numeric ID and their exact password.
        QWidget* studentPage = new QWidget(this); QVBoxLayout* stLayout = new QVBoxLayout(studentPage);
        QFormLayout* stForm = new QFormLayout();
        studentIdInput = new QLineEdit(this); studentIdInput->setPlaceholderText("Enter Student ID (e.g. 1001)"); studentIdInput->setValidator(new QIntValidator(1, MAX_STUDENT_ID, this)); studentIdInput->setMaxLength(9);
        studentPassInput = makePasswordInput(this);
        stForm->addRow("Student ID:", studentIdInput); stForm->addRow("Password:", studentPassInput);
        stLayout->addLayout(stForm);
        auto* studentLoginBtn = makeButton("Login as Student", this, "#00d2ff", "#000", 10);
        stLayout->addWidget(studentLoginBtn); formStack->addWidget(studentPage);

        // Professors use their usernames; Head uses the reserved username 'Head'.
        QWidget* profPage = new QWidget(this); QVBoxLayout* prLayout = new QVBoxLayout(profPage);
        QFormLayout* prForm = new QFormLayout();
        profUser = new QLineEdit(this); profUser->setPlaceholderText("Username (Head or prof_user)");
        profPass = makePasswordInput(this);
        prForm->addRow("Username:", profUser); prForm->addRow("Password:", profPass);
        prLayout->addLayout(prForm);
        auto* profLoginBtn = makeButton("Login as Staff / Admin", this, "#2e86de", "#fff", 10);
        prLayout->addWidget(profLoginBtn); formStack->addWidget(profPage);

        mainLayout->addWidget(formStack);

        toggleModeBtn = new QPushButton("Are you Staff / Head? Click to Login", this);
        toggleModeBtn->setStyleSheet("background: transparent; color: #a55eea; text-decoration: underline; border: none; font-weight: bold;");
        mainLayout->addWidget(toggleModeBtn);

        forgotPassBtn = new QPushButton("Forgot Password?", this);
        forgotPassBtn->setStyleSheet("background: transparent; color: #ff4757; text-decoration: underline; border: none; font-weight: bold;");
        mainLayout->addWidget(forgotPassBtn);

        // Wire each Login button to its own role-aware credential checker.
        connect(studentLoginBtn, &QPushButton::clicked, this, &LoginDialog::handleStudentLogin);
        connect(profLoginBtn, &QPushButton::clicked, this, &LoginDialog::handleProfLogin);
        // Switch visible form and update the title/link together so the person sees the matching
        // login mode.
        connect(toggleModeBtn, &QPushButton::clicked, [this](){
            const bool isProfMode = formStack->currentIndex() == 0;
            formStack->setCurrentIndex(isProfMode ? 1 : 0);
            modeTitle->setText(isProfMode ? "Staff & Head Portal Login" : "Student Portal Access");
            toggleModeBtn->setText(isProfMode ? "Are you a Student? Click to Login" : "Are you Staff / Head? Click to Login");
        });
        connect(forgotPassBtn, &QPushButton::clicked, this, &LoginDialog::handleForgotPassword);
    }

    // Return the verified role; the caller should read this only after the login dialog is
    // accepted.
    UserRole getRole() const { return loggedRole; }
    // Return the verified student ID; nonstudent logins leave it at -1.
    int getStudentId() const { return loggedStudentId; }
    // Return the verified professor username; it stays empty for other roles.
    string getProfUser() const { return loggedProfUser; }

private:
    // Open recovery once at a time using this dialog's shared account data.
    // If recovery is accepted, save the appropriate student, professor, or Head file.
    // If saving fails, run the recovery undo action and show the error.
    // Show success only after the changed password has been committed.
    void handleForgotPassword() {
        if (authInProgress) return;
        // Set the busy flag for this scope; QScopedValueRollback automatically restores it on
        // every return.
        QScopedValueRollback<bool> operation(authInProgress, true);
        ForgotPasswordDialog dialog(roster, profAccounts, headAccount, this);
        if (dialog.exec() != QDialog::Accepted) return;
        int role = dialog.recoveredRole();
        bool saved = role == 0 ? FileIO::saveStudents("students.txt", roster)
            : role == 1 ? FileIO::saveProfessors(profFilename, profAccounts) : FileIO::saveHead(headFilename, headAccount);
        if (!saved) { dialog.restoreAccount(); Storage::report(this); return; }
        QMessageBox::information(this, "Password Reset", "Your new password was saved successfully.");
    }

    // Check staff credentials, trying the reserved Head account before professor lookup.
    // For a valid password, require security setup when the account is still pending
    // or recovery is unavailable. Save accepted setup and restore old values on failure.
    // Only then record the role/username and accept login. Otherwise show Login Failed.
    // The busy guard prevents repeated actions while the check or setup is running.
    void handleProfLogin() {
        if (authInProgress) return;
        QScopedValueRollback<bool> operation(authInProgress, true);
        string user = profUser->text().trimmed().toStdString(), pass = profPass->text().toStdString();
        if (user == "Head" && Security::verify(pass, headAccount.password)) {
            if (headAccount.firstLogin || !headAccount.recoveryConfigured) {
                SetupSecurityDialog dialog(this, "Head Admin Security Setup");
                if (dialog.exec() != QDialog::Accepted) return;
                auto previous = headAccount;
                headAccount = {Security::hash(dialog.getPassword()), dialog.getQuestion(), Security::hash(Security::answerText(dialog.getAnswer())), false, true};
                if (!FileIO::saveHead(headFilename, headAccount)) { headAccount = previous; Storage::report(this); return; }
            }
            loggedRole = ROLE_HEAD; accept(); return;
        }
        auto found = profAccounts.find(user);
        if (found != profAccounts.end() && Security::verify(pass, found->second.password)) {
            if (found->second.firstLogin || !found->second.hasRecovery()) {
                SetupSecurityDialog dialog(this, "Professor Security Setup");
                if (dialog.exec() != QDialog::Accepted) return;
                auto previous = found->second;
                found->second = ProfAccount(dialog.getPassword(), false, dialog.getQuestion(), dialog.getAnswer());
                if (!FileIO::saveProfessors(profFilename, profAccounts)) { found->second = previous; Storage::report(this); return; }
            }
            loggedRole = ROLE_PROFESSOR; loggedProfUser = user; accept(); return;
        }
        QMessageBox::critical(this, "Login Failed", "Invalid username or password.");
    }

    // Validate the entered student ID, find its record, and verify the exact password.
    // Require security setup when needed; save the new hashes and flags or restore
    // the previous student if saving fails. After success, record role and ID and
    // accept login. Invalid credentials leave the login form open.
    void handleStudentLogin() {
        if (authInProgress) return;
        QScopedValueRollback<bool> operation(authInProgress, true);
        int id;
        if (!Storage::integer(studentIdInput->text().toStdString(), id, MAX_STUDENT_ID)) { QMessageBox::warning(this, "Invalid ID", "Enter a positive Student ID of up to 9 digits."); return; }
        auto found = find_if(roster.begin(), roster.end(), [id](const Student& student) { return student.getId() == id; });
        if (found == roster.end() || !Security::verify(studentPassInput->text().toStdString(), found->getPassword())) {
            QMessageBox::critical(this, "Login Failed", "Invalid Student ID or password."); return;
        }
        if (found->isFirstLogin() || !found->hasRecovery()) {
            SetupSecurityDialog dialog(this, "Student Security Setup");
            if (dialog.exec() != QDialog::Accepted) return;
            auto previous = *found;
            found->setPassword(dialog.getPassword()); found->setSecurityQA(dialog.getQuestion(), dialog.getAnswer()); found->setFirstLogin(false);
            if (!FileIO::saveStudents("students.txt", roster)) { *found = previous; Storage::report(this); return; }
        }
        loggedRole = ROLE_STUDENT; loggedStudentId = id; accept();
    }
};

// Edit curriculum entries by year and semester; the dashboard supplies a temporary catalog copy.
class MasterSubjectDialog : public QDialog {
private:
    // Share the catalog supplied by the caller; openCatalogDialog() supplies an editable copy.
    vector<MasterSubject>& catalog;
    QTableWidget* table;
    QLineEdit *codeInput, *unitsInput;
    QComboBox *yearCombo, *semesterCombo;

public:
    // Build year, semester, code, and units inputs plus a read-only curriculum table.
    // Add/Remove change the supplied catalog; Save accepts it for the caller to persist.
    // Changing year or semester refreshes the rows. Clicking a row fills code and units
    // so an older unassigned subject can be assigned using Add.
    MasterSubjectDialog(vector<MasterSubject>& cat, QWidget* parent = nullptr, int semester = 1, int year = 1)
        : QDialog(parent), catalog(cat) {
        setWindowTitle("Curriculum by Year and Semester"); setMinimumSize(820, 540);
        auto* layout = new QVBoxLayout(this);
        auto* info = new QLabel("Choose a year level and semester, then add course codes and credit units. To assign an older unassigned subject, select its row and add it to the chosen year.", this);
        info->setWordWrap(true); layout->addWidget(info);
        auto* form = new QFormLayout;
        yearCombo = makeYearCombo(this, year); yearCombo->setObjectName("curriculumYearSelector");
        semesterCombo = makeSemesterCombo(this, semester); semesterCombo->setObjectName("curriculumSemesterSelector");
        codeInput = new QLineEdit(this); codeInput->setObjectName("curriculumCourseCode"); codeInput->setPlaceholderText("Course Code (e.g. CS101)");
        unitsInput = new QLineEdit(this); unitsInput->setObjectName("curriculumUnits"); unitsInput->setPlaceholderText("Units (e.g. 3)");
        unitsInput->setValidator(new QIntValidator(1, numeric_limits<int>::max(), this));
        form->addRow("Year Level:", yearCombo); form->addRow("Semester:", semesterCombo);
        form->addRow("Course Code:", codeInput); form->addRow("Units:", unitsInput); layout->addLayout(form);
        auto* actions = new QHBoxLayout;
        auto* addBtn = makeButton("Add to Curriculum", this, "#2ed573"); addBtn->setObjectName("curriculumAddButton");
        auto* delBtn = makeButton("Remove Selected", this, "#ff4757", "#fff"); delBtn->setObjectName("curriculumRemoveButton");
        actions->addWidget(addBtn); actions->addWidget(delBtn); layout->addLayout(actions);
        table = new QTableWidget(this); table->setObjectName("curriculumTable");
        prepareTable(table, {"Year Level", "Semester", "Course Code", "Units"}, true);
        table->setSelectionBehavior(QAbstractItemView::SelectRows); layout->addWidget(table);
        auto* saveBtn = addDialogButtons(this, layout, "Save Curriculum");
        connect(addBtn, &QPushButton::clicked, this, &MasterSubjectDialog::handleAdd);
        connect(delBtn, &QPushButton::clicked, this, &MasterSubjectDialog::handleDelete);
        connect(saveBtn, &QPushButton::clicked, this, &QDialog::accept);
        // Changing either selector rebuilds the filtered view without moving subjects between
        // years.
        connect(yearCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { refreshTable(); });
        connect(semesterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { refreshTable(); });
        // Copy the clicked row's code and units into the form; the selected year/semester still
        // control Add.
        connect(table, &QTableWidget::cellClicked, this, [this](int row, int) {
            codeInput->setText(table->item(row, 2)->text()); unitsInput->setText(table->item(row, 3)->text());
        });
        refreshTable();
    }

private:
    // Check code and positive units, then add to the selected year and semester.
    // Reject a duplicate {year, semester, code}. If an old year-0 entry has the same
    // semester and code, assign that entry to this year and update its units instead.
    // Otherwise append a new subject. Clear the inputs and refresh; saving is the caller's job.
    void handleAdd() {
        string code = codeInput->text().trimmed().toStdString(); int units;
        if (code.empty() || !Storage::integer(unitsInput->text().toStdString(), units)) {
            QMessageBox::warning(this, "Input Error", "Provide a course code and complete positive units."); return;
        }
        const int year = yearCombo->currentData().toInt(), semester = semesterCombo->currentData().toInt();
        for (const auto& subject : catalog) if (subject.code == code && subject.semester == semester && subject.year == year) {
            QMessageBox::warning(this, "Duplicate", "Subject code already exists in this year and semester."); return;
        }
        // Find an old unassigned entry to reuse rather than leave a duplicate behind.
        auto legacy = find_if(catalog.begin(), catalog.end(), [&](const MasterSubject& subject) {
            return subject.code == code && subject.semester == semester && subject.year == 0;
        });
        if (legacy != catalog.end()) *legacy = {code, units, semester, year};
        else catalog.push_back({code, units, semester, year});
        codeInput->clear(); unitsInput->clear(); refreshTable();
    }
    // Remove the selected table entry by its actual year, semester, and code.
    // The table's hidden year data distinguishes a displayed unassigned subject from
    // an assigned one. Change the supplied catalog and refresh; no file is written here.
    void handleDelete() {
        int row = table->currentRow(); if (row < 0) return;
        const string code = table->item(row, 2)->text().toStdString();
        const int year = table->item(row, 0)->data(Qt::UserRole).toInt(), semester = semesterCombo->currentData().toInt();
        catalog.erase(remove_if(catalog.begin(), catalog.end(), [&](const MasterSubject& subject) {
            return subject.code == code && subject.semester == semester && subject.year == year;
        }), catalog.end()); refreshTable();
    }
    // Rebuild rows for the selected year and semester, including applicable old subjects.
    // Keep the real subject year in hidden cell data and show its readable label.
    // Each cell is read-only; Add and Remove are the ways to change entries.
    void refreshTable() {
        table->setRowCount(0);
        for (const auto& subject : curriculumForYear(catalog, yearCombo->currentData().toInt())) {
            if (subject.semester != semesterCombo->currentData().toInt()) continue;
            int row = table->rowCount(); table->insertRow(row);
            auto* year = readOnlyItem(yearText(subject.year)); year->setData(Qt::UserRole, subject.year);
            table->setItem(row, 0, year); table->setItem(row, 1, readOnlyItem(semesterText(subject.semester)));
            table->setItem(row, 2, readOnlyItem(QString::fromStdString(subject.code)));
            table->setItem(row, 3, readOnlyItem(QString::number(subject.units)));
        }
    }
};

// Collect student identity and an existing class assignment for registration or editing.
class StudentFormDialog : public QDialog {
private:
    QLineEdit *idInput, *nameInput;
    QComboBox *programInput, *yearInput, *sectionInput;
    QLabel* groupPreview;
    // Keep a cleaned, duplicate-free copy of the known groups offered by this form.
    vector<ClassGroup> availableGroups;

    // Show the chosen valid class code, or explain which choices or class creation are still
    // needed.
    void refreshGroupPreview() {
        const QString code = getGroup();
        groupPreview->setText(code.isEmpty() ? (availableGroups.empty() ? "Create a class group first" : "Choose program, year level and section") : code);
    }
    // Refill section choices for the selected program and year.
    // Block section-change signals while rebuilding, collect unique sections, enable
    // the input only when choices exist, and update the class preview afterward.
    void refreshSections() {
        QSignalBlocker blocker(sectionInput);
        sectionInput->clear(); sectionInput->addItem("Select section", "");
        set<QString> sections;
        for (const auto& group : availableGroups)
            if (group.program == getProgram() && group.year == getYear()) sections.insert(QString::fromStdString(group.section));
        for (const auto& section : sections) sectionInput->addItem(section, section);
        sectionInput->setEnabled(!sections.empty()); refreshGroupPreview();
    }
    // Refill year choices for the selected program using known class groups.
    // Block signals while rebuilding and use 0 for 'Select year level'.
    // Then refresh sections. Existing legacy groups can offer years above 4;
    // creating a new class is separately limited to years 1 through 4.
    void refreshYears() {
        QSignalBlocker blocker(yearInput);
        yearInput->clear(); yearInput->addItem("Select year level", 0);
        set<int> years;
        for (const auto& group : availableGroups) if (group.program == getProgram()) years.insert(group.year);
        for (int year : years) yearInput->addItem(QString("Year %1").arg(year), year);
        yearInput->setEnabled(!years.empty()); refreshSections();
    }
public:
    // Build an Add/Edit Student form from the supplied known class groups.
    // Clean and deduplicate groups, then offer program -> year -> section choices.
    // In edit mode, fill the current identity and disable ID changes.
    // Restore the supplied class selections when they exist. Save checks ID, name,
    // and a real known group before accepting; the dashboard changes and saves the record.
    StudentFormDialog(QWidget* parent = nullptr, bool editMode = false, int id = 0, QString name = "", int year = 0, QString section = "", QString program = "", const vector<ClassGroup>& groups = {})
        : QDialog(parent) {
        set<QString> codes;
        // Ignore invalid or duplicate groups before using them as dropdown choices.
        for (const auto& group : groups) if (!group.code().isEmpty() && codes.insert(group.code()).second)
            availableGroups.push_back({normalizeProgram(QString::fromStdString(group.program)).toStdString(), group.year, normalizeSection(QString::fromStdString(group.section)).toStdString()});
        setWindowTitle(editMode ? "Edit Student Record" : "Add New Student"); setMinimumWidth(520);
        auto* layout = new QVBoxLayout(this); auto* form = new QFormLayout;
        idInput = new QLineEdit(this); idInput->setPlaceholderText("e.g. 1001");
        idInput->setValidator(new QIntValidator(1, MAX_STUDENT_ID, this)); idInput->setMaxLength(9);
        nameInput = new QLineEdit(this); nameInput->setPlaceholderText("First & Last Name");
        programInput = new QComboBox(this); programInput->setObjectName("studentProgram"); programInput->addItem("Select program", "");
        set<QString> programs;
        for (const auto& group : availableGroups) programs.insert(QString::fromStdString(group.program));
        for (const auto& value : programs) programInput->addItem(value, value);
        programInput->setEnabled(!programs.empty());
        yearInput = new QComboBox(this); yearInput->setObjectName("studentYear");
        sectionInput = new QComboBox(this); sectionInput->setObjectName("studentSection");
        groupPreview = new QLabel(this); groupPreview->setObjectName("classGroupPreview");
        groupPreview->setStyleSheet("color: #00d2ff; font-weight: bold;");
        // Keep the student ID fixed during editing so account and grade records retain the same
        // identity.
        if (editMode) { idInput->setText(QString::number(id)); idInput->setDisabled(true); nameInput->setText(name); }
        form->addRow("Student ID:", idInput); form->addRow("Full Name:", nameInput);
        form->addRow("Program:", programInput); form->addRow("Year Level:", yearInput); form->addRow("Section:", sectionInput);
        form->addRow("Class Group:", groupPreview); layout->addLayout(form);
        auto* help = new QLabel("Choose an existing class group. To add a new class, use Create Class Group on the roster.", this);
        help->setWordWrap(true); help->setStyleSheet("color: #aaa; font-size: 15px;"); layout->addWidget(help);
        // Changing program rebuilds years, changing year rebuilds sections, and changing section
        // updates preview.
        connect(programInput, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { refreshYears(); });
        connect(yearInput, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { refreshSections(); });
        connect(sectionInput, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] { refreshGroupPreview(); });
        refreshYears();
        int index = programInput->findData(normalizeProgram(program)); programInput->setCurrentIndex(index >= 0 ? index : 0);
        index = yearInput->findData(year); yearInput->setCurrentIndex(index >= 0 ? index : 0);
        index = sectionInput->findData(normalizeSection(section)); sectionInput->setCurrentIndex(index >= 0 ? index : 0);
        refreshGroupPreview();
        auto* saveBtn = addDialogButtons(this, layout, editMode ? "Update" : "Save Student");
        saveBtn->setEnabled(!availableGroups.empty());
        // Accept only valid identity fields and an existing class group; the caller checks
        // duplicate IDs when adding.
        connect(saveBtn, &QPushButton::clicked, this, [this] {
            if (!idInput->hasAcceptableInput() || nameInput->text().trimmed().isEmpty() || getGroup().isEmpty()) {
                QMessageBox::warning(this, "Input Error", "Enter a valid student ID and name, then choose an existing program, year level and section."); return;
            }
            accept();
        });
    }
    // Convert the entered ID text to an integer; read it after the form has passed validation.
    int getId() const { return idInput->text().toInt(); }
    // Return the name with surrounding whitespace removed.
    string getName() const { return nameInput->text().trimmed().toStdString(); }
    // Return the selected year from item data; 0 means the placeholder is selected.
    int getYear() const { return yearInput->currentData().toInt(); }
    // Return the selected program from item data; the placeholder contains empty text.
    string getProgram() const { return programInput->currentData().toString().toStdString(); }
    // Return the selected section from item data; the placeholder contains empty text.
    string getSection() const { return sectionInput->currentData().toString().toStdString(); }
    // Build the selected class code and confirm it exists in availableGroups.
    // Return empty text if the choices do not name a known group, preventing an
    // unlisted class from being invented just by combining dropdown values.
    QString getGroup() const {
        const QString code = classGroupCode(programInput->currentData().toString(), getYear(), sectionInput->currentData().toString());
        return any_of(availableGroups.begin(), availableGroups.end(), [&](const ClassGroup& group) { return group.code() == code; }) ? code : QString();
    }
};

// Collect the three parts of a new class group and preview its normalized code.
class ClassGroupDialog : public QDialog {
public:
    QLineEdit *programInput, *sectionInput;
    QComboBox* yearInput; QLabel* preview;
    // Build a Create Class Group form with program, section, and only years 1 through 4.
    // Update the preview whenever a field changes. Create checks the code is valid,
    // then accepts; MainWindow checks existence and saves the resulting group.
    ClassGroupDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Create Class Group"); setMinimumWidth(520);
        auto* layout = new QVBoxLayout(this); auto* form = new QFormLayout;
        programInput = new QLineEdit(this); programInput->setPlaceholderText("e.g. BSIS"); programInput->setMaxLength(16);
        yearInput = new QComboBox(this); yearInput->addItem("Select year level", 0);
        for (int year=1; year<=4; ++year) yearInput->addItem(yearText(year), year);
        sectionInput = new QLineEdit(this); sectionInput->setPlaceholderText("e.g. 04"); sectionInput->setMaxLength(8);
        preview = new QLabel(this); preview->setStyleSheet("color: #00d2ff; font-weight: bold;");
        form->addRow("Program:",programInput); form->addRow("Year Level:",yearInput); form->addRow("Section:",sectionInput); form->addRow("Class Group:",preview);
        layout->addLayout(form);
        // This local refresh action shows the cleaned class code, or asks the person to complete
        // the fields.
        auto refresh = [this] { const auto code = group().code(); preview->setText(code.isEmpty() ? "Complete all class fields" : code); };
        // Each input change runs the same preview action so its label follows the current
        // choices.
        connect(programInput,&QLineEdit::textChanged,this,[refresh] { refresh(); });
        connect(sectionInput,&QLineEdit::textChanged,this,[refresh] { refresh(); });
        connect(yearInput,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[refresh] { refresh(); }); refresh();
        auto* save = addDialogButtons(this,layout,"Create Class Group");
        // On Create, reject an invalid group code and leave the form open for correction.
        connect(save,&QPushButton::clicked,this,[this] {
            if (group().code().isEmpty()) { QMessageBox::warning(this,"Class Required","Enter a valid program, year level and section."); return; }
            accept();
        });
    }
    // Return a ClassGroup built from cleaned program/section text and the selected numeric year.
    ClassGroup group() const { return {normalizeProgram(programInput->text()).toStdString(),yearInput->currentData().toInt(),normalizeSection(sectionInput->text()).toStdString()}; }
};

// A read-only credits dialog shows the existing team names and the running application version.
class MeetTeamDialog : public QDialog {
public:
    // Build the app title, version, team credits, and Close button; this dialog changes no school
    // records.
    MeetTeamDialog(QWidget* parent = nullptr) : QDialog(parent) {
        setWindowTitle("Meet the Team"); setMinimumWidth(560);
        auto* layout = new QVBoxLayout(this); layout->setSpacing(18);
        auto* appTitle = new QLabel("Student Management System",this);
        appTitle->setObjectName("teamAppTitle"); appTitle->setWordWrap(true); appTitle->setAlignment(Qt::AlignCenter);
        appTitle->setStyleSheet("font-size: 30px; color: #00d2ff; font-weight: bold;"); layout->addWidget(appTitle);
        auto* teamTitle = new QLabel("Meet the Team",this);
        teamTitle->setObjectName("teamSubtitle"); teamTitle->setWordWrap(true); teamTitle->setAlignment(Qt::AlignCenter);
        teamTitle->setStyleSheet("font-size: 22px; font-weight: bold;"); layout->addWidget(teamTitle);
        auto* version = new QLabel(QString("Version %1").arg(QCoreApplication::applicationVersion()),this);
        version->setObjectName("teamVersion"); version->setAlignment(Qt::AlignCenter);
        version->setStyleSheet("font-size: 15px; color: #aaa;"); layout->addWidget(version);
        auto* developer = new QLabel("Leader, Designer, and Developer",this); developer->setStyleSheet("font-weight: bold; color: #a55eea;"); layout->addWidget(developer);
        layout->addWidget(new QLabel("Raphael Solis",this));
        auto* paper = new QLabel("Creation of paper",this); paper->setStyleSheet("font-weight: bold; color: #70a1ff;"); layout->addWidget(paper);
        auto* names = new QLabel("Alde, Keith\nBangcore, Joel\nResulta, Lloyd\nResulta, Ronald",this); names->setObjectName("paperMembers"); layout->addWidget(names);
        auto* close = makeButton("Close",this,"#33334d","#fff"); layout->addWidget(close); connect(close,&QPushButton::clicked,this,&QDialog::accept);
    }
};

// Edit a supplied student copy's marks and display its updated weighted averages immediately.
class GradeCalculatorDialog : public QDialog {
private:
    // Share the student supplied by the caller; MainWindow passes a copy until the dialog is
    // accepted.
    Student& student;
    // Read the curriculum to choose courses and their weights without editing it.
    const vector<MasterSubject>& catalog;
    QTableWidget* courseTable;
    QLabel* computedGwaLabel;
    // Keep the semester being edited so the same course code in another semester stays separate.
    int semester;

public:
    // Build the student's course table for their year and the requested term.
    // Midterm/final cells use PercentageDelegate for percentage entry; code, units,
    // and computed subject grades are read-only. Recalculate and display the averages.
    // Save first commits any visible cell editor, then accepts; MainWindow persists
    // the edited student copy. Closing without acceptance discards that copy's edits.
    GradeCalculatorDialog(Student& s, const vector<MasterSubject>& cat, QWidget* parent = nullptr, int term = 1)
        : QDialog(parent), student(s), catalog(cat), semester(term) {

        setWindowTitle("Grade Entry & Calculation — " + semesterText(semester)); setMinimumSize(900, 540);
        QVBoxLayout* layout = new QVBoxLayout(this);
        QLabel* info = new QLabel(QString("Entering Grades for: <b>%1</b> (ID: %2)<br>Class Group: %3<br>Double-click Midterm or Final Grade cells, enter a score (0–100, including decimals), and press Enter.<br>The cell shows its converted 1–5 grade. Clear the input for no grade.")
            .arg(QString::fromStdString(student.getName()).toHtmlEscaped()).arg(student.getId())
            .arg(student.getClassGroup().isEmpty() ? "Needs class assignment" : student.getClassGroup().toHtmlEscaped()), this);
        info->setAlignment(Qt::AlignCenter); info->setWordWrap(true); layout->addWidget(info);

        courseTable = new QTableWidget(this);
        prepareTable(courseTable, {"Course Code", "Units", "Midterm Grade", "Final Grade", "Subject Grade"});
        courseTable->setProperty("percentageGradeEntry", true);
        // Use the percentage delegate for editable cells so new 0-to-100 scores become 1-to-5
        // marks.
        courseTable->setItemDelegate(new Grading::PercentageDelegate(courseTable));
        layout->addWidget(courseTable);

        computedGwaLabel = new QLabel(this); computedGwaLabel->setStyleSheet("font-size: 18px; font-weight: bold; color: #00d2ff;");
        computedGwaLabel->setAlignment(Qt::AlignCenter); layout->addWidget(computedGwaLabel);

        auto* closeBtn = makeButton("Save & Recalculate GWA", this, "#00d2ff");
        layout->addWidget(closeBtn);

        // After a cell changes, update the student's marks through handleCellChanged().
        connect(courseTable, &QTableWidget::cellChanged, this, &GradeCalculatorDialog::handleCellChanged);
        // On Save, check and commit any still-open editor before accepting the dialog.
        // This captures the last typed score even when Enter was not pressed.
        connect(closeBtn, &QPushButton::clicked, this, [this] {
            QLineEdit* input = nullptr;
            for (auto* editor : courseTable->findChildren<QLineEdit*>("percentageGradeEditor"))
                if (editor->isVisible()) { input = editor; break; }
            if (input) {
                if (!Grading::PercentageDelegate::validInput(input)) {
                    Grading::PercentageDelegate::showInputError(input); input->setFocus(); return;
                }
                courseTable->itemDelegate()->setModelData(input, courseTable->model(), courseTable->currentIndex());
                courseTable->setFocus();
            }
            accept();
        });
        student.recalculateGWA(catalog, semester); refreshTable();
    }

private:
    // Process only midterm/final columns, whose text is already on the 1-to-5 scale.
    // Read both marks in the row. Invalid data shows a warning and restores its view.
    // If both are missing, erase the course entry; otherwise store the mark pair.
    // Recalculate the student's GWA and schedule a row refresh after Qt closes its editor.
    void handleCellChanged(int row, int col) {
        if (col != 2 && col != 3) return;
        auto codeItem = courseTable->item(row, 0); auto midItem = courseTable->item(row, 2); auto finalItem = courseTable->item(row, 3);
        if (!codeItem || !midItem || !finalItem) return;
        // Parse displayed marks: blank or 'N/A' means zero; other text must be a valid
        // saved-scale grade.
        auto parse = [](const QString& text, double& grade) {
            QString value = text.trimmed();
            if (value.isEmpty() || value == "N/A") { grade = 0; return true; }
            bool ok; grade = value.toDouble(&ok); return ok && Storage::grade(grade);
        };
        double mid, final;
        if (!parse(midItem->text(), mid) || !parse(finalItem->text(), final)) {
            QMessageBox::warning(this, "Invalid Grade", "Enter a score from 0 to 100, including decimals, in the editor; clear the input for no grade.");
            QTimer::singleShot(0, this, [this, row] { refreshRow(row); }); return;
        }
        string code = codeItem->text().toStdString();
        if (mid == 0 && final == 0) student.removeGrade(code, semester);
        else student.setTermGrades(code, mid, final, semester);
        student.recalculateGWA(catalog, semester);
        // Queue the visual update for the next event-loop turn so the active editor can finish
        // closing first.
        QTimer::singleShot(0, this, [this, row] { refreshRow(row); });
    }

    // Put the student's three cached averages into the summary label, formatting missing values
    // as 'N/A'.
    void updateGwaLabel() {
        computedGwaLabel->setText(QString("Midterm GWA: %1  |  Finals GWA: %2  |  Overall GWA: %3")
            .arg(fmtGwa(student.getMidtermGwa())).arg(fmtGwa(student.getFinalsGwa())).arg(fmtGwa(student.getGwa())));
    }

    // Refresh one existing row from the student's stored marks and update the GWA label.
    // Pause table change signals while writing text so this display update does not
    // call handleCellChanged() again. Restore the previous signal state afterward.
    void refreshRow(int row) {
        if (row < 0 || row >= courseTable->rowCount()) return;
        const auto text = gradeText(student.gradeFor(courseTable->item(row, 0)->text().toStdString(), semester));
        // Remember the previous signal setting, then stop notifications while replacing displayed
        // marks.
        const bool blocked = courseTable->blockSignals(true);
        courseTable->item(row, 2)->setText(text.midterm); courseTable->item(row, 3)->setText(text.finalGrade);
        courseTable->item(row, 4)->setText(text.subject);
        courseTable->blockSignals(blocked); updateGwaLabel();
    }

    // Build rows from the student's year-filtered curriculum for the editing semester.
    // Show recorded marks or 'N/A'; allow editing only of midterm and final cells.
    // Block edit signals during population, restore them, and update the average label.
    void refreshTable() {
        const bool blocked = courseTable->blockSignals(true);
        courseTable->setRowCount(0); int row = 0;
        for (const auto& sub : curriculumForYear(catalog, student.gradeYear())) {
            if (sub.semester != semester) continue;
            courseTable->insertRow(row);
            const auto text = gradeText(student.gradeFor(sub.code, semester));
            courseTable->setItem(row, 0, readOnlyItem(QString::fromStdString(sub.code)));
            courseTable->setItem(row, 1, readOnlyItem(QString::number(sub.units)));
            courseTable->setItem(row, 2, new QTableWidgetItem(text.midterm));
            courseTable->setItem(row, 3, new QTableWidgetItem(text.finalGrade));
            courseTable->setItem(row, 4, readOnlyItem(text.subject)); ++row;
        }
        courseTable->blockSignals(blocked); updateGwaLabel();
    }
};

// Show a student's report as read-only text and offer a separate plain-text export.
class ReportCardDialog : public QDialog {
private:
    const Student& student;
    string reportContent;
    int reportSemester;

public:
    // Build a report from the supplied student, catalog, and semester.
    // Use year-filtered courses, stored marks, academic status, and the student's
    // already-calculated averages. The normal dashboard caller supplies their current
    // year record. This dialog formats data; it does not recalculate or change marks.
    // Save exports the report text; Close dismisses the preview.
    ReportCardDialog(const Student& s, const vector<MasterSubject>& catalog, QWidget* parent = nullptr, int semester = 1)
        : QDialog(parent), student(s), reportSemester(semester) {

        setWindowTitle("Official Student Report Card — " + semesterText(semester)); setMinimumSize(840, 640);
        QVBoxLayout* layout = new QVBoxLayout(this);
        QTextEdit* reportText = new QTextEdit(this); reportText->setReadOnly(true);

        const string status = s.academicSummary(catalog, semester).status(true);

        // Compose reportContent using a text stream; fixed-width fields and a monospace font
        // align columns.
        stringstream ss;
        ss << "===============================================================\n"
           << "                OFFICIAL ACADEMIC REPORT CARD                  \n"
           << "===============================================================\n\n"
           << " Student ID   : " << s.getId() << "\n"
           << " Full Name    : " << s.getName() << "\n"
           << " Program      : " << (s.getProgram().empty() ? "Not set" : s.getProgram()) << "\n"
           << " Class Group  : " << (s.getClassGroup().isEmpty() ? "Needs class assignment" : s.getClassGroup().toStdString()) << "\n"
           << " Year         : " << (s.getYear() ? to_string(s.getYear()) : "Not set") << "\n"
           << " Section      : " << (s.getSection().empty() ? "Not set" : s.getSection()) << "\n"
           << " Semester     : " << semesterText(semester).toStdString() << "\n"
           << " Midterm GWA  : " << fmtGwa(s.getMidtermGwa()).toStdString() << "\n"
           << " Finals GWA   : " << fmtGwa(s.getFinalsGwa()).toStdString() << "\n"
           << " Overall GWA  : " << fmtGwa(s.getGwa()).toStdString() << "\n\n"
           << "---------------------------------------------------------------\n"
           << " COURSE CODE    UNITS    MIDTERM    FINALS    SUBJECT GRADE    \n"
           << "---------------------------------------------------------------\n";

        if (!s.academicSummary(catalog, semester).recorded) ss << " (No grades recorded for this semester)\n";
        // If no course result is recorded, show a message; otherwise print courses that have
        // stored mark entries.
        else {
            for (const auto& sub : curriculumForYear(catalog, s.gradeYear())) {
                if (sub.semester != semester) continue;
                auto found = s.getGrades().find({semester, sub.code});
                if (found != s.getGrades().end()) {
                    const auto text = gradeText(found->second);
                    ss << " " << left << setw(15) << sub.code << setw(9) << sub.units
                       << setw(11) << text.midterm.toStdString() << setw(10) << text.finalGrade.toStdString()
                       << setw(14) << text.subject.toStdString() << "\n";
                }
            }
        }

        ss << "---------------------------------------------------------------\n\n"
           << " Academic Status : " << status << "\n"
           << "===============================================================\n";

        reportContent = ss.str();
        reportText->setPlainText(QString::fromStdString(reportContent));
        reportText->setStyleSheet("font-family: 'Courier New', monospace; font-size: 17px; background: #0a0a0f; color: #30d158;");

        QHBoxLayout* btnLayout = new QHBoxLayout();
        auto* saveFileBtn = makeButton("Save Report Card (.txt)", this, "#2ed573");
        auto* closeBtn = makeButton("Close", this, "#33334d", "#fff");
        btnLayout->addWidget(saveFileBtn); btnLayout->addWidget(closeBtn);

        layout->addWidget(reportText); layout->addLayout(btnLayout);
        // Link Save to the file exporter and Close to accepting the preview dialog.
        connect(saveFileBtn, &QPushButton::clicked, this, &ReportCardDialog::handleSaveToFile);
        connect(closeBtn, &QPushButton::clicked, this, &QDialog::accept);
    }

private:
    // Export reportContent in the current data folder as ReportCard_ID_SemesterN.txt.
    // The filename separates semesters, but contains no year; a later export for the
    // same student/semester replaces that export through Storage's protected writer.
    // Show success only when the complete file save succeeds.
    void handleSaveToFile() {
        string filename = "ReportCard_" + to_string(student.getId()) + "_Semester" + to_string(reportSemester) + ".txt";
        if (!Storage::exportFile(filename, QByteArray::fromStdString(reportContent))) { Storage::report(this); return; }
        QMessageBox::information(this, "File Saved", QString("Report card saved to:\n%1").arg(QString::fromStdString(filename)));
    }
};

// MainWindow joins the app's data and dashboard controls after a successful login.
// Its role decides which controls exist; action handlers also check permissions.
// Changes are saved through helper methods that restore the last good copy on failure.
class MainWindow : public QMainWindow {
private:
    // The authenticated role and account identity determine which dashboard actions are
    // available.
    UserRole currentRole;
    int currentStudentId;
    string currentProfUser;

    // Working copies of students, subjects, staff accounts, personal tasks, and the shared
    // notice.
    vector<Student> studentList;
    vector<MasterSubject> masterCatalog;
    map<string, ProfAccount> profAccounts;
    vector<TodoItem> todoList;
    string classAnnouncement;
    // Keep known class groups and their last-saved copy; activeClassGroup selects the roster
    // filter.
    vector<ClassGroup> classGroups, savedClassGroups;
    QString activeClassGroup;
    // Last-saved snapshots let a failed edit/save restore the working data and its screen.
    vector<Student> savedStudents;
    vector<MasterSubject> savedCatalog;
    map<string, ProfAccount> savedProfessors;
    vector<TodoItem> savedTasks;
    string savedAnnouncement;

    // These record filenames are relative to main()'s data folder, even when their contents are
    // JSON.
    const string filename = "students.txt", catalogFilename = "curriculum.txt", announcementFilename = "announcement.txt", profFilename = "professors.txt", headFilename = "head_admin.txt";
    // The logged-in account's personal task filename is chosen by Storage::taskFilename().
    string todoFilename;
    // Known class groups have their own version-4 JSON document.
    const string groupsFilename = "class_groups.txt";

    // The page stack shows teachers (0), roster/personal grades (1), or tasks (2).
    QStackedWidget* mainStack;
    // Pointers connect the controls built by setupUI() to the handlers that use them.
    QLineEdit* todoInput = nullptr;
    QLineEdit* rosterSearchInput = nullptr;
    QComboBox* classGroupCombo = nullptr;
    // The student's grade-year dropdown controls viewing only; it does not move their class
    // assignment.
    QComboBox* studentYearCombo = nullptr;
    // Keep the year currently being viewed on the student dashboard, initially year 1.
    int activeStudentYear = 1;
    // Staff choose the year whose classes and curriculum they want to work with.
    // This filters the dashboard and does not change any student's assigned year.
    QComboBox* staffYearCombo = nullptr;
    int activeStaffYear = 1;
    // The dashboard semester and the task semester are separate choices with different purposes.
    QComboBox *semesterCombo = nullptr, *todoSemesterCombo = nullptr, *todoCourseCombo = nullptr, *todoSortCombo = nullptr;
    QDateEdit* todoDueDateInput;
    // The active dashboard semester chooses displayed GWA, grade entry, exports, and reports.
    int activeSemester = 1;
    // Separate tables display the staff roster, student roster, and student's own course marks.
    QTableWidget *tableWidget = nullptr, *teacherTableWidget = nullptr, *studentGradesTable = nullptr;
    // Labels display counts, the shared notice, identity, rank, and academic status.
    QLabel *statsLabel, *teacherStatsLabel, *announcementBanner, *studentCardInfo, *studentCardRank, *studentCardStatus;
    // Display personal tasks; each row remembers the original todoList index for correct
    // deletion.
    QTableWidget* todoListWidget;
    // Choose the priority saved with a new task.
    QComboBox* todoPriorityCombo;

public:
    // Open the dashboard for the authenticated role and identity.
    // Start with a 1280 by 800 window, bounded to the screen's available space.
    // Choose this account's task file, load needed records, and stop with an error
    // if a load fails. Merge known class groups, calculate GWA, and keep rollback copies.
    // Build the controls, apply the theme and optional external tablet layout, then fill views.
    MainWindow(UserRole role, int studentId = -1, const string& profUser = "", QWidget *parent = nullptr)
        : QMainWindow(parent), currentRole(role), currentStudentId(studentId), currentProfUser(profUser) {

        setWindowTitle(QString("Student Management System · Version %1").arg(QCoreApplication::applicationVersion()));
        // Use the existing requested window size, reduced only when the available screen is
        // smaller.
        resize(QSize(1280, 800).boundedTo(QApplication::primaryScreen()->availableGeometry().size()));
        todoFilename = Storage::taskFilename(currentRole, currentStudentId, currentProfUser);

        // Load subjects, students, tasks, and notice; only staff sessions load professor/group
        // files.
        if (!FileIO::loadCatalog(catalogFilename, masterCatalog) || !FileIO::loadStudents(filename, studentList)
            || (currentRole != ROLE_STUDENT && !FileIO::loadProfessors(profFilename, profAccounts))
            || (currentRole != ROLE_STUDENT && !FileIO::loadClassGroups(groupsFilename, classGroups))
            || !FileIO::loadTasks(todoFilename, todoList) || !loadAnnouncement()) throw runtime_error(Storage::lastError.toStdString());
        syncClassGroups(); savedClassGroups = classGroups;
        recalculateGrades();
        // Remember the loaded working state before user edits so failed saves can be undone.
        savedStudents = studentList; savedCatalog = masterCatalog;
        if (currentRole != ROLE_STUDENT) savedProfessors = profAccounts;
        savedTasks = todoList; savedAnnouncement = classAnnouncement;
        setupUI(); applyGlobalDarkTheme();
#ifdef V3_TABLET_UI
        // Let the separately supplied tablet library adapt this window when tablet support is
        // enabled.
        Tablet::prepareMain(this);
#endif
#ifdef V4_PHONE_UI
        // Phones need the page's full width. Put navigation behind a Menu button
        // and let wide tables scroll, instead of squeezing them beside the sidebar.
        auto* phoneLayout = qobject_cast<QBoxLayout*>(centralWidget()->layout());
        auto* navigation = findChild<QWidget*>("navigationPanel");
        auto* sidebarScroll = findChild<QScrollArea*>("sidebarScroll");
        if (phoneLayout && navigation) {
            phoneLayout->setDirection(QBoxLayout::TopToBottom);
            navigation->setMinimumWidth(0); navigation->setMaximumWidth(QWIDGETSIZE_MAX);
            navigation->setMaximumHeight(min(320, QApplication::primaryScreen()->availableGeometry().height() / 2));
            if (sidebarScroll) {
                sidebarScroll->setMinimumWidth(0); sidebarScroll->setMaximumWidth(QWIDGETSIZE_MAX);
            }
            // A scrollable page keeps every table column and form control reachable.
            phoneLayout->removeWidget(mainStack);
            auto* content = new QScrollArea(centralWidget()); content->setObjectName("phoneContentScroll");
            content->setWidgetResizable(true); content->setFrameShape(QFrame::NoFrame);
            content->setWidget(mainStack); phoneLayout->addWidget(content, 1);
            auto* menu = new QPushButton("Menu", centralWidget()); menu->setObjectName("phoneMenuButton");
            menu->setCheckable(true); styleBtn(menu, "#252538", "#fff", 10);
            phoneLayout->insertWidget(0, menu); navigation->hide();
            // Show navigation when requested; choosing another page closes it again.
            connect(menu, &QPushButton::toggled, navigation, &QWidget::setVisible);
            connect(mainStack, &QStackedWidget::currentChanged, menu, [menu] { menu->setChecked(false); });
        }
#endif
        refreshTeacherTable(); refreshTable(); refreshTodoList();
    }

private:
    // Recalculate every student's current-year GWA for activeSemester; update memory without
    // saving a file.
    void recalculateGrades() { for (auto& student : studentList) student.recalculateGWA(masterCatalog, activeSemester); }

    // Add valid class assignments found in student records to the known group list.
    // Avoid duplicates and sort the groups by display code. This supports older
    // students whose class exists in their record but not yet in class_groups.txt.
    // The function changes memory only; saving groups is a separate step.
    void syncClassGroups() {
        set<QString> known; for (const auto& group : classGroups) known.insert(group.code());
        for (const auto& student : studentList) if (!student.getClassGroup().isEmpty() && known.insert(student.getClassGroup()).second)
            classGroups.push_back({student.getProgram(),student.getYear(),student.getSection()});
        // Sort groups by code so class choices appear in a predictable order.
        sort(classGroups.begin(),classGroups.end(),[](const ClassGroup& a,const ClassGroup& b) { return a.code()<b.code(); });
    }
    // Rebuild the class dropdown, keeping preferred or the previous active choice if possible.
    // Show only groups in the chosen staff year, including unassigned students in that year.
    // After creating or moving a student to another group, preferred also selects its year.
    // Block signals while rebuilding so a display update does not trigger another refresh.
    // Show a creation prompt when the selected year has no groups or unassigned students.
    void refreshClassGroups(const QString& preferred = QString()) {
        if (!classGroupCombo) return;
        syncClassGroups(); QSignalBlocker block(classGroupCombo);
        const QString choice = preferred.isEmpty() ? activeClassGroup : preferred;
        if (!preferred.isEmpty()) {
            for (const auto& group : classGroups) if (group.code() == preferred && group.year <= 4) {
                activeStaffYear = group.year;
                if (staffYearCombo) {
                    QSignalBlocker yearBlock(staffYearCombo);
                    staffYearCombo->setCurrentIndex(staffYearCombo->findData(activeStaffYear));
                }
                break;
            }
        }
        classGroupCombo->clear();
        for (const auto& group : classGroups) if (group.year == activeStaffYear)
            classGroupCombo->addItem(group.code(),group.code());
        // Use the internal '__legacy__' value to select students without a valid class
        // assignment.
        if (any_of(studentList.begin(),studentList.end(),[this](const Student& student) {
            return student.getClassGroup().isEmpty() && student.gradeYear() == activeStaffYear;
        }))
            classGroupCombo->addItem("Needs class assignment", "__legacy__");
        if (classGroupCombo->count()==0) classGroupCombo->addItem("Create a class group",QString());
        int index = classGroupCombo->findData(choice); classGroupCombo->setCurrentIndex(index>=0 ? index : 0);
        activeClassGroup = classGroupCombo->currentData().toString();
    }
    // Return whether a student belongs in the selected roster.
    // First require the selected year. The special legacy choice includes unassigned
    // students in that year; a real choice must match their full class code.
    // An empty class choice includes no students.
    bool inSelectedClass(const Student& student) const {
        if (student.gradeYear() != activeStaffYear) return false;
        return activeClassGroup == "__legacy__" ? student.getClassGroup().isEmpty()
            : !activeClassGroup.isEmpty() && student.getClassGroup()==activeClassGroup;
    }
    // Save classGroups and remember a new snapshot on success.
    // On failure, restore savedClassGroups, refresh the choices, and show the storage error.
    // Return true only when the proposed group list was saved.
    bool saveClassGroups() {
        if (FileIO::saveClassGroups(groupsFilename,classGroups)) { savedClassGroups=classGroups; return true; }
        classGroups=savedClassGroups; refreshClassGroups(); return Storage::report(this);
    }
    // Use the staff's Year Level selection for curriculum and subject counts.
    // It still works when that year has no class group yet.
    int selectedClassYear() const { return activeStaffYear; }
    // Ensure a valid group exists before using it for an assignment.
    // Accept an existing group, including a legacy year 5 or 6 group. For a new group,
    // reject years above 4, append it, and save. Return whether the group is usable.
    bool ensureClassGroup(const ClassGroup& group) {
        if (group.code().isEmpty()) return false;
        if (any_of(classGroups.begin(),classGroups.end(),[&](const ClassGroup& existing) { return existing.code()==group.code(); })) return true;
        if (group.year > 4) return false;
        classGroups.push_back(group); return saveClassGroups();
    }
    // For staff only, open the new-class form and save an accepted valid group.
    // Select the resulting group, clear roster search, and refresh the class roster.
    // Cancellation or a failed group save stops the action.
    void openClassGroupDialog() {
        if (currentRole==ROLE_STUDENT) return;
        ClassGroupDialog dialog(this);
        if (dialog.exec()!=QDialog::Accepted || !ensureClassGroup(dialog.group())) return;
        refreshClassGroups(dialog.group().code()); if (rosterSearchInput) rosterSearchInput->clear(); refreshTable();
    }

    // Build the dashboard's navigation, role-specific controls, and three pages.
    // Create widgets and layouts, then connect clicks and selector changes to handlers.
    // Staff choose Year Level, then Academic Semester, and get matching class/roster tools.
    // Students use those choices for their own current or historical grade view.
    // Everyone gets personal tasks, credits, and logout. Populate labels later using
    // refresh methods; making a button here does not execute its action.
    void setupUI() {
        // Arrange a navigation panel on the left and the current dashboard page on the right.
        QWidget* centralWidget = new QWidget(this); setCentralWidget(centralWidget);
        QHBoxLayout* rootLayout = new QHBoxLayout(centralWidget); rootLayout->setContentsMargins(0, 0, 0, 0); rootLayout->setSpacing(0);

        // Choose the greeting from Head's role name, the professor username, or the student's
        // record.
        string displayUser = "Staff";
        if (currentRole == ROLE_HEAD) displayUser = "Head Admin";
        else if (currentRole == ROLE_PROFESSOR) displayUser = currentProfUser;
        else if (currentRole == ROLE_STUDENT) {
            for (const auto& s : studentList) if (s.getId() == currentStudentId) { displayUser = s.getName(); break; }
        }

        // Build the existing 320-wide sidebar with vertically stacked navigation controls.
        QFrame* sidebar = new QFrame(this); sidebar->setObjectName("desktopSidebar"); sidebar->setFixedWidth(320); sidebar->setStyleSheet("background-color: #1a1a24; border-right: 1px solid #2a2a3c;");
        QVBoxLayout* sidebarLayout = new QVBoxLayout(sidebar); sidebarLayout->setContentsMargins(15, 20, 15, 20); sidebarLayout->setSpacing(10);

        // Escape the account name before placing it in the welcome label's formatted text.
        QLabel* appTitle = new QLabel(QString("Welcome,\n%1!").arg(QString::fromStdString(displayUser).toHtmlEscaped()), sidebar);
        appTitle->setStyleSheet("font-size: 22px; font-weight: bold; color: #00d2ff;"); appTitle->setWordWrap(true); sidebarLayout->addWidget(appTitle);

        QString roleText = (currentRole == ROLE_HEAD) ? "Role: Head Admin" : ((currentRole == ROLE_PROFESSOR) ? "Role: Professor" : "Role: Student (" + QString::number(currentStudentId) + ")");
        QLabel* roleBadge = new QLabel(roleText, sidebar); roleBadge->setStyleSheet("color: #aaa; font-size: 16px; margin-bottom: 15px;");
        sidebarLayout->addWidget(roleBadge);
        // Students start grade viewing on their assigned year, capped at the fourth choice.
        // The year control changes the view; it does not edit the student record.
        if (currentRole == ROLE_STUDENT) {
            for (const auto& student : studentList) if (student.getId() == currentStudentId) {
                activeStudentYear = min(4, student.gradeYear()); break;
            }
            sidebarLayout->addWidget(new QLabel("Year Level", sidebar));
            studentYearCombo = new QComboBox(sidebar); studentYearCombo->setObjectName("studentGradeYearSelector");
            studentYearCombo->addItem("1st Year", 1); studentYearCombo->addItem("2nd Year", 2);
            studentYearCombo->addItem("3rd Year", 3); studentYearCombo->addItem("4th Year", 4);
            studentYearCombo->setCurrentIndex(activeStudentYear - 1); sidebarLayout->addWidget(studentYearCombo);
            // On a grade-year change, store the selected number and refresh the student's
            // historical/current view.
            connect(studentYearCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] {
                activeStudentYear = studentYearCombo->currentData().toInt(); refreshTable();
            });
        } else {
            // Give Head and professors the same four year choices above Academic Semester.
            // Start on the first available class year's choice, or year 1 when none exist.
            for (const auto& group : classGroups) if (group.year >= 1 && group.year <= 4) {
                activeStaffYear = group.year; break;
            }
            sidebarLayout->addWidget(new QLabel("Year Level", sidebar));
            staffYearCombo = makeYearCombo(sidebar, activeStaffYear);
            staffYearCombo->setObjectName("staffGradeYearSelector");
            sidebarLayout->addWidget(staffYearCombo);
            // Changing the year refills the matching classes and clears the old search.
            // The next grade, report, or export action then uses a student from this year.
            connect(staffYearCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] {
                activeStaffYear = staffYearCombo->currentData().toInt();
                refreshClassGroups();
                if (rosterSearchInput) rosterSearchInput->clear();
                refreshTable();
            });
        }
        sidebarLayout->addWidget(new QLabel("Academic Semester", sidebar));
        semesterCombo = makeSemesterCombo(sidebar); semesterCombo->setObjectName("semesterSelector");
        sidebarLayout->addWidget(semesterCombo);
        // On a dashboard-semester change, recalculate current-year averages and refresh the
        // visible grades.
        connect(semesterCombo, QOverload<int>::of(&QComboBox::currentIndexChanged), this, [this] {
            activeSemester = semesterCombo->currentData().toInt();
            recalculateGrades(); refreshTable();
        });

        QPushButton *btnTeacherRoster = nullptr, *btnStudentRoster = nullptr;
        // Create the shared Tasks and Logout controls, keeping their existing colors and spacing.
        QPushButton* btnTodo = new QPushButton("📝 To-Do List", sidebar);
        auto* btnLogout = makeButton("Logout", sidebar, "#ff4757", "#fff", 10);
        styleBtn(btnTodo, "#252538", "#fff", 10);

        // Head navigation includes teacher accounts, student roster, curriculum, and Head
        // security settings.
        if (currentRole == ROLE_HEAD) {
            btnTeacherRoster = new QPushButton("Teacher Roster", sidebar); styleBtn(btnTeacherRoster, "#252538", "#00d2ff", 10); sidebarLayout->addWidget(btnTeacherRoster);
            btnStudentRoster = new QPushButton("Student Roster", sidebar); styleBtn(btnStudentRoster, "#252538", "#70a1ff", 10); sidebarLayout->addWidget(btnStudentRoster);

            auto* btnCurriculum = makeButton("Curriculum Manager", sidebar, "#252538", "#fff", 10); sidebarLayout->addWidget(btnCurriculum);
            auto* btnHeadPass = makeButton("Change Head Password", sidebar, "#252538", "#a55eea", 10); sidebarLayout->addWidget(btnHeadPass);

            // Connect Head's curriculum and security buttons to their separate dialog handlers.
            connect(btnCurriculum, &QPushButton::clicked, this, &MainWindow::openCatalogDialog);
            connect(btnHeadPass, &QPushButton::clicked, this, &MainWindow::handleChangeHeadPassword);
        // Professor navigation provides student, grade, curriculum, report, export, and
        // own-security actions.
        } else if (currentRole == ROLE_PROFESSOR) {
            btnStudentRoster = new QPushButton("Student Roster", sidebar); styleBtn(btnStudentRoster, "#252538", "#00d2ff", 10); sidebarLayout->addWidget(btnStudentRoster);

            auto* btnCurriculum = makeButton("Curriculum Manager", sidebar, "#252538", "#fff", 10); sidebarLayout->addWidget(btnCurriculum);
            auto* btnGrades = makeButton("Enter / Compute Grades", sidebar, "#252538", "#a55eea", 10); sidebarLayout->addWidget(btnGrades);
            auto* btnReport = makeButton("Generate Report Card", sidebar, "#252538", "#ffa801", 10); sidebarLayout->addWidget(btnReport);
            auto* btnResetStudentPass = makeButton("Reset Student Password", sidebar, "#252538", "#e1b12c", 10); sidebarLayout->addWidget(btnResetStudentPass);
            auto* btnProfPass = makeButton("Change My Password", sidebar, "#252538", "#70a1ff", 10); sidebarLayout->addWidget(btnProfPass);
            auto* btnExportCsv = makeButton("Export Class Roster (.csv)", sidebar, "#252538", "#2ed573", 10); sidebarLayout->addWidget(btnExportCsv);

            connect(btnCurriculum, &QPushButton::clicked, this, &MainWindow::openCatalogDialog);
            connect(btnGrades, &QPushButton::clicked, this, &MainWindow::openGradeCalculator);
            connect(btnReport, &QPushButton::clicked, this, &MainWindow::generateReportCard);
            connect(btnResetStudentPass, &QPushButton::clicked, this, &MainWindow::handleResetStudentPassword);
            connect(btnProfPass, &QPushButton::clicked, this, &MainWindow::handleChangeProfPassword);
            connect(btnExportCsv, &QPushButton::clicked, this, &MainWindow::handleExportCSV);
        // Student navigation provides View Grades and the student's own official report.
        } else if (currentRole == ROLE_STUDENT) {
            auto* viewGrades = makeButton("View Grades", sidebar, "#252538", "#fff", 10);
            viewGrades->setObjectName("studentViewGradesButton"); sidebarLayout->addWidget(viewGrades);
            // View Grades opens page 1 and refreshes it using the chosen grade year and dashboard
            // semester.
            connect(viewGrades, &QPushButton::clicked, this, [this] { mainStack->setCurrentIndex(1); refreshTable(); });
            auto* btnReport = makeButton("Generate Official Report Card", sidebar, "#252538", "#ffa801", 10); sidebarLayout->addWidget(btnReport);
            connect(btnReport, &QPushButton::clicked, this, &MainWindow::generateStudentOwnReportCard);
        }

        sidebarLayout->addWidget(btnTodo); sidebarLayout->addStretch();

        // Keep page positions consistent: teachers 0, roster or personal grades 1, personal tasks
        // 2.
        mainStack = new QStackedWidget(this); mainStack->setObjectName("dashboardPages");

        // Only Head gets the teacher-management page and its account creation/reset/deletion
        // controls.
        if (currentRole == ROLE_HEAD) {
            QWidget* pageTeacher = new QWidget(this); QVBoxLayout* teacherLayout = new QVBoxLayout(pageTeacher); teacherLayout->setContentsMargins(15, 15, 15, 15);
            QLabel* teacherTitle = new QLabel("Teacher Management Dashboard", pageTeacher); teacherTitle->setStyleSheet("font-size: 26px; font-weight: bold; color: #00d2ff;");
            teacherTitle->setAlignment(Qt::AlignCenter); teacherTitle->setWordWrap(true); teacherLayout->addWidget(teacherTitle);

            QHBoxLayout* teacherToolbar = new QHBoxLayout();
            auto* addProfBtn = makeButton("Add Professor Account", pageTeacher, "#00d2ff");
            auto* resetProfPassBtn = makeButton("Reset Teacher Password", pageTeacher, "#2e86de", "#fff");
            auto* delProfBtn = makeButton("Delete Selected Teacher", pageTeacher, "#ff4757", "#fff");
            teacherToolbar->addWidget(addProfBtn); teacherToolbar->addWidget(resetProfPassBtn); teacherToolbar->addWidget(delProfBtn);
            teacherLayout->addLayout(teacherToolbar);

            QHBoxLayout* teacherSearchLayout = new QHBoxLayout();
            QLabel* tSearchLabel = new QLabel("Filter:", pageTeacher); auto* teacherSearchInput = new QLineEdit(pageTeacher); teacherSearchInput->setPlaceholderText("Search Teacher Username...");
            teacherSearchLayout->addWidget(tSearchLabel); teacherSearchLayout->addWidget(teacherSearchInput); teacherLayout->addLayout(teacherSearchLayout);

            teacherTableWidget = new QTableWidget(pageTeacher);
            prepareTable(teacherTableWidget, {"Username", "First Login Pending", "Security Question Set"}, true);
            teacherTableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
            teacherLayout->addWidget(teacherTableWidget);

            teacherStatsLabel = new QLabel(pageTeacher); teacherStatsLabel->setStyleSheet("font-weight: bold; color: #aaa;"); teacherLayout->addWidget(teacherStatsLabel);

            connect(addProfBtn, &QPushButton::clicked, this, &MainWindow::openAddProfDialog);
            connect(resetProfPassBtn, &QPushButton::clicked, this, &MainWindow::handleResetProfPassword);
            connect(delProfBtn, &QPushButton::clicked, this, &MainWindow::handleDeleteProf);
            // Typing in teacher search refills the visible rows using that username filter.
            connect(teacherSearchInput, &QLineEdit::textChanged, [this](const QString& text){ refreshTeacherTable(text); });

            mainStack->addWidget(pageTeacher);

        // Other roles get a blank page 0 so page 1 and page 2 keep the same navigation indexes.
        } else mainStack->addWidget(new QWidget(this));

        // Build page 1 with the shared notice and either a staff roster or a student's academic
        // view.
        QWidget* pageRoster = new QWidget(this); QVBoxLayout* rosterLayout = new QVBoxLayout(pageRoster); rosterLayout->setContentsMargins(15, 15, 15, 15);
        QLabel* pageTitle = new QLabel((currentRole == ROLE_HEAD || currentRole == ROLE_PROFESSOR) ? "Student Management Dashboard" : "My Academic Profile", pageRoster);
        pageTitle->setStyleSheet("font-size: 26px; font-weight: bold; color: #00d2ff;"); pageTitle->setAlignment(Qt::AlignCenter); pageTitle->setWordWrap(true); rosterLayout->addWidget(pageTitle);

        // Show announcement text plainly; staff get a Post Notice action to edit the shared
        // notice.
        QFrame* noticeFrame = new QFrame(pageRoster); noticeFrame->setStyleSheet("background-color: #1e1e2d; border: 1px solid #70a1ff; border-radius: 6px; padding: 6px;");
        QHBoxLayout* noticeLayout = new QHBoxLayout(noticeFrame);
        announcementBanner = new QLabel(noticeFrame); announcementBanner->setTextFormat(Qt::PlainText); announcementBanner->setWordWrap(true); announcementBanner->setStyleSheet("font-size: 17px; color: #70a1ff; font-weight: bold;"); noticeLayout->addWidget(announcementBanner, 1);

        if (currentRole == ROLE_HEAD || currentRole == ROLE_PROFESSOR) {
            auto* editNoticeBtn = makeButton("Post Notice", noticeFrame, "#70a1ff", "#000", 4); noticeLayout->addWidget(editNoticeBtn);
            connect(editNoticeBtn, &QPushButton::clicked, this, &MainWindow::handleEditAnnouncement);
        }
        rosterLayout->addWidget(noticeFrame);

        // For staff, select a known class before managing its roster; create additional groups
        // through a form.
        if (currentRole == ROLE_HEAD || currentRole == ROLE_PROFESSOR) {
            auto* groupRow = new QHBoxLayout;
            groupRow->addWidget(new QLabel("Class Group:",pageRoster));
            classGroupCombo = new QComboBox(pageRoster); classGroupCombo->setObjectName("classGroupSelector"); groupRow->addWidget(classGroupCombo,1);
            auto* createGroup = makeButton("Create Class Group",pageRoster,"#252538","#00d2ff",8); groupRow->addWidget(createGroup);
            rosterLayout->addLayout(groupRow); refreshClassGroups();
            connect(createGroup,&QPushButton::clicked,this,&MainWindow::openClassGroupDialog);
            // Changing class stores its code, clears the old search, and refreshes rows when the
            // table exists.
            connect(classGroupCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this] {
                activeClassGroup=classGroupCombo->currentData().toString();
                if (rosterSearchInput) rosterSearchInput->clear(); if (tableWidget) refreshTable();
            });
            // Create staff add/edit/delete/sort controls above the filtered student roster.
            QHBoxLayout* toolbar1 = new QHBoxLayout();
            auto* addBtn = makeButton("Add Student", pageRoster, "#00d2ff");
            auto* editBtn = makeButton("Edit Selected", pageRoster, "#2e86de", "#fff");
            auto* deleteBtn = makeButton("Delete Selected", pageRoster, "#ff4757", "#fff");
            auto* sortBtn = makeButton("Sort by GWA", pageRoster, "#2ed573");
            toolbar1->addWidget(addBtn); toolbar1->addWidget(editBtn); toolbar1->addWidget(deleteBtn); toolbar1->addWidget(sortBtn);
            rosterLayout->addLayout(toolbar1);

            QHBoxLayout* searchLayout = new QHBoxLayout();
            QLabel* searchLabel = new QLabel("Filter:", pageRoster); auto* searchInput = new QLineEdit(pageRoster); rosterSearchInput=searchInput; searchInput->setPlaceholderText("Search this class by student ID or name...");
            searchLayout->addWidget(searchLabel); searchLayout->addWidget(searchInput); rosterLayout->addLayout(searchLayout);

            tableWidget = new QTableWidget(pageRoster);
            prepareTable(tableWidget, {"Student ID", "Full Name", "Class Group", "Calculated GWA"}, true);
            tableWidget->horizontalHeader()->setStretchLastSection(false);
            tableWidget->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
            tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
            rosterLayout->addWidget(tableWidget);

            statsLabel = new QLabel(pageRoster); statsLabel->setStyleSheet("font-weight: bold; color: #aaa;"); rosterLayout->addWidget(statsLabel);
            // An empty year's class prompt is longer than a class code.
            // Wrap the status text so switching years cannot widen the window.
            statsLabel->setWordWrap(true);

            connect(addBtn, &QPushButton::clicked, this, &MainWindow::openAddDialog);
            connect(editBtn, &QPushButton::clicked, this, &MainWindow::openEditDialog);
            connect(deleteBtn, &QPushButton::clicked, this, &MainWindow::handleDelete);
            connect(sortBtn, &QPushButton::clicked, this, &MainWindow::handleSort);
            connect(searchInput, &QLineEdit::textChanged, this, &MainWindow::refreshTable);
        } else {

            // For students, build read-only identity, rank, status, and course-grade displays.
            QFrame* studentProfileCard = new QFrame(pageRoster); studentProfileCard->setStyleSheet("background-color: #1e1e2d; border: 1px solid #2a2a3c; border-radius: 8px; padding: 8px;");
            QVBoxLayout* cardLayout = new QVBoxLayout(studentProfileCard);
            studentCardInfo = new QLabel(studentProfileCard); studentCardInfo->setTextFormat(Qt::PlainText); studentCardInfo->setWordWrap(true); studentCardInfo->setStyleSheet("font-size: 18px; color: #fff;"); studentCardInfo->setAlignment(Qt::AlignCenter);
            studentCardRank = new QLabel(studentProfileCard); studentCardRank->setStyleSheet("font-size: 17px; font-weight: bold; color: #00d2ff;"); studentCardRank->setAlignment(Qt::AlignCenter);
            studentCardStatus = new QLabel(studentProfileCard); studentCardStatus->setStyleSheet("font-size: 17px; font-weight: bold; color: #2ed573;"); studentCardStatus->setAlignment(Qt::AlignCenter);
            cardLayout->addWidget(studentCardInfo); cardLayout->addWidget(studentCardRank); cardLayout->addWidget(studentCardStatus);
            rosterLayout->addWidget(studentProfileCard);

            QLabel* courseGradesLabel = new QLabel("Enrolled Courses & Earned Grades", pageRoster);
            courseGradesLabel->setStyleSheet("font-size: 19px; font-weight: bold; color: #00d2ff; margin-top: 4px;"); courseGradesLabel->setAlignment(Qt::AlignCenter);
            rosterLayout->addWidget(courseGradesLabel);

            studentGradesTable = new QTableWidget(pageRoster);
            prepareTable(studentGradesTable, {"Course Code", "Units", "Midterm Grade", "Final Grade", "Subject Grade"}, true);
            rosterLayout->addWidget(studentGradesTable, 1);
        }

        mainStack->addWidget(pageRoster);

        // Build page 2 for this account's personal tasks.
        // Students attach tasks to current-year courses and a task semester;
        // Head and professors create general work tasks without a course.
        const bool studentTasks = currentRole==ROLE_STUDENT;
        QWidget* pageTodo = new QWidget(this); QVBoxLayout* todoLayout = new QVBoxLayout(pageTodo);
        todoLayout->setContentsMargins(12,12,12,12); todoLayout->setSpacing(6);
#ifndef V3_TABLET_UI
        // Apply the existing desktop task-page stylesheet only when the external tablet layout is
        // not enabled.
        pageTodo->setStyleSheet(QStringLiteral(R"(
            QWidget { font-size: 15px; }
            QLineEdit, QComboBox, QDateEdit { padding: 6px; min-height: 30px; }
            QPushButton { min-height: 32px; }
            QHeaderView::section { padding: 6px; font-size: 15px; }
        )"));
#endif
        const QString taskTitle = studentTasks ? "Personal Academic Tasks (To-Do List)"
            : currentRole==ROLE_HEAD ? "Administrative Tasks" : "Teaching Tasks";
        auto* todoTitle = new QLabel(taskTitle,pageTodo); todoTitle->setAlignment(Qt::AlignCenter); todoTitle->setWordWrap(true);
        todoTitle->setStyleSheet("font-size: 21px; font-weight: bold; color: #00d2ff; margin-bottom: 10px;"); todoLayout->addWidget(todoTitle);
        auto* todoForm = new QGridLayout; todoForm->setHorizontalSpacing(10); todoForm->setVerticalSpacing(6);
        todoForm->setColumnStretch(1,1); todoForm->setColumnStretch(3,1);
        // This local helper places a task-form label and input in grid cells with the existing
        // minimum height.
        auto addField = [&](const QString& label,QWidget* input,int row,int column,int span=1) {
            todoForm->addWidget(new QLabel(label,pageTodo),row,column); todoForm->addWidget(input,row,column+1,1,span); input->setMinimumHeight(44);
        };
        todoInput = new QLineEdit(pageTodo); todoInput->setObjectName("todoDescription");
        todoInput->setPlaceholderText(studentTasks ? "Enter assignment or study task..."
            : currentRole==ROLE_HEAD ? "e.g. Schedule a department meeting" : "e.g. Prepare lesson materials");
        addField("Task:",todoInput,0,0,3);
        // Student task semester starts unselected; choosing it fills the course dropdown
        // separately from grade viewing.
        if (studentTasks) {
            todoSemesterCombo = new QComboBox(pageTodo); todoSemesterCombo->setObjectName("todoSemester");
            todoSemesterCombo->addItem("Select semester first",0); todoSemesterCombo->addItem("1st Semester",1); todoSemesterCombo->addItem("2nd Semester",2);
            todoCourseCombo = new QComboBox(pageTodo); todoCourseCombo->setObjectName("todoCourse");
            addField("Select Semester:",todoSemesterCombo,1,0); addField("Select Course:",todoCourseCombo,1,2);
        }
        todoDueDateInput = new QDateEdit(QDate::currentDate(),pageTodo); todoDueDateInput->setObjectName("todoDueDate");
        todoDueDateInput->setCalendarPopup(true); todoDueDateInput->setDisplayFormat("MMM d, yyyy");
        todoPriorityCombo = new QComboBox(pageTodo); todoPriorityCombo->addItems({"🔴 High","🟡 Medium","🟢 Low"}); todoPriorityCombo->setCurrentIndex(1);
        const int dateRow = studentTasks ? 2 : 1;
        addField("Due Date:",todoDueDateInput,dateRow,0); addField("Priority:",todoPriorityCombo,dateRow,2); todoLayout->addLayout(todoForm);
        auto* addTodoBtn = makeButton("Add Task",pageTodo,"#2ed573","#000",6); addTodoBtn->setMinimumHeight(44); addTodoBtn->setFixedWidth(132);
        auto* actions = new QHBoxLayout; actions->setSpacing(10); actions->addWidget(addTodoBtn);
        actions->addWidget(new QLabel("Arrange by:",pageTodo)); todoSortCombo = new QComboBox(pageTodo); todoSortCombo->setObjectName("todoSort");
        todoSortCombo->addItem("Due date (soonest first)"); if (studentTasks) todoSortCombo->addItem("Course");
        todoSortCombo->addItems({"Priority","Date added"}); actions->addWidget(todoSortCombo,1); todoLayout->addLayout(actions);
        todoListWidget = new QTableWidget(pageTodo); todoListWidget->setObjectName("todoTable");
        prepareTable(todoListWidget,studentTasks ? QStringList{"Task","Course","Due Date","Priority"} : QStringList{"Task","Due Date","Priority"},true);
        todoListWidget->setSelectionBehavior(QAbstractItemView::SelectRows); todoListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        todoListWidget->horizontalHeader()->setStretchLastSection(false); todoListWidget->horizontalHeader()->setSectionResizeMode(0,QHeaderView::Stretch);
        for (int column=1;column<todoListWidget->columnCount();++column) todoListWidget->horizontalHeader()->setSectionResizeMode(column,QHeaderView::ResizeToContents);
        todoListWidget->setMinimumHeight(160); todoLayout->addWidget(todoListWidget,1);
        auto* delTodoBtn = makeButton("Remove Selected Task",pageTodo,"#ff4757","#fff",6); delTodoBtn->setMinimumHeight(44); todoLayout->addWidget(delTodoBtn);
        // Add Task and Enter in the description run the same add handler; Remove runs the delete
        // handler.
        connect(addTodoBtn,&QPushButton::clicked,this,&MainWindow::handleAddTodo); connect(todoInput,&QLineEdit::returnPressed,this,&MainWindow::handleAddTodo);
        connect(delTodoBtn,&QPushButton::clicked,this,&MainWindow::handleDeleteTodo);
        // A task-sort change redraws the display; a task-semester change refills the course
        // choices.
        connect(todoSortCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this] { refreshTodoList(); });
        if (studentTasks) connect(todoSemesterCombo,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this] { refreshTodoCourseChoices(); });
        refreshTodoCourseChoices(); mainStack->addWidget(pageTodo);

        // Put long navigation content in a scroll area and keep credits/logout in the footer
        // below it.
        auto* sidebarScroll = new QScrollArea(centralWidget);
        sidebarScroll->setObjectName("sidebarScroll"); sidebarScroll->setFrameShape(QFrame::NoFrame);
        sidebarScroll->setWidgetResizable(true); sidebarScroll->setFixedWidth(320);
        sidebarScroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
        sidebar->setMinimumWidth(0); sidebar->setMaximumWidth(QWIDGETSIZE_MAX); sidebarScroll->setWidget(sidebar);
        auto* navigationPanel = new QWidget(centralWidget); navigationPanel->setObjectName("navigationPanel"); navigationPanel->setFixedWidth(320);
        auto* navigationLayout = new QVBoxLayout(navigationPanel); navigationLayout->setContentsMargins(0,0,0,0); navigationLayout->setSpacing(0);
        navigationLayout->addWidget(sidebarScroll,1);
        auto* footer = new QWidget(navigationPanel); footer->setStyleSheet("background-color: #1a1a24;");
        auto* footerLayout = new QHBoxLayout(footer); footerLayout->setContentsMargins(12,12,12,12); footerLayout->setSpacing(6);
        auto* team = makeButton("Meet the Team",footer,"#252538","#00d2ff",8); team->setObjectName("meetTeamButton");
        footerLayout->addWidget(team,1); footerLayout->addWidget(btnLogout,1); navigationLayout->addWidget(footer);
        // Meet the Team opens its credits dialog and waits until the person closes it.
        connect(team,&QPushButton::clicked,this,[this] { MeetTeamDialog dialog(this); dialog.exec(); });
        rootLayout->addWidget(navigationPanel); rootLayout->addWidget(mainStack, 1);

        // Start Head on the teacher page; start professors and students on roster/personal
        // grades.
        int defaultPageIndex = (currentRole == ROLE_HEAD) ? 0 : 1;
        mainStack->setCurrentIndex(defaultPageIndex);

        // Connect available roster buttons and Tasks to their page indexes, then connect Logout
        // to its handler.
        if (btnTeacherRoster) connect(btnTeacherRoster, &QPushButton::clicked, [this]() { mainStack->setCurrentIndex(0); });
        if (btnStudentRoster) connect(btnStudentRoster, &QPushButton::clicked, [this]() { mainStack->setCurrentIndex(1); });
        connect(btnTodo, &QPushButton::clicked, [this]() { mainStack->setCurrentIndex(2); });
        connect(btnLogout, &QPushButton::clicked, this, &MainWindow::handleLogout);

        refreshAnnouncementDisplay();
    }

    // Refresh the banner with the shared notice, using a default message when the notice is
    // empty.
    void refreshAnnouncementDisplay() {
        announcementBanner->setText(classAnnouncement.empty() ? "Notice Board: No active announcements from the department." : "Notice Board: " + QString::fromStdString(classAnnouncement));
    }

    // For Head only, rebuild the teacher table from the loaded account map.
    // Apply an optional case-insensitive username filter and show setup flags and
    // question text. The count label shows all registered professors, even while filtered.
    // No account secrets are shown or changed by this display function.
    void refreshTeacherTable(const QString& filter = "") {
        if (currentRole != ROLE_HEAD) return;
        teacherTableWidget->setRowCount(0); int row = 0;
        for (const auto& pair : profAccounts) {
            QString user = QString::fromStdString(pair.first);
            // Skip a username if it does not contain the requested text, ignoring letter case.
            if (!filter.isEmpty() && !user.contains(filter, Qt::CaseInsensitive)) continue;

            teacherTableWidget->insertRow(row);
            // Insert the username, setup state, and readable question into cells owned by the
            // table.
            teacherTableWidget->setItem(row, 0, new QTableWidgetItem(user));
            teacherTableWidget->setItem(row, 1, new QTableWidgetItem(pair.second.firstLogin ? "Yes (Temp Pass)" : "No (Configured)"));
            teacherTableWidget->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(pair.second.secQuestion)));
            row++;
        }
        teacherStatsLabel->setText(QString("Total Registered Professors: %1").arg(profAccounts.size()));
    }

    // Refresh page 1 according to the logged-in role.
    // Staff see students in the selected year/class matching the ID/name search, cached
    // GWA for activeSemester, and counts for the selected class/year curriculum.
    // Students see only their own chosen year/semester using a temporary historical
    // view. Show marks, weighted averages, status, and a current-class rank when available.
    // This display function does not save records or change a student's assigned year.
    void refreshTable(const QString& filter = "") {
        if (currentRole == ROLE_HEAD || currentRole == ROLE_PROFESSOR) {
            // Use the supplied search text, or the existing search box when refreshing without an
            // explicit filter.
            const QString query = filter.isEmpty() && rosterSearchInput ? rosterSearchInput->text() : filter;
            tableWidget->setRowCount(0); int row = 0;
            for (auto& s : studentList) {
                QString idStr = QString::number(s.getId()), nameStr = QString::fromStdString(s.getName());
                if (!inSelectedClass(s) || (!query.isEmpty() && !idStr.contains(query,Qt::CaseInsensitive) && !nameStr.contains(query,Qt::CaseInsensitive))) continue;

                tableWidget->insertRow(row);
                // Populate the roster by fixed student ID, name, class, and formatted cached
                // average.
                tableWidget->setItem(row, 0, new QTableWidgetItem(idStr));
                tableWidget->setItem(row, 1, new QTableWidgetItem(nameStr));
                tableWidget->setItem(row,2,new QTableWidgetItem(s.getClassGroup().isEmpty() ? "Needs class assignment" : s.getClassGroup()));
                tableWidget->setItem(row,3,new QTableWidgetItem(fmtGwa(s.getGwa())));
                row++;
            }
            const auto selectedCatalog = curriculumForYear(masterCatalog, selectedClassYear());
            // Count the semester's subjects for the selected class year, including applicable
            // unassigned old subjects.
            int subjects = count_if(selectedCatalog.begin(), selectedCatalog.end(), [this](const MasterSubject& subject) { return subject.semester == activeSemester; });
            statsLabel->setText(QString("Class: %1 | Students: %2 | %3 | Subjects: %4").arg(classGroupCombo->currentText()).arg(row).arg(semesterText(activeSemester)).arg(subjects));
        } else {

            // Build the rank list from current records in this student's current class whose
            // grade year matches the viewed year and whose semester GWA is recorded.
            // This does not rank every student's archived history; an older-year view normally
            // has no current-class rank. Pointers avoid copying records merely for sorting.
            QString ownGroup; for (const auto& student : studentList) if (student.getId()==currentStudentId) { ownGroup=student.getClassGroup(); break; }
            vector<const Student*> gradedList; for (const auto& s : studentList)
                if (s.gradeYear()==activeStudentYear && s.getGwa()>0 && s.getClassGroup()==ownGroup) gradedList.push_back(&s);
            // Sort recorded averages from lower to higher; this produces positions, not shared
            // ranks for equal averages.
            sort(gradedList.begin(), gradedList.end(), [](const Student* a, const Student* b){ return a->getGwa() < b->getGwa(); });

            for (auto& s : studentList) if (s.getId() == currentStudentId) {
                const auto& yearCatalog = s.catalogForYear(activeStudentYear, masterCatalog);
                // Obtain the requested year's catalog and a grade-view copy, then summarize that
                // copy's semester results.
                const Student viewed = s.forAcademicYear(activeStudentYear, masterCatalog, activeSemester);
                const auto summary = viewed.academicSummary(yearCatalog, activeSemester);
                QString statusStr = "Academic Status: " + QString::fromStdString(summary.status(true));
                QString statusColor = !summary.recorded ? "#aaa" : summary.failures > 3 ? "#ff4757" : summary.failures ? "#ffa801" : "#2ed573";

                // Find this student's 1-based position; leave N/A if they are outside the current
                // rank list.
                int rankPos = -1;
                for (size_t i = 0; i < gradedList.size(); ++i) if (gradedList[i]->getId() == s.getId()) { rankPos = i + 1; break; }
                QString rankText = (rankPos > 0 && !gradedList.empty()) ? QString("Class Rank: #%1 out of %2 (Top %3%)")
                    .arg(rankPos).arg(gradedList.size()).arg(QString::number((double)rankPos / gradedList.size() * 100.0, 'f', 1)) : "Class Rank: N/A";

                studentCardInfo->setText(QString("ID: %1 | Name: %2\nClass Group: %3 | Viewing Year %8, %4\nMidterm GWA: %5 | Finals GWA: %6 | Overall GWA: %7")
                    .arg(s.getId()).arg(QString::fromStdString(s.getName()))
                    .arg(s.getClassGroup().isEmpty() ? "Needs class assignment" : s.getClassGroup()).arg(semesterText(activeSemester))
                    .arg(fmtGwa(viewed.getMidtermGwa())).arg(fmtGwa(viewed.getFinalsGwa())).arg(fmtGwa(viewed.getGwa())).arg(activeStudentYear));
                studentCardRank->setText(rankText); studentCardStatus->setText(statusStr);
                studentCardStatus->setStyleSheet(QString("font-size: 17px; font-weight: bold; color: %1;").arg(statusColor));

                // Fill only the chosen year's semester courses with the viewed marks.
                // Without a saved history, the catalog is empty. Existing courses with missing
                // marks still show rows containing 'N/A'. The status prompt explains missing
                // results.
                studentGradesTable->setRowCount(0); int r = 0;
                studentGradesTable->setToolTip(summary.recorded ? QString() : "No grades recorded for this year and semester.");
                if (!summary.recorded) studentCardStatus->setText("Academic Status: No grades recorded");
                for (const auto& sub : yearCatalog) {
                    if (sub.semester != activeSemester) continue;
                    studentGradesTable->insertRow(r);
                    studentGradesTable->setItem(r, 0, new QTableWidgetItem(QString::fromStdString(sub.code)));
                    studentGradesTable->setItem(r, 1, new QTableWidgetItem(QString::number(sub.units)));
                    const auto text = gradeText(viewed.gradeFor(sub.code, activeSemester));
                    studentGradesTable->setItem(r, 2, new QTableWidgetItem(text.midterm));
                    studentGradesTable->setItem(r, 3, new QTableWidgetItem(text.finalGrade));
                    studentGradesTable->setItem(r, 4, new QTableWidgetItem(text.subject)); r++;
                }
                break;
            }
        }
    }

    // Let staff edit the shared notice in a dialog.
    // On acceptance, save the new text and refresh the banner. A failed save restores
    // the old text; show the success message only after the save works.
    void handleEditAnnouncement() {
        if (currentRole == ROLE_STUDENT) return;
        EditAnnouncementDialog dialog(classAnnouncement, this);
        if (dialog.exec() == QDialog::Accepted) {
            classAnnouncement = dialog.getAnnouncement(); if (!saveAnnouncement()) return; refreshAnnouncementDisplay();
            QMessageBox::information(this, "Success", "Class announcement posted successfully!");
        }
    }

    // For staff, export one CSV summary row for every student in the selected class.
    // Use the dashboard semester's averages and status. Roster search text does not
    // limit this export. Include identity/class details and recorded-course counts.
    // Escape text fields and save a class/semester-named file with the protected writer.
    void handleExportCSV() {
        if (currentRole == ROLE_STUDENT) return;
        if (none_of(studentList.begin(),studentList.end(),[this](const Student& student) { return inSelectedClass(student); })) { QMessageBox::warning(this,"Export Error","No students in the selected class."); return; }
        string exportFilename = "Class_" + (activeClassGroup=="__legacy__" ? string("Needs_assignment") : activeClassGroup.toStdString()) + "_Semester" + to_string(activeSemester) + ".csv"; stringstream outFile;

        outFile << "Student ID,Full Name,Program,Year,Section,Class Group,Semester,Midterm GWA,Finals GWA,Overall GWA,Academic Status,Subjects Recorded\n";
        for (auto& s : studentList) {
            if (!inSelectedClass(s)) continue;
            const auto summary = s.academicSummary(masterCatalog, activeSemester);
            const string status = summary.status();
            // Quote text fields so commas, quotes, and line breaks do not split a name or class
            // into extra CSV fields.
            outFile << s.getId() << "," << Storage::csv(s.getName()) << "," << Storage::csv(s.getProgram()) << "," << (s.getYear() ? to_string(s.getYear()) : "") << ","
                    << Storage::csv(s.getSection()) << "," << Storage::csv(s.getClassGroup().toStdString()) << "," << activeSemester << "," << fmtGwa(s.getMidtermGwa()).toStdString() << ","
                    << fmtGwa(s.getFinalsGwa()).toStdString() << "," << fmtGwa(s.getGwa()).toStdString() << ","
                    << status << "," << summary.recorded << "\n";
        }
        if (!Storage::exportFile(exportFilename, QByteArray::fromStdString(outFile.str()))) { Storage::report(this); return; }
        QMessageBox::information(this, "Export Success", QString("Selected class roster exported to:\n%1").arg(QString::fromStdString(exportFilename)));
    }

    // For Head only, collect a professor username/password and reject duplicates or 'Head'.
    // Create a hashed account requiring first-login setup, save the account map, and
    // refresh the teacher table. A failed save restores the last saved professor map.
    void openAddProfDialog() {
        if (currentRole != ROLE_HEAD) return;
        AddProfDialog dialog(this);
        if (dialog.exec() == QDialog::Accepted) {
            string u = dialog.getUsername(), p = dialog.getPassword();
            if (profAccounts.find(u) != profAccounts.end() || u == "Head") { QMessageBox::warning(this, "Duplicate", "Account exists!"); return; }

            profAccounts[u] = {p, true};
            if (!saveProfessors()) return; refreshTeacherTable();
            QMessageBox::information(this, "Success", QString("New professor account '%1' created!").arg(QString::fromStdString(u)));
        }
    }

    // For Head only, ask for a replacement password for the selected teacher.
    // Hash it, require first-login setup, and mark recovery unconfigured.
    // Save the map and refresh its table; report success only after the save succeeds.
    void handleResetProfPassword() {
        if (currentRole != ROLE_HEAD) return;
        int r = teacherTableWidget->currentRow();
        if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a teacher row from the table first."); return; }

        string user = teacherTableWidget->item(r, 0)->text().toStdString();
        ResetAccountPasswordDialog dialog(user, "temp1234", this);
        if (dialog.exec() == QDialog::Accepted) {
            profAccounts.at(user).password = Security::hash(dialog.getNewPassword());
            profAccounts.at(user).firstLogin = true; profAccounts.at(user).recoveryConfigured = false;
            if (!saveProfessors()) return; refreshTeacherTable();
            QMessageBox::information(this, "Success", QString("Password for Professor '%1' reset!").arg(QString::fromStdString(user)));
        }
    }

    // For Head only, ask for confirmation before deleting the selected professor account.
    // Remove its username from the map, save, and refresh; a failed save restores it.
    // This deletes the account record, not a separate personal task file.
    void handleDeleteProf() {
        if (currentRole != ROLE_HEAD) return;
        int r = teacherTableWidget->currentRow();
        if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a teacher row to delete."); return; }

        string user = teacherTableWidget->item(r, 0)->text().toStdString();
        if (QMessageBox::question(this, "Confirm Delete", QString("Delete Professor account '%1'?").arg(QString::fromStdString(user))) == QMessageBox::Yes) {
            profAccounts.erase(user);
            if (!saveProfessors()) return; refreshTeacherTable();
        }
    }

    // For Head only, load the latest Head account and open a security-change form.
    // On acceptance, replace password and recovery details with new hashes and save.
    // Cancel or a storage error stops the action; announce success after committing.
    void handleChangeHeadPassword() {
        if (currentRole != ROLE_HEAD) return;
        HeadAccount account;
        if (!FileIO::loadHead(headFilename, account)) { Storage::report(this); return; }
        SetupSecurityDialog dialog(this, "Change Head Admin Security Credentials");
        if (dialog.exec() != QDialog::Accepted) return;
        account = {Security::hash(dialog.getPassword()), dialog.getQuestion(), Security::hash(Security::answerText(dialog.getAnswer())), false, true};
        if (!FileIO::saveHead(headFilename, account)) { Storage::report(this); return; }
        QMessageBox::information(this, "Success", "Head Admin security credentials saved.");
    }

    // Let the logged-in professor update their own password and recovery details.
    // Find that username, collect accepted input, create its hashed replacement,
    // and save. The save helper restores the old professor map if writing fails.
    void handleChangeProfPassword() {
        if (currentRole != ROLE_PROFESSOR) return;
        auto found = profAccounts.find(currentProfUser);
        if (found == profAccounts.end()) return;
        SetupSecurityDialog dialog(this, "Change Professor Security Credentials");
        if (dialog.exec() != QDialog::Accepted) return;
        found->second = ProfAccount(dialog.getPassword(), false, dialog.getQuestion(), dialog.getAnswer());
        if (!saveProfessors()) return;
        QMessageBox::information(this, "Success", "Your password and security settings were saved.");
    }

    // For staff only, reset the selected student's password using a validated dialog.
    // Find the student by fixed ID, hash the new password, and require setup next login.
    // Save the roster before showing success. The previous recovery answer may remain
    // stored, but firstLogin prevents using it until the new setup is complete.
    void handleResetStudentPassword() {
        if (currentRole == ROLE_STUDENT) return;
        int r = tableWidget->currentRow(); if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a student row first."); return; }
        int id = tableWidget->item(r, 0)->text().toInt(); string name = tableWidget->item(r, 1)->text().toStdString();
        ResetAccountPasswordDialog dialog(name, QString("temp%1").arg(id, 6, 10, QChar('0')).toStdString(), this);
        if (dialog.exec() == QDialog::Accepted) {
            // Use the ID stored in the selected row, since sorting/filtering changes row
            // positions.
            for (auto& s : studentList) if (s.getId() == id) { s.setPassword(dialog.getNewPassword()); s.setFirstLogin(true); break; }
            if (!saveStudents()) return;
            QMessageBox::information(this, "Password Reset", QString("Password for Student ID %1 (%2) has been reset!").arg(id).arg(QString::fromStdString(name)));
        }
    }

    // For staff only, register a student in an existing class.
    // Require known groups, open the form with the selected class, and reject duplicate IDs.
    // Create a temporary password based on the ID, hash it in the new Student, and
    // require first-login setup. Save, select the student's group, and refresh the roster.
    // Show the temporary password only after the record has been saved successfully.
    void openAddDialog() {
        if (currentRole == ROLE_STUDENT) return;
        syncClassGroups();
        if (classGroups.empty()) {
            QMessageBox::information(this, "Class Group Required", "Create a class group on the roster before adding a student."); return;
        }
        ClassGroup selected;
        for (const auto& group : classGroups) if (group.code()==activeClassGroup) { selected=group; break; }
        StudentFormDialog dialog(this,false,0,"",selected.year,QString::fromStdString(selected.section),QString::fromStdString(selected.program),classGroups);
        if (dialog.exec() == QDialog::Accepted) {
            int id = dialog.getId(); string name = dialog.getName();
            for (const auto& s : studentList) if (s.getId() == id) { QMessageBox::critical(this, "Duplicate ID", "Student ID exists!"); return; }

            if (!ensureClassGroup({dialog.getProgram(),dialog.getYear(),dialog.getSection()})) return;
            string temporaryPassword = QString("temp%1").arg(id, 6, 10, QChar('0')).toStdString();
            studentList.push_back(Student(id, name, 0.0, temporaryPassword, true));
            studentList.back().setClassGroup(dialog.getYear(),dialog.getProgram(),dialog.getSection());
            if (!saveStudents()) return; refreshClassGroups(dialog.getGroup()); if (rosterSearchInput) rosterSearchInput->clear(); refreshTable();
            QMessageBox::information(this, "Registered", QString("Student registered!\nTemporary Password: %1").arg(QString::fromStdString(temporaryPassword)));
        }
    }

    // For staff only, edit the selected student's name and existing class assignment.
    // Find the record by ID; the form keeps that ID fixed. Before changing years,
    // archive outgoing marks and restore the destination year's marks using changeGradeYear().
    // Update identity/class, recalculate, save, and refresh. Failed saving restores the roster.
    void openEditDialog() {
        if (currentRole == ROLE_STUDENT) return;
        int r = tableWidget->currentRow(); if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a student row first."); return; }
        int id = tableWidget->item(r, 0)->text().toInt(); QString name = tableWidget->item(r, 1)->text();
        auto selected = find_if(studentList.begin(), studentList.end(), [id](const Student& student) { return student.getId() == id; });
        if (selected == studentList.end()) return;
        StudentFormDialog dialog(this,true,id,name,selected->getYear(),QString::fromStdString(selected->getSection()),QString::fromStdString(selected->getProgram()),classGroups);
        if (dialog.exec() == QDialog::Accepted) {
            if (!ensureClassGroup({dialog.getProgram(),dialog.getYear(),dialog.getSection()})) return;
            for (auto& s : studentList) if (s.getId()==id) {
                // Move the grade-history page before setting the new class year so outgoing marks
                // keep their correct year.
                s.changeGradeYear(dialog.getYear(), masterCatalog);
                s.setName(dialog.getName()); s.setClassGroup(dialog.getYear(),dialog.getProgram(),dialog.getSection());
                s.recalculateGWA(masterCatalog, activeSemester); break;
            }
            if (!saveStudents()) return; refreshClassGroups(dialog.getGroup()); if (rosterSearchInput) rosterSearchInput->clear(); refreshTable();
        }
    }

    // For staff only, edit a copy of the curriculum using the selected year and semester.
    // Cancel discards the copy. On acceptance, replace the working catalog, recalculate
    // averages, save it, and refresh roster/task course choices. Failed saving restores
    // the old catalog and recalculates the display from it.
    void openCatalogDialog() {
        if (currentRole == ROLE_STUDENT) return;
        auto edited = masterCatalog; MasterSubjectDialog dialog(edited, this, activeSemester, selectedClassYear());
        if (dialog.exec() != QDialog::Accepted) return;
        masterCatalog = std::move(edited); recalculateGrades(); if (!saveCatalog()) return; refreshTable(); refreshTodoCourseChoices(true);
    }

    // For staff only, require semester subjects and a selected student before grade entry.
    // Pass a student copy to GradeCalculatorDialog so cancellation leaves live marks alone.
    // On acceptance, copy the edited record back, save the roster, and refresh it.
    // The student's current class year and dashboard semester choose the edited courses.
    void openGradeCalculator() {
        if (currentRole == ROLE_STUDENT) return;
        const auto selectedCatalog = curriculumForYear(masterCatalog, selectedClassYear());
        if (none_of(selectedCatalog.begin(), selectedCatalog.end(), [this](const MasterSubject& subject) { return subject.semester == activeSemester; })) {
            QMessageBox::warning(this, "Curriculum Empty", "Add subjects for " + semesterText(activeSemester) + " first."); return;
        }
        int row = tableWidget->currentRow();
        if (row < 0) { QMessageBox::warning(this, "Selection Required", "Select a student row first."); return; }
        int id = tableWidget->item(row, 0)->text().toInt();
        for (auto& student : studentList) if (student.getId() == id) {
            auto edited = student; GradeCalculatorDialog dialog(edited, masterCatalog, this, activeSemester);
            if (dialog.exec() != QDialog::Accepted) return;
            student = edited; if (!saveStudents()) return; refreshTable(); return;
        }
    }

    // For staff, find the selected student's fixed ID and preview their current-year report for
    // activeSemester.
    void generateReportCard() {
        if (currentRole == ROLE_STUDENT) return;
        int r = tableWidget->currentRow(); if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a student row first."); return; }
        int id = tableWidget->item(r, 0)->text().toInt();
        for (const auto& s : studentList) if (s.getId() == id) { ReportCardDialog dialog(s, masterCatalog, this, activeSemester); dialog.exec(); break; }
    }

    // Find the logged-in student's own record and preview its report for activeSemester.
    // This uses the student's current assigned year; the View Grades historical year
    // selector does not change which year this official report uses.
    void generateStudentOwnReportCard() {
        for (const auto& s : studentList) if (s.getId() == currentStudentId) { ReportCardDialog dialog(s, masterCatalog, this, activeSemester); dialog.exec(); break; }
    }

    // For staff only, confirm deletion of the selected student ID.
    // Remove its record, save the roster, and refresh; a failed save restores it.
    // Its marks and history are part of that record; separate task/export files are not removed.
    void handleDelete() {
        if (currentRole == ROLE_STUDENT) return;
        int r = tableWidget->currentRow(); if (r < 0) { QMessageBox::warning(this, "Selection Required", "Select a student row to delete."); return; }
        int id = tableWidget->item(r, 0)->text().toInt();
        if (QMessageBox::question(this, "Confirm Delete", QString("Delete Student ID %1?").arg(id)) == QMessageBox::Yes) {
            // remove_if moves matching records out of the kept range; erase removes that
            // discarded range.
            studentList.erase(remove_if(studentList.begin(), studentList.end(), [id](const Student& s){ return s.getId() == id; }), studentList.end());
            if (!saveStudents()) return; refreshTable();
        }
    }

    // For staff, sort the in-memory student list by lower (better) recorded GWA.
    // Missing averages come last. Refresh the selected class view without saving here;
    // future actions still locate students by fixed IDs rather than sorted row numbers.
    void handleSort() {
        if (currentRole == ROLE_STUDENT) return;
        // The comparison puts positive averages before missing ones, then compares two positive
        // averages numerically.
        sort(studentList.begin(), studentList.end(), [](const Student& a, const Student& b){                                                                                    if (a.getGwa() <= 0) return false; if (b.getGwa() <= 0) return true; return a.getGwa() < b.getGwa();
        });
        refreshTable();
    }

    // Refill a student's task-course choices after selecting a task semester.
    // Use their actual current year and current master curriculum, independently of
    // the historical grade-view year. Keep the previous choice only when requested
    // and still available. Disable course selection until valid subjects are offered.
    void refreshTodoCourseChoices(bool preserveSelection = false) {
        if (currentRole!=ROLE_STUDENT) return;
        const QString previous = preserveSelection ? todoCourseCombo->currentData().toString() : QString();
        const int semester = todoSemesterCombo->currentData().toInt();
        QSignalBlocker blocker(todoCourseCombo); todoCourseCombo->clear();
        todoCourseCombo->addItem(semester == 0 ? "Select a semester first" : "Select course", "");
        int year = 1; for (const auto& student : studentList) if (student.getId() == currentStudentId) { year = student.gradeYear(); break; }
        for (const auto& subject : curriculumForYear(masterCatalog, year)) {
            if (subject.semester != semester) continue;
            const QString code = QString::fromStdString(subject.code);
            todoCourseCombo->addItem(code, code);
        }
        if (semester != 0 && todoCourseCombo->count() == 1)
            todoCourseCombo->setItemText(0, "No subjects in this semester");
        todoCourseCombo->setEnabled(semester != 0 && todoCourseCombo->count() > 1);
        const int index = todoCourseCombo->findData(previous);
        todoCourseCombo->setCurrentIndex(index < 0 ? 0 : index);
    }

    // Add a personal task from the form; empty text simply refocuses the description box.
    // Students must choose semester and course. Staff use general tasks with semester 0.
    // Store description, priority, course, due date, and semester, then save the list.
    // On success clear the description and redraw; on failure the save helper restores tasks.
    void handleAddTodo() {
        const string task=todoInput->text().trimmed().toStdString();
        if (task.empty()) { todoInput->setFocus(); return; }
        string course; int semester=0;
        if (currentRole==ROLE_STUDENT) {
            semester=todoSemesterCombo->currentData().toInt(); course=todoCourseCombo->currentData().toString().toStdString();
            if (semester<1 || semester>2) {
                QMessageBox::warning(this,"Semester Required","Choose 1st Semester or 2nd Semester first."); todoSemesterCombo->setFocus(); return;
            }
            if (course.empty()) {
                QMessageBox::warning(this,"Course Required","Choose a course from the selected semester."); todoCourseCombo->setFocus(); return;
            }
        }
        todoList.push_back({task,todoPriorityCombo->currentText().toStdString(),course,todoDueDateInput->date(),semester});
        if (!saveTodoList()) return; todoInput->clear(); refreshTodoList(); todoInput->setFocus();
    }

    // Delete the selected task using its hidden original vector index, not its display row.
    // Check the index, remove that task, save, and redraw. This selects the correct task
    // even after display sorting; a failed save restores the previous task list.
    void handleDeleteTodo() {
        const int row = todoListWidget->currentRow(); if (row < 0) return;
        const int index = todoListWidget->item(row, 0)->data(Qt::UserRole).toInt();
        if (index < 0 || index >= int(todoList.size())) return;
        todoList.erase(todoList.begin() + index); if (!saveTodoList()) return; refreshTodoList();
    }

    // Rebuild the task table in the chosen order without rearranging todoList itself.
    // Sort a list of original indexes by due date, course, priority, or entry order.
    // Store each original index in its displayed row for later deletion.
    // Show due dates and priority colors, marking past dates overdue. 'Date added'
    // uses list order rather than a saved timestamp; loaded legacy tasks may have no date.
    void refreshTodoList() {
        vector<int> order; for (int index=0;index<int(todoList.size());++index) order.push_back(index);
        // Map High to 0, Medium/unknown to 1, and Low to 2 so smaller numbers sort first.
        auto priorityRank=[](const string& priority) { return priority.find("High")!=string::npos ? 0 : priority.find("Low")!=string::npos ? 2 : 1; };
        const bool studentTasks=currentRole==ROLE_STUDENT;
        // Staff do not have the Course sort option, so adjust their dropdown index to the shared
        // sorting rules.
        int sorting=todoSortCombo->currentIndex(); if (!studentTasks && sorting>0) ++sorting;
        // Compare the indexed tasks: dated tasks first and earlier dates first, then priority;
        // or course plus semester; or priority alone; or original list position.
        // stable_sort keeps tied tasks in their original order.
        stable_sort(order.begin(),order.end(),[&](int left,int right) {
            const auto& a=todoList[left]; const auto& b=todoList[right];
            if (sorting==0) {
                if (a.dueDate.isValid()!=b.dueDate.isValid()) return a.dueDate.isValid();
                if (a.dueDate!=b.dueDate) return a.dueDate<b.dueDate;
                return priorityRank(a.priority)<priorityRank(b.priority);
            }
            if (sorting==1) { const int comparison=QString::fromStdString(a.course).compare(QString::fromStdString(b.course),Qt::CaseInsensitive); return comparison ? comparison<0 : a.semester<b.semester; }
            if (sorting==2) return priorityRank(a.priority)<priorityRank(b.priority);
            return left<right;
        });
        todoListWidget->setRowCount(0);
        for (int index : order) {
            const auto& task=todoList[index]; const int row=todoListWidget->rowCount(); todoListWidget->insertRow(row);
            // Store the source index in the description cell and show its full text as a hover
            // hint.
            auto* description=readOnlyItem(QString::fromStdString(task.task)); description->setData(Qt::UserRole,index); description->setToolTip(description->text()); todoListWidget->setItem(row,0,description);
            if (studentTasks) todoListWidget->setItem(row,1,readOnlyItem(task.course.empty() ? "General" : QString::fromStdString(task.course)+"\n"+semesterText(task.semester)));
            const bool overdue=task.dueDate.isValid() && task.dueDate<QDate::currentDate();
            // Only a valid date earlier than today is overdue; today's tasks are not yet overdue.
            auto* date=readOnlyItem(task.dueDate.isValid() ? task.dueDate.toString("MMM d, yyyy")+(overdue ? "\nOverdue" : "") : "No due date");
            if (overdue) date->setForeground(QColor("#ff6b81")); todoListWidget->setItem(row,studentTasks ? 2 : 1,date);
            auto* priority=readOnlyItem(QString::fromStdString(task.priority)); priority->setForeground(QColor(priorityRank(task.priority)==0 ? "#ff6b81" : priorityRank(task.priority)==2 ? "#2ed573" : "#ffa801"));
            todoListWidget->setItem(row,studentTasks ? 3 : 2,priority);
        }
        todoListWidget->resizeRowsToContents(); for (int row=0;row<todoListWidget->rowCount();++row) todoListWidget->setRowHeight(row,qMax(56,todoListWidget->rowHeight(row)));
    }

    // Log out by clearing file snapshot tracking and ending Qt's event loop with code 1000.
    // main() recognizes that code, reloads students, and returns to the login dialog.
    // Edits that needed saving have already used their save handlers; logout does not save.
    void handleLogout() {
    // Discard old owner fingerprints before fresh login/dashboard objects load the files again.
    Storage::revisions.clear(); 
    QMessageBox::information(this, "Logout", "Logged out successfully."); qApp->exit(1000); }

    // Save the current catalog and update savedCatalog on success.
    // On failure, restore the old catalog, recalculate averages, refresh grades,
    // show the storage error, and return false.
    bool saveCatalog() {
        if (FileIO::saveCatalog(catalogFilename, masterCatalog)) { savedCatalog = masterCatalog; return true; }
        masterCatalog = savedCatalog; recalculateGrades(); refreshTable(); return Storage::report(this);
    }
    // Save the complete student roster and remember it as the new saved snapshot.
    // On failure, restore the previous roster, recalculate its averages, refresh its
    // view, and show the error. Return whether the proposed records were saved.
    bool saveStudents() {
        if (FileIO::saveStudents(filename, studentList)) { savedStudents = studentList; return true; }
        studentList = savedStudents; recalculateGrades(); refreshTable(); return Storage::report(this);
    }
    // Save the professor map and update its saved snapshot on success.
    // On failure, restore the old map, refresh Head's teacher view if applicable,
    // and show the storage error.
    bool saveProfessors() {
        if (FileIO::saveProfessors(profFilename, profAccounts)) { savedProfessors = profAccounts; return true; }
        profAccounts = savedProfessors; refreshTeacherTable(); return Storage::report(this);
    }

    // Save the full shared announcement as plain text using protected replacement.
    // Keep the new saved snapshot on success. Restore the previous notice and
    // banner on failure, then show the error.
    bool saveAnnouncement() {
        if (Storage::write(announcementFilename, QByteArray::fromStdString(classAnnouncement), &classAnnouncement)) { savedAnnouncement = classAnnouncement; return true; }
        classAnnouncement = savedAnnouncement; refreshAnnouncementDisplay(); return Storage::report(this);
    }
    // Read the complete shared announcement into memory, preserving line breaks.
    // A missing file is allowed and becomes an empty notice; other read failures return false.
    bool loadAnnouncement() {
        QByteArray data; if (!Storage::read(announcementFilename, data, &classAnnouncement, true)) return false;
        classAnnouncement = data.toStdString(); return true;
    }

    // Save this account's full personal task list and update savedTasks on success.
    // On failure, restore its previous list, redraw the task table, and show the error.
    // Return true only when the new task records were saved.
    bool saveTodoList() {
        if (FileIO::saveTasks(todoFilename, todoList)) { savedTasks = todoList; return true; }
        todoList = savedTasks; refreshTodoList(); return Storage::report(this);
    }
};

// PROGRAM ENTRY POINT
// Receive command-line arguments, create QApplication, and configure its name/version.
// Prepare the platform's data folder and optional tablet event helper; lock the folder
// so only one running copy can use these records. Validate all startup databases.
// A fresh installation asks for Head security setup, then creates/migrates needed files.
// Repeatedly show login, open the authenticated dashboard, and process Qt events.
// Logout code 1000 restarts login after reloading students; other exits finish the app.
// Return 0 for a normal end and 1 for a startup/storage error.
int runApplication(int argc, char *argv[]) {
    // On Qt 5 builds, enable high-DPI scaling and sharp images before creating the application.
#if QT_VERSION < QT_VERSION_CHECK(6, 0, 0)
    QApplication::setAttribute(Qt::AA_EnableHighDpiScaling);
    QApplication::setAttribute(Qt::AA_UseHighDpiPixmaps);
#endif
    // Create the Qt application; it handles the event loop and application-wide settings.
    QApplication app(argc, argv);
    // Startup switches between temporary dialogs; closing one must not exit Qt.
    app.setQuitOnLastWindowClosed(false);
    StartupTrace::note("Startup: Qt application created.");
    QCoreApplication::setApplicationName("StudentManagementV3");
    QCoreApplication::setApplicationVersion(APP_VERSION);
    QCoreApplication::setOrganizationName("StudentManagement");
#ifdef Q_OS_ANDROID
    // On Android, create and use the app's writable data folder for local records.
    const QString dataFolder = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!QDir().mkpath(dataFolder) || !QDir::setCurrent(dataFolder)) {
        QMessageBox::critical(nullptr, "Storage Error", "Cannot prepare the application data folder."); return 1;
    }
#elif defined(Q_OS_WIN)
    // On Windows, use the executable's folder so relative record names resolve beside the
    // program.
    if (!QDir::setCurrent(QCoreApplication::applicationDirPath())) {
        QMessageBox::critical(nullptr, "Storage Error", "Cannot open the application folder."); return 1;
    }
#endif
    StartupTrace::note("Startup: application data folder ready.");
    applyGlobalDarkTheme();
#ifdef V3_TABLET_UI
    // Install the external tablet dialog event watcher for the lifetime of this running
    // application.
    Tablet::Dialogs tabletDialogs; app.installEventFilter(&tabletDialogs);
#endif
    // Hold an instance lock for this data folder; refuse to open another copy using the same
    // records.
    QLockFile instanceLock(QDir::current().absoluteFilePath("student_management.lock"));
    if (!instanceLock.tryLock(0)) { QMessageBox::warning(nullptr, "App Already Open", "Close the other copy before opening this database."); return 1; }
    // Treat the installation as fresh only when student, professor, and Head account files are
    // all absent.
    bool fresh = !QFileInfo::exists("students.txt") && !QFileInfo::exists("professors.txt") && !QFileInfo::exists("head_admin.txt");
    vector<Student> roster; map<string, ProfAccount> professors; vector<MasterSubject> catalog; HeadAccount head;
    // Load and validate every startup database before attempting to save any migrated records.
    if (!FileIO::loadStudents("students.txt", roster, fresh) || !FileIO::loadProfessors("professors.txt", professors, fresh)
        || !FileIO::loadCatalog("curriculum.txt", catalog, fresh) || !FileIO::loadHead("head_admin.txt", head, fresh)) { Storage::report(); return 1; }
    StartupTrace::note("Startup: databases loaded and validated.");
    // On first use, require accepted Head credentials; cancel ends normally before creating
    // database files.
    if (fresh) {
        StartupTrace::note("Setup: opening Head account form.");
        SetupSecurityDialog dialog(nullptr, "Create Head Admin Account");
        if (dialog.exec() != QDialog::Accepted) return 0;
        StartupTrace::note("Setup: hashing Head password.");
        head.password = Security::hash(dialog.getPassword());
        StartupTrace::note("Setup: hashing recovery answer.");
        head.question = dialog.getQuestion();
        head.answer = Security::hash(Security::answerText(dialog.getAnswer()));
        head.firstLogin = false; head.recoveryConfigured = true;
        StartupTrace::note("Setup: Head credentials prepared.");
    }
    // This local migration helper saves only an accepted missing/old-format file.
    // A current version-4 JSON file needs no rewrite; validation failures have already stopped
    // startup.
    auto migrate = [](const string& filename, auto& records, auto save) {
        StartupTrace::note(filename.c_str());
        return !Storage::needsMigration(filename, &records) || save(filename, records);
    };
    if (!migrate("students.txt", roster, FileIO::saveStudents) || !migrate("professors.txt", professors, FileIO::saveProfessors)
        || !migrate("curriculum.txt", catalog, FileIO::saveCatalog) || !migrate("head_admin.txt", head, FileIO::saveHead)) { Storage::report(); return 1; }
    StartupTrace::note("Startup: all database files saved.");
    // Repeat the login/dashboard cycle until login is cancelled, the app closes, or an error ends
    // startup.
    while (true) {
        try {
            app.setQuitOnLastWindowClosed(false);
            StartupTrace::note("Startup: opening login dialog.");
            LoginDialog loginDlg(roster);
            if (loginDlg.exec() != QDialog::Accepted) break;
            StartupTrace::note("Login: accepted; opening dashboard.");
            // Use only the identity returned by an accepted login to create the role-specific
            // dashboard.
            MainWindow window(loginDlg.getRole(), loginDlg.getStudentId(), loginDlg.getProfUser());
            // Once the dashboard is open, its close button should end the application.
            app.setQuitOnLastWindowClosed(true);
#ifdef Q_OS_ANDROID
            // Show the Android main window maximized; other builds use the normal requested
            // window size.
            window.showMaximized();
#else
            window.show();
#endif
            // Run Qt's event loop: it waits for clicks, edits, and timer events
            // until exit is requested.
            if (app.exec() != 1000) break;
            // After logout, reload the student roster so the next login uses the latest saved
            // passwords and records.
            if (!FileIO::loadStudents("students.txt", roster)) { Storage::report(); return 1; }
        // Catch load errors thrown by dialog/dashboard constructors, show their message, and exit
        // with code 1.
        } catch (const exception& error) {
            QMessageBox::critical(nullptr, "Cannot Open Database", QString::fromUtf8(error.what())); return 1;
        }
    }
    return 0;
}

// Start the Windows crash log, then run the application inside a final error guard.
// An unexpected C++ error during setup gets a visible message instead of vanishing.
int main(int argc, char *argv[]) {
    StartupTrace::start();
    try {
        const int result = runApplication(argc, argv);
        StartupTrace::note(result == 0 ? "Application ended normally." : "Application ended with a startup error.");
        return result;
    } catch (const std::exception& error) {
        StartupTrace::note("Startup failed with a C++ exception.");
#ifdef Q_OS_WIN
        const QString message = QString::fromUtf8(error.what());
        MessageBoxW(nullptr, reinterpret_cast<const wchar_t*>(message.utf16()), L"Cannot Start Application", MB_OK | MB_ICONERROR);
#endif
        return 1;
    } catch (...) {
        StartupTrace::note("Startup failed with an unknown exception.");
#ifdef Q_OS_WIN
        MessageBoxW(nullptr, L"An unexpected startup error occurred. Please check startup-diagnostic.log beside the EXE.", L"Cannot Start Application", MB_OK | MB_ICONERROR);
#endif
        return 1;
    }
}
