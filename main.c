#include <gtk/gtk.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <glib.h>
#include <errno.h>

// Versionsnummer
#define VERSION "1.2"

// Enum für Konfliktantworten
typedef enum {
    CONFLICT_OVERWRITE = 1,
    CONFLICT_OVERWRITE_ALL = 2,
    CONFLICT_SKIP = 3,
    CONFLICT_SKIP_ALL = 4,
    CONFLICT_ABORT = 5
} ConflictResponse;

// Struktur für die Anwendungsdaten
typedef struct {
    GtkWidget *local_tree;
    GtkWidget *remote_tree;
    GtkWidget *local_path_entry;
    GtkWidget *remote_path_entry;
    GtkWidget *host_entry;
    GtkWidget *user_entry;
    GtkWidget *password_entry;
    GtkWidget *port_entry;
    GtkWidget *key_file_entry;
    GtkWidget *protocol_combo;
    GtkWidget *connect_button;
    GtkWidget *status_label;
    GtkWidget *progress_bar;
    
    ssh_session session;
    sftp_session sftp;
    int connected;
    int use_scp;
    
    GtkListStore *local_store;
    GtkListStore *remote_store;
    
    // Konfliktbehandlung
    int overwrite_all;
    int skip_all;
    int copy_aborted;
} AppData;

// Globale Anwendungsdaten
static AppData *app_data = NULL;

// Funktionen-Deklarationen
void refresh_local_directory(AppData *data);
void refresh_remote_directory(AppData *data);
void refresh_remote_directory_scp(AppData *data);
void connect_ssh(AppData *data);
void disconnect_ssh(AppData *data);
void copy_file_to_remote(AppData *data, const char *local_path, const char *remote_path);
void copy_file_from_remote(AppData *data, const char *remote_path, const char *local_path);
void copy_file_to_remote_scp(AppData *data, const char *local_path, const char *remote_path);
void copy_file_from_remote_scp(AppData *data, const char *remote_path, const char *local_path);
void copy_directory_to_remote(AppData *data, const char *local_path, const char *remote_path);
void copy_directory_from_remote(AppData *data, const char *remote_path, const char *local_path);
void copy_directory_to_remote_sftp(AppData *data, const char *local_path, const char *remote_path);
void copy_directory_from_remote_sftp(AppData *data, const char *remote_path, const char *local_path);
void copy_directory_to_remote_scp(AppData *data, const char *local_path, const char *remote_path);
void copy_directory_from_remote_scp(AppData *data, const char *remote_path, const char *local_path);
void save_connection(AppData *data);
void load_connection(AppData *data, const char *name);
void load_connection_dialog(AppData *data);
gboolean load_connection_dialog_func(gpointer data);
void delete_connection(const char *name);
GList* get_saved_connection_names(void);
char* get_config_file_path(void);
char* prompt_key_file_password(void);
char* prompt_ssh_password(void);
void on_browse_key_file_clicked(GtkWidget *widget, gpointer data);
void on_support_clicked(GtkWidget *widget, gpointer data);
void delete_local_file(AppData *data, const char *path);
void delete_remote_file(AppData *data, const char *path);
void delete_local_directory_recursive(const char *path);
void delete_remote_directory_sftp(AppData *data, const char *path);
void delete_remote_directory_scp(AppData *data, const char *path);
void on_delete_local_clicked(GtkWidget *widget, gpointer data);
void on_delete_remote_clicked(GtkWidget *widget, gpointer data);
gboolean on_local_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data);
gboolean on_remote_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data);
void on_local_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data);
gboolean on_local_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data);
void on_remote_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data);
void on_remote_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data);
gboolean on_remote_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data);
void on_local_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data);
gboolean verify_ssh_fingerprint(ssh_session session, const char *host, int port);
char* get_known_hosts_file_path(void);
gboolean is_fingerprint_known(const char *host, int port, unsigned char *hash, size_t hlen);
void save_fingerprint(const char *host, int port, unsigned char *hash, size_t hlen);
void create_local_directory(AppData *data, const char *dirname);
void create_remote_directory(AppData *data, const char *dirname);
void on_mkdir_local_clicked(GtkWidget *widget, gpointer data);
void on_mkdir_remote_clicked(GtkWidget *widget, gpointer data);
ConflictResponse show_conflict_dialog(const char *filename, const char *local_size, const char *local_date, const char *remote_size, const char *remote_date);
ConflictResponse show_directory_conflict_dialog(const char *dirname);
void format_file_size(char *buffer, size_t size, uint64_t bytes);
void format_file_date(char *buffer, size_t size, time_t mtime);

// Helper-Funktionen für Progress Bar
void show_progress_bar(AppData *data) {
    gtk_widget_set_visible(data->progress_bar, TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), 0.0);
    gtk_progress_bar_set_text(GTK_PROGRESS_BAR(data->progress_bar), "");
}

void hide_progress_bar(AppData *data) {
    gtk_widget_set_visible(data->progress_bar, FALSE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), 0.0);
}

void update_progress_bar(AppData *data, double fraction, const char *text) {
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), fraction);
    if (text) {
        gtk_progress_bar_set_text(GTK_PROGRESS_BAR(data->progress_bar), text);
    }
    // GUI aktualisieren
    while (gtk_events_pending()) {
        gtk_main_iteration();
    }
}

// Callback für lokales Dateiverzeichnis aktualisieren
void on_local_refresh_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    refresh_local_directory(app);
}

// Callback für Remote-Dateiverzeichnis aktualisieren
void on_remote_refresh_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    if (app->connected) {
        refresh_remote_directory(app);
    } else {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Not connected!");
    }
}

// Lokales Verzeichnis aktualisieren
void refresh_local_directory(AppData *data) {
    gtk_list_store_clear(data->local_store);
    
    const char *path = gtk_entry_get_text(GTK_ENTRY(data->local_path_entry));
    if (strlen(path) == 0) {
        struct passwd *pw = getpwuid(getuid());
        path = pw->pw_dir;
        gtk_entry_set_text(GTK_ENTRY(data->local_path_entry), path);
    }
    
    // ".." Eintrag hinzufügen, wenn nicht im Root-Verzeichnis
    if (strcmp(path, "/") != 0) {
        GtkTreeIter iter;
        gtk_list_store_append(data->local_store, &iter);
        gtk_list_store_set(data->local_store, &iter,
                          0, "..",
                          1, "Directory",
                          2, "-",
                          -1);
    }
    
    DIR *dir = opendir(path);
    if (!dir) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Could not open directory");
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char full_path[1024];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) != 0) continue;
        
        GtkTreeIter iter;
        gtk_list_store_append(data->local_store, &iter);
        
        const char *type = S_ISDIR(st.st_mode) ? "Directory" : "File";
        char size_str[64];
        if (S_ISDIR(st.st_mode)) {
            snprintf(size_str, sizeof(size_str), "-");
        } else {
            snprintf(size_str, sizeof(size_str), "%ld", (long)st.st_size);
        }
        
        gtk_list_store_set(data->local_store, &iter,
                          0, entry->d_name,
                          1, type,
                          2, size_str,
                          -1);
    }
    closedir(dir);
    
    // Sortierung wieder auf Standard setzen (nach Dateiname)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(data->local_store), 0, GTK_SORT_ASCENDING);
    
    gtk_label_set_text(GTK_LABEL(data->status_label), "Local directory refreshed");
}

// Remote-Verzeichnis aktualisieren mit SCP (SSH-Befehl)
void refresh_remote_directory_scp(AppData *data) {
    gtk_list_store_clear(data->remote_store);
    
    const char *path = gtk_entry_get_text(GTK_ENTRY(data->remote_path_entry));
    if (strlen(path) == 0) {
        path = ".";
        gtk_entry_set_text(GTK_ENTRY(data->remote_path_entry), path);
    }
    
    // ".." Eintrag hinzufügen, wenn nicht im Root-Verzeichnis
    if (strcmp(path, "/") != 0 && strcmp(path, ".") != 0) {
        GtkTreeIter iter;
        gtk_list_store_append(data->remote_store, &iter);
        gtk_list_store_set(data->remote_store, &iter,
                          0, "..",
                          1, "Directory",
                          2, "-",
                          -1);
    }
    
    // SSH-Kanal erstellen und Befehl ausführen
    ssh_channel channel = ssh_channel_new(data->session);
    if (!channel) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Fehler beim Erstellen des SSH-Kanals: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error opening SSH session: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_channel_free(channel);
        return;
    }
    
    // Befehl ausführen: Verwende ls und stat für strukturierte Ausgabe
    // Format: "d 0 dirname" für Verzeichnisse, "f 1234 filename" für Dateien
    char command[1024];
    snprintf(command, sizeof(command), "cd '%s' && ls -1a | while read f; do if [ \"$f\" != \".\" ] && [ \"$f\" != \"..\" ]; then if [ -d \"$f\" ]; then echo \"d 0 $f\"; else echo \"f $(stat -c %%s \"$f\" 2>/dev/null || echo 0) $f\"; fi; fi; done", path);
    
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Fehler beim Ausführen des Befehls: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }
    
    // Ausgabe lesen (mehrere Reads falls nötig)
    char buffer[8192];
    int total_read = 0;
    int nbytes;
    
    while ((nbytes = ssh_channel_read(channel, buffer + total_read, sizeof(buffer) - total_read - 1, 0)) > 0) {
        total_read += nbytes;
        if (total_read >= (int)sizeof(buffer) - 1) break;
    }
    
    if (nbytes < 0 && total_read == 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Fehler beim Lesen: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }
    
    buffer[total_read] = '\0';
    
    // Ausgabe parsen: Format ist "d 0 filename" oder "f 1234 filename"
    char *line = strtok(buffer, "\n");
    
    while (line != NULL) {
        if (strlen(line) > 2) {
            // Prüfe erstes Zeichen für Typ
            char type_char = line[0];
            const char *type = (type_char == 'd') ? "Directory" : "File";
            
            // Finde die Größe (zwischen erstem und zweitem Leerzeichen)
            char *size_start = strchr(line, ' ');
            if (size_start) {
                size_start++; // Nach dem ersten Leerzeichen
                char *name_start = strchr(size_start, ' ');
                if (name_start) {
                    name_start++; // Nach dem zweiten Leerzeichen
                    
                    // Extrahiere Größe
                    size_t size_len = name_start - size_start - 1;
                    char size_str[64];
                    if (size_len > 0 && size_len < sizeof(size_str)) {
                        strncpy(size_str, size_start, size_len);
                        size_str[size_len] = '\0';
                    } else {
                        strcpy(size_str, "0");
                    }
                    
                    // Wenn es ein Verzeichnis ist, setze Größe auf "-"
                    if (type_char == 'd') {
                        strcpy(size_str, "-");
                    }
                    
                    GtkTreeIter iter;
                    gtk_list_store_append(data->remote_store, &iter);
                    gtk_list_store_set(data->remote_store, &iter,
                                      0, name_start,
                                      1, type,
                                      2, size_str,
                                      -1);
                }
            }
        }
        
        line = strtok(NULL, "\n");
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    // Sortierung wieder auf Standard setzen (nach Dateiname)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(data->remote_store), 0, GTK_SORT_ASCENDING);
    
    gtk_label_set_text(GTK_LABEL(data->status_label), "Remote directory refreshed");
}

// Remote-Verzeichnis aktualisieren
void refresh_remote_directory(AppData *data) {
    if (!data->connected) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    // Bei SCP verwenden wir SSH-Befehle für Verzeichnisauflistung
    if (data->use_scp) {
        refresh_remote_directory_scp(data);
        return;
    }
    
    if (!data->sftp) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "SFTP session not available!");
        return;
    }
    
    gtk_list_store_clear(data->remote_store);
    
    const char *path = gtk_entry_get_text(GTK_ENTRY(data->remote_path_entry));
    if (strlen(path) == 0) {
        path = ".";
        gtk_entry_set_text(GTK_ENTRY(data->remote_path_entry), path);
    }
    
    // ".." Eintrag hinzufügen, wenn nicht im Root-Verzeichnis
    if (strcmp(path, "/") != 0 && strcmp(path, ".") != 0) {
        GtkTreeIter iter;
        gtk_list_store_append(data->remote_store, &iter);
        gtk_list_store_set(data->remote_store, &iter,
                          0, "..",
                          1, "Directory",
                          2, "-",
                          -1);
    }
    
    sftp_dir dir = sftp_opendir(data->sftp, path);
    if (!dir) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error opening: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    sftp_attributes attributes;
    while ((attributes = sftp_readdir(data->sftp, dir)) != NULL) {
        if (attributes->name[0] == '.') {
            sftp_attributes_free(attributes);
            continue;
        }
        
        GtkTreeIter iter;
        gtk_list_store_append(data->remote_store, &iter);
        
        const char *type = (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) ? "Directory" : "File";
        char size_str[64];
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            snprintf(size_str, sizeof(size_str), "-");
        } else {
            snprintf(size_str, sizeof(size_str), "%llu", (unsigned long long)attributes->size);
        }
        
        gtk_list_store_set(data->remote_store, &iter,
                          0, attributes->name,
                          1, type,
                          2, size_str,
                          -1);
        
        sftp_attributes_free(attributes);
    }
    
    sftp_closedir(dir);
    
    // Sortierung wieder auf Standard setzen (nach Dateiname)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(data->remote_store), 0, GTK_SORT_ASCENDING);
    
    gtk_label_set_text(GTK_LABEL(data->status_label), "Remote directory refreshed");
}

// SSH-Verbindung herstellen
void connect_ssh(AppData *data) {
    if (data->connected) {
        disconnect_ssh(data);
        return;
    }
    
    const char *host = gtk_entry_get_text(GTK_ENTRY(data->host_entry));
    const char *user = gtk_entry_get_text(GTK_ENTRY(data->user_entry));
    const char *password = gtk_entry_get_text(GTK_ENTRY(data->password_entry));
    const char *port_str = gtk_entry_get_text(GTK_ENTRY(data->port_entry));
    
    int port = 22;
    if (strlen(port_str) > 0) {
        port = atoi(port_str);
    }
    
    if (strlen(host) == 0 || strlen(user) == 0) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Host and user required!");
        return;
    }
    
    data->session = ssh_new();
    if (!data->session) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating SSH session");
        return;
    }
    
    ssh_options_set(data->session, SSH_OPTIONS_HOST, host);
    ssh_options_set(data->session, SSH_OPTIONS_USER, user);
    ssh_options_set(data->session, SSH_OPTIONS_PORT, &port);
    
    if (ssh_connect(data->session) != SSH_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Connection error: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_free(data->session);
        data->session = NULL;
        return;
    }
    
    // Fingerprint-Überprüfung
    if (!verify_ssh_fingerprint(data->session, host, port)) {
        // Benutzer hat die Verbindung abgebrochen
        ssh_disconnect(data->session);
        ssh_free(data->session);
        data->session = NULL;
        return;
    }
    
    // Authentifizierung
    int auth_result = SSH_AUTH_ERROR;
    const char *key_file_path = gtk_entry_get_text(GTK_ENTRY(data->key_file_entry));
    
    // Versuche zuerst Key-File-Authentifizierung, wenn angegeben
    if (strlen(key_file_path) > 0) {
        ssh_key privkey = NULL;
        int rc = ssh_pki_import_privkey_file(key_file_path, NULL, NULL, NULL, &privkey);
        
        if (rc == SSH_OK && privkey != NULL) {
            // Key-File ist nicht passwortgeschützt
            auth_result = ssh_userauth_publickey(data->session, NULL, privkey);
            ssh_key_free(privkey);
        } else if (rc == SSH_EOF || rc == SSH_ERROR) {
            // Key-File ist möglicherweise passwortgeschützt, versuche mit Passwort
            char *key_password = prompt_key_file_password();
            if (key_password) {
                rc = ssh_pki_import_privkey_file(key_file_path, key_password, NULL, NULL, &privkey);
                if (rc == SSH_OK && privkey != NULL) {
                    auth_result = ssh_userauth_publickey(data->session, NULL, privkey);
                    ssh_key_free(privkey);
                }
                // Passwort löschen
                memset(key_password, 0, strlen(key_password));
                g_free(key_password);
            }
        }
    }
    
    // Falls Key-File-Auth fehlgeschlagen oder nicht angegeben
    if (auth_result != SSH_AUTH_SUCCESS) {
        // Wenn Passwort im Feld eingegeben wurde, versuche es direkt
    if (strlen(password) > 0) {
        auth_result = ssh_userauth_password(data->session, NULL, password);
    } else {
            // Kein Passwort im Feld - versuche erst ohne Passwort (automatische Public Key Auth)
        auth_result = ssh_userauth_autopubkey(data->session, NULL);
            
            // Falls das fehlgeschlagen ist, frage nach Passwort
            if (auth_result != SSH_AUTH_SUCCESS) {
                char *dialog_password = prompt_ssh_password();
                if (dialog_password) {
                    auth_result = ssh_userauth_password(data->session, NULL, dialog_password);
                    // Passwort löschen
                    memset(dialog_password, 0, strlen(dialog_password));
                    g_free(dialog_password);
                } else {
                    // Benutzer hat abgebrochen
                    gtk_label_set_text(GTK_LABEL(data->status_label), "Connection cancelled");
                    ssh_disconnect(data->session);
                    ssh_free(data->session);
                    data->session = NULL;
                    return;
                }
            }
        }
    }
    
    if (auth_result != SSH_AUTH_SUCCESS) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Authentication error: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_disconnect(data->session);
        ssh_free(data->session);
        data->session = NULL;
        return;
    }
    
    // Protokollauswahl auslesen
    int protocol_index = gtk_combo_box_get_active(GTK_COMBO_BOX(data->protocol_combo));
    data->use_scp = (protocol_index == 1); // 0 = SFTP, 1 = SCP
    
    // SFTP-Session nur erstellen, wenn SFTP gewählt wurde
    if (!data->use_scp) {
        // Prüfe, ob die SSH-Session noch gültig ist
        if (!data->session || ssh_is_connected(data->session) == 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "SSH session not connected. Cannot create SFTP session.");
            gtk_label_set_text(GTK_LABEL(data->status_label), msg);
            if (data->session) {
                ssh_disconnect(data->session);
                ssh_free(data->session);
                data->session = NULL;
            }
            return;
        }
        
    data->sftp = sftp_new(data->session);
    if (!data->sftp) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Error creating SFTP session: %s", ssh_get_error(data->session));
            gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_disconnect(data->session);
        ssh_free(data->session);
        data->session = NULL;
        return;
    }
    
        int sftp_init_result = sftp_init(data->sftp);
        if (sftp_init_result != SSH_OK) {
            char msg[512];
            const char *error_msg = ssh_get_error(data->session);
            
            // Spezielle Behandlung für "Channel request subsystem failed"
            if (error_msg && strstr(error_msg, "subsystem") != NULL) {
                snprintf(msg, sizeof(msg), 
                    "SFTP subsystem not available on server.\n\n"
                    "The server does not support SFTP or the SFTP subsystem is not enabled.\n"
                    "This is a server configuration issue.\n\n"
                    "Solution: Use SCP protocol instead (it works with your server).\n"
                    "The server administrator needs to enable the SFTP subsystem in sshd_config.");
            } else {
                snprintf(msg, sizeof(msg), 
                    "SFTP init error (code %d): %s\n\n"
                    "Note: Some servers may not support SFTP. Try using SCP protocol instead.", 
                    sftp_init_result, error_msg ? error_msg : "Unknown error");
            }
            
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        sftp_free(data->sftp);
            data->sftp = NULL;
        ssh_disconnect(data->session);
        ssh_free(data->session);
        data->session = NULL;
        return;
        }
    }
    
    data->connected = 1;
    gtk_button_set_label(GTK_BUTTON(data->connect_button), "Disconnect");
    gtk_label_set_text(GTK_LABEL(data->status_label), "Connected!");
    refresh_remote_directory(data);
}

// SSH-Verbindung trennen
void disconnect_ssh(AppData *data) {
    if (!data->connected) return;
    
    if (data->sftp) {
        sftp_free(data->sftp);
        data->sftp = NULL;
    }
    
    if (data->session) {
        ssh_disconnect(data->session);
        ssh_free(data->session);
        data->session = NULL;
    }
    
    data->connected = 0;
    gtk_button_set_label(GTK_BUTTON(data->connect_button), "Connect");
    gtk_label_set_text(GTK_LABEL(data->status_label), "Disconnected");
    gtk_list_store_clear(data->remote_store);
}

// Callback für Verbindungsbutton
void on_connect_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    if (app->connected) {
        disconnect_ssh(app);
    } else {
        connect_ssh(app);
    }
}

// SCP: Datei zu Remote kopieren
void copy_file_to_remote_scp(AppData *data, const char *local_path, const char *remote_path) {
    if (data->copy_aborted) {
        return;
    }
    
    if (!data->connected || !data->session) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    // Prüfe, ob lokale Datei existiert
    struct stat local_st;
    if (stat(local_path, &local_st) != 0 || !S_ISREG(local_st.st_mode)) {
        // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
        refresh_local_directory(data);
        return;
    }
    
    // Prüfe, ob Remote-Datei existiert
    if (!data->overwrite_all && !data->skip_all) {
        ssh_channel channel = ssh_channel_new(data->session);
        if (channel && ssh_channel_open_session(channel) == SSH_OK) {
            char test_command[2048];
            snprintf(test_command, sizeof(test_command), "test -f '%s' && stat -c '%%s|%%Y' '%s' || echo ''", remote_path, remote_path);
            
            if (ssh_channel_request_exec(channel, test_command) == SSH_OK) {
                char buffer[256];
                int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
                if (nbytes > 0) {
                    buffer[nbytes] = '\0';
                    // Entferne Newline
                    char *newline = strchr(buffer, '\n');
                    if (newline) *newline = '\0';
                    
                    if (strlen(buffer) > 0) {
                        // Remote-Datei existiert
                        struct stat local_st;
                        if (stat(local_path, &local_st) == 0 && S_ISREG(local_st.st_mode)) {
                            // Parse Remote-Info: "size|mtime"
                            char *pipe_pos = strchr(buffer, '|');
                            if (pipe_pos) {
                                *pipe_pos = '\0';
                                uint64_t remote_size = strtoull(buffer, NULL, 10);
                                time_t remote_mtime = (time_t)strtoull(pipe_pos + 1, NULL, 10);
                                
                                char local_size_str[64];
                                char local_date_str[64];
                                char remote_size_str[64];
                                char remote_date_str[64];
                                
                                format_file_size(local_size_str, sizeof(local_size_str), local_st.st_size);
                                format_file_date(local_date_str, sizeof(local_date_str), local_st.st_mtime);
                                format_file_size(remote_size_str, sizeof(remote_size_str), remote_size);
                                format_file_date(remote_date_str, sizeof(remote_date_str), remote_mtime);
                                
                                const char *filename = strrchr(remote_path, '/');
                                filename = filename ? filename + 1 : remote_path;
                                
                                ConflictResponse response = show_conflict_dialog(filename, local_size_str, local_date_str, remote_size_str, remote_date_str);
                                
                                ssh_channel_send_eof(channel);
                                ssh_channel_close(channel);
                                ssh_channel_free(channel);
                                
                                if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
                                    if (response == CONFLICT_SKIP_ALL) {
                                        data->skip_all = 1;
                                    }
                                    return;
                                } else if (response == CONFLICT_OVERWRITE_ALL) {
                                    data->overwrite_all = 1;
                                } else if (response == CONFLICT_ABORT) {
                                    data->copy_aborted = 1;
                                    return;
                                }
                            }
                        }
                    }
                }
            }
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        } else if (channel) {
            ssh_channel_free(channel);
        }
    }
    
    FILE *local_file = fopen(local_path, "rb");
    if (!local_file) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Could not open local file");
        return;
    }
    
    // Dateigröße ermitteln
    fseek(local_file, 0, SEEK_END);
    long file_size = ftell(local_file);
    fseek(local_file, 0, SEEK_SET);
    
    // Progress Bar anzeigen
    show_progress_bar(data);
    char progress_text[256];
    snprintf(progress_text, sizeof(progress_text), "Copying... 0 / %ld Bytes", file_size);
    update_progress_bar(data, 0.0, progress_text);
    
    // SCP-Session erstellen
    ssh_scp scp = ssh_scp_new(data->session, SSH_SCP_WRITE, remote_path);
    if (!scp) {
        fclose(local_file);
        char msg[256];
        snprintf(msg, sizeof(msg), "Fehler beim Erstellen der SCP-Session: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    if (ssh_scp_init(scp) != SSH_OK) {
        fclose(local_file);
        char msg[256];
        snprintf(msg, sizeof(msg), "SCP-Init-Fehler: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_scp_free(scp);
        return;
    }
    
    // Datei senden
    const char *filename = strrchr(local_path, '/');
    filename = filename ? filename + 1 : local_path;
    
    if (ssh_scp_push_file(scp, filename, file_size, S_IRUSR | S_IWUSR) != SSH_OK) {
        fclose(local_file);
        char msg[256];
        snprintf(msg, sizeof(msg), "SCP-Push-Fehler: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return;
    }
    
    char buffer[8192];
    size_t bytes_read;
    long total_written = 0;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), local_file)) > 0) {
        if (ssh_scp_write(scp, buffer, bytes_read) != SSH_OK) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error writing");
            hide_progress_bar(data);
            break;
        }
        
        total_written += bytes_read;
        if (file_size > 0) {
            double fraction = (double)total_written / (double)file_size;
            snprintf(progress_text, sizeof(progress_text), "Copying... %ld / %ld Bytes (%.1f%%)", 
                     total_written, file_size, fraction * 100.0);
            update_progress_bar(data, fraction, progress_text);
        }
    }
    
    fclose(local_file);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    hide_progress_bar(data);
    gtk_label_set_text(GTK_LABEL(data->status_label), "File copied!");
}

// SCP: Datei von Remote kopieren
void copy_file_from_remote_scp(AppData *data, const char *remote_path, const char *local_path) {
    if (data->copy_aborted) {
        return;
    }
    
    if (!data->connected || !data->session) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    // Prüfe, ob Remote-Datei existiert
    ssh_channel channel = ssh_channel_new(data->session);
    if (channel && ssh_channel_open_session(channel) == SSH_OK) {
        char test_cmd[2048];
        snprintf(test_cmd, sizeof(test_cmd), "test -f '%s' && echo 'exists' || echo ''", remote_path);
        
        if (ssh_channel_request_exec(channel, test_cmd) == SSH_OK) {
            char buffer[64];
            int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
            if (nbytes > 0) {
                buffer[nbytes] = '\0';
                char *newline = strchr(buffer, '\n');
                if (newline) *newline = '\0';
                
                if (strcmp(buffer, "exists") != 0) {
                    // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    refresh_remote_directory(data);
                    return;
                }
            }
        }
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    } else if (channel) {
        ssh_channel_free(channel);
    }
    
    // Prüfe, ob lokale Datei existiert
    struct stat local_st;
    int local_exists = (stat(local_path, &local_st) == 0 && S_ISREG(local_st.st_mode));
    
    if (local_exists && !data->overwrite_all && !data->skip_all) {
        // Hole Remote-Datei-Informationen
        channel = ssh_channel_new(data->session);
        if (channel && ssh_channel_open_session(channel) == SSH_OK) {
            char stat_command[2048];
            snprintf(stat_command, sizeof(stat_command), "stat -c '%%s|%%Y' '%s' 2>/dev/null || echo ''", remote_path);
            
            if (ssh_channel_request_exec(channel, stat_command) == SSH_OK) {
                char buffer[256];
                int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
                if (nbytes > 0) {
                    buffer[nbytes] = '\0';
                    char *newline = strchr(buffer, '\n');
                    if (newline) *newline = '\0';
                    
                    if (strlen(buffer) > 0) {
                        // Parse Remote-Info: "size|mtime"
                        char *pipe_pos = strchr(buffer, '|');
                        if (pipe_pos) {
                            *pipe_pos = '\0';
                            uint64_t remote_size = strtoull(buffer, NULL, 10);
                            time_t remote_mtime = (time_t)strtoull(pipe_pos + 1, NULL, 10);
                            
                            char local_size_str[64];
                            char local_date_str[64];
                            char remote_size_str[64];
                            char remote_date_str[64];
                            
                            format_file_size(local_size_str, sizeof(local_size_str), local_st.st_size);
                            format_file_date(local_date_str, sizeof(local_date_str), local_st.st_mtime);
                            format_file_size(remote_size_str, sizeof(remote_size_str), remote_size);
                            format_file_date(remote_date_str, sizeof(remote_date_str), remote_mtime);
                            
                            const char *filename = strrchr(local_path, '/');
                            filename = filename ? filename + 1 : local_path;
                            
                            ConflictResponse response = show_conflict_dialog(filename, remote_size_str, remote_date_str, local_size_str, local_date_str);
                            
                            ssh_channel_send_eof(channel);
                            ssh_channel_close(channel);
                            ssh_channel_free(channel);
                            
                            if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
                                if (response == CONFLICT_SKIP_ALL) {
                                    data->skip_all = 1;
                                }
                                return;
                            } else if (response == CONFLICT_OVERWRITE_ALL) {
                                data->overwrite_all = 1;
                            } else if (response == CONFLICT_ABORT) {
                                data->copy_aborted = 1;
                                return;
                            }
                        }
                    }
                }
            }
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        } else if (channel) {
            ssh_channel_free(channel);
        }
    }
    
    // SCP-Session erstellen
    ssh_scp scp = ssh_scp_new(data->session, SSH_SCP_READ, remote_path);
    if (!scp) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Fehler beim Erstellen der SCP-Session: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    if (ssh_scp_init(scp) != SSH_OK) {
        char msg[256];
        snprintf(msg, sizeof(msg), "SCP-Init-Fehler: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_scp_free(scp);
        return;
    }
    
    // Pull-Request senden
    if (ssh_scp_pull_request(scp) != SSH_SCP_REQUEST_NEWFILE) {
        char msg[256];
        snprintf(msg, sizeof(msg), "SCP pull error: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        return;
    }
    
    FILE *local_file = fopen(local_path, "wb");
    if (!local_file) {
        ssh_scp_close(scp);
        ssh_scp_free(scp);
        gtk_label_set_text(GTK_LABEL(data->status_label), "Could not create local file");
        return;
    }
    
    // Accept file
    ssh_scp_accept_request(scp);
    
    size_t file_size = ssh_scp_request_get_size(scp);
    
    // Progress Bar anzeigen
    show_progress_bar(data);
    char progress_text[256];
    snprintf(progress_text, sizeof(progress_text), "Loading... 0 / %zu Bytes", file_size);
    update_progress_bar(data, 0.0, progress_text);
    
    char buffer[8192];
    size_t bytes_read;
    size_t total_read = 0;
    
    while (total_read < file_size) {
        size_t to_read = (file_size - total_read < sizeof(buffer)) ? 
                         (file_size - total_read) : sizeof(buffer);
        int result = ssh_scp_read(scp, buffer, to_read);
        
        if (result == SSH_ERROR) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error reading");
            hide_progress_bar(data);
            break;
        }
        
        bytes_read = (size_t)result;
        
        if (fwrite(buffer, 1, bytes_read, local_file) != bytes_read) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error writing");
            hide_progress_bar(data);
            break;
        }
        
        total_read += bytes_read;
        
        // Fortschritt aktualisieren
        if (file_size > 0) {
            double fraction = (double)total_read / (double)file_size;
            snprintf(progress_text, sizeof(progress_text), "Loading... %zu / %zu Bytes (%.1f%%)", 
                     total_read, file_size, fraction * 100.0);
            update_progress_bar(data, fraction, progress_text);
        }
    }
    
    fclose(local_file);
    ssh_scp_close(scp);
    ssh_scp_free(scp);
    hide_progress_bar(data);
    gtk_label_set_text(GTK_LABEL(data->status_label), "File copied!");
    refresh_local_directory(data);
}

// Konfliktdialog anzeigen
ConflictResponse show_conflict_dialog(const char *filename, const char *local_size, const char *local_date, const char *remote_size, const char *remote_date) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("File Conflict",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Overwrite", CONFLICT_OVERWRITE,
                                                     "Overwrite All", CONFLICT_OVERWRITE_ALL,
                                                     "Skip", CONFLICT_SKIP,
                                                     "Skip All", CONFLICT_SKIP_ALL,
                                                     "Abort", CONFLICT_ABORT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
    
    char msg[512];
    snprintf(msg, sizeof(msg), "File already exists:\n%s", filename);
    GtkWidget *label = gtk_label_new(msg);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    // Lokale Datei-Info
    char local_info[256];
    snprintf(local_info, sizeof(local_info), "Local:  %s  %s", local_size, local_date);
    label = gtk_label_new(local_info);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    // Remote Datei-Info
    char remote_info[256];
    snprintf(remote_info, sizeof(remote_info), "Remote: %s  %s", remote_size, remote_date);
    label = gtk_label_new(remote_info);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(content), vbox);
    gtk_widget_show_all(dialog);
    
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    
    return (ConflictResponse)response;
}

// Verzeichnis-Konfliktdialog anzeigen
ConflictResponse show_directory_conflict_dialog(const char *dirname) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Directory Conflict",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Overwrite", CONFLICT_OVERWRITE,
                                                     "Overwrite All", CONFLICT_OVERWRITE_ALL,
                                                     "Skip", CONFLICT_SKIP,
                                                     "Skip All", CONFLICT_SKIP_ALL,
                                                     "Abort", CONFLICT_ABORT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    
    char msg[512];
    snprintf(msg, sizeof(msg), "Directory already exists:\n%s", dirname);
    GtkWidget *label = gtk_label_new(msg);
    gtk_label_set_line_wrap(GTK_LABEL(label), TRUE);
    gtk_container_add(GTK_CONTAINER(content), label);
    
    gtk_widget_show_all(dialog);
    
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    
    return (ConflictResponse)response;
}

// Format Dateigröße
void format_file_size(char *buffer, size_t size, uint64_t bytes) {
    if (bytes < 1024) {
        snprintf(buffer, size, "%llu B", (unsigned long long)bytes);
    } else if (bytes < 1024 * 1024) {
        snprintf(buffer, size, "%.1f KB", bytes / 1024.0);
    } else if (bytes < 1024ULL * 1024 * 1024) {
        snprintf(buffer, size, "%.1f MB", bytes / (1024.0 * 1024.0));
    } else {
        snprintf(buffer, size, "%.1f GB", bytes / (1024.0 * 1024.0 * 1024.0));
    }
}

// Format Datum
void format_file_date(char *buffer, size_t size, time_t mtime) {
    struct tm *tm_info = localtime(&mtime);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

// Datei zu Remote kopieren
void copy_file_to_remote(AppData *data, const char *local_path, const char *remote_path) {
    if (data->copy_aborted) {
        return;
    }
    
    if (data->use_scp) {
        copy_file_to_remote_scp(data, local_path, remote_path);
        return;
    }
    
    // SFTP-Implementierung
    if (!data->connected || !data->sftp) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    // Prüfe, ob lokale Datei existiert
    struct stat local_st;
    if (stat(local_path, &local_st) != 0 || !S_ISREG(local_st.st_mode)) {
        // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
        refresh_local_directory(data);
        return;
    }
    
    // Prüfe, ob Remote-Datei existiert
    sftp_attributes remote_attrs = sftp_stat(data->sftp, remote_path);
    if (remote_attrs && !data->overwrite_all && !data->skip_all) {
        // Konflikt: Datei existiert bereits
        struct stat local_st;
        if (stat(local_path, &local_st) == 0 && S_ISREG(local_st.st_mode)) {
            char local_size_str[64];
            char local_date_str[64];
            char remote_size_str[64];
            char remote_date_str[64];
            
            format_file_size(local_size_str, sizeof(local_size_str), local_st.st_size);
            format_file_date(local_date_str, sizeof(local_date_str), local_st.st_mtime);
            format_file_size(remote_size_str, sizeof(remote_size_str), remote_attrs->size);
            format_file_date(remote_date_str, sizeof(remote_date_str), remote_attrs->mtime);
            
            const char *filename = strrchr(remote_path, '/');
            filename = filename ? filename + 1 : remote_path;
            
            ConflictResponse response = show_conflict_dialog(filename, local_size_str, local_date_str, remote_size_str, remote_date_str);
            
            if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
                sftp_attributes_free(remote_attrs);
                if (response == CONFLICT_SKIP_ALL) {
                    data->skip_all = 1;
                }
                return;
            } else if (response == CONFLICT_OVERWRITE_ALL) {
                data->overwrite_all = 1;
            } else if (response == CONFLICT_ABORT) {
                data->copy_aborted = 1;
                sftp_attributes_free(remote_attrs);
                return;
            }
        }
    }
    if (remote_attrs) {
        sftp_attributes_free(remote_attrs);
    }
    
    FILE *local_file = fopen(local_path, "rb");
    if (!local_file) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Could not open local file");
        return;
    }
    
    // Dateigröße ermitteln
    fseek(local_file, 0, SEEK_END);
    long file_size = ftell(local_file);
    fseek(local_file, 0, SEEK_SET);
    
    sftp_file remote_file = sftp_open(data->sftp, remote_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (!remote_file) {
        fclose(local_file);
        char msg[256];
        snprintf(msg, sizeof(msg), "Error opening remote file: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    // Progress Bar anzeigen
    show_progress_bar(data);
    char progress_text[256];
    snprintf(progress_text, sizeof(progress_text), "Copying... 0 / %ld Bytes", file_size);
    update_progress_bar(data, 0.0, progress_text);
    
    char buffer[8192];
    size_t bytes_read;
    ssize_t bytes_written;
    long total_written = 0;
    
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), local_file)) > 0) {
        bytes_written = sftp_write(remote_file, buffer, bytes_read);
        if (bytes_written != (ssize_t)bytes_read) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error writing");
            hide_progress_bar(data);
            break;
        }
        
        total_written += bytes_written;
        // Fortschritt aktualisieren
        if (file_size > 0) {
            double fraction = (double)total_written / (double)file_size;
            snprintf(progress_text, sizeof(progress_text), "Copying... %ld / %ld Bytes (%.1f%%)", 
                     total_written, file_size, fraction * 100.0);
            update_progress_bar(data, fraction, progress_text);
        }
    }
    
    fclose(local_file);
    sftp_close(remote_file);
    hide_progress_bar(data);
    gtk_label_set_text(GTK_LABEL(data->status_label), "File copied!");
    refresh_remote_directory(data);
}

// Datei von Remote kopieren
void copy_file_from_remote(AppData *data, const char *remote_path, const char *local_path) {
    if (data->copy_aborted) {
        return;
    }
    
    if (data->use_scp) {
        copy_file_from_remote_scp(data, remote_path, local_path);
        return;
    }
    
    // SFTP-Implementierung
    if (!data->connected || !data->sftp) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    // Prüfe, ob Remote-Datei existiert
    sftp_attributes remote_attrs = sftp_stat(data->sftp, remote_path);
    if (!remote_attrs) {
        // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
        refresh_remote_directory(data);
        return;
    }
    
    // Prüfe, ob lokale Datei existiert
    struct stat local_st;
    int local_exists = (stat(local_path, &local_st) == 0 && S_ISREG(local_st.st_mode));
    if (local_exists && remote_attrs && !data->overwrite_all && !data->skip_all) {
        // Konflikt: Datei existiert bereits
        char local_size_str[64];
        char local_date_str[64];
        char remote_size_str[64];
        char remote_date_str[64];
        
        format_file_size(local_size_str, sizeof(local_size_str), local_st.st_size);
        format_file_date(local_date_str, sizeof(local_date_str), local_st.st_mtime);
        format_file_size(remote_size_str, sizeof(remote_size_str), remote_attrs->size);
        format_file_date(remote_date_str, sizeof(remote_date_str), remote_attrs->mtime);
        
        const char *filename = strrchr(local_path, '/');
        filename = filename ? filename + 1 : local_path;
        
        ConflictResponse response = show_conflict_dialog(filename, remote_size_str, remote_date_str, local_size_str, local_date_str);
        
        if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
            sftp_attributes_free(remote_attrs);
            if (response == CONFLICT_SKIP_ALL) {
                data->skip_all = 1;
            }
            return;
        } else if (response == CONFLICT_OVERWRITE_ALL) {
            data->overwrite_all = 1;
        } else if (response == CONFLICT_ABORT) {
            data->copy_aborted = 1;
            sftp_attributes_free(remote_attrs);
            return;
        }
    }
    
    sftp_file remote_file = sftp_open(data->sftp, remote_path, O_RDONLY, 0);
    if (!remote_file) {
        if (remote_attrs) sftp_attributes_free(remote_attrs);
        char msg[256];
        snprintf(msg, sizeof(msg), "Error opening: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    // Dateigröße ermitteln
    sftp_attributes attrs = sftp_fstat(remote_file);
    uint64_t file_size = attrs ? attrs->size : 0;
    if (attrs) sftp_attributes_free(attrs);
    if (remote_attrs) sftp_attributes_free(remote_attrs);
    
    FILE *local_file = fopen(local_path, "wb");
    if (!local_file) {
        sftp_close(remote_file);
        gtk_label_set_text(GTK_LABEL(data->status_label), "Could not create local file");
        return;
    }
    
    // Progress Bar anzeigen
    show_progress_bar(data);
    char progress_text[256];
    snprintf(progress_text, sizeof(progress_text), "Loading... 0 / %llu Bytes", (unsigned long long)file_size);
    update_progress_bar(data, 0.0, progress_text);
    
    char buffer[8192];
    ssize_t bytes_read;
    size_t bytes_written;
    uint64_t total_read = 0;
    
    while ((bytes_read = sftp_read(remote_file, buffer, sizeof(buffer))) > 0) {
        bytes_written = fwrite(buffer, 1, bytes_read, local_file);
        if (bytes_written != (size_t)bytes_read) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error writing");
            hide_progress_bar(data);
            break;
        }
        
        total_read += bytes_read;
        // Fortschritt aktualisieren
        if (file_size > 0) {
            double fraction = (double)total_read / (double)file_size;
            snprintf(progress_text, sizeof(progress_text), "Loading... %llu / %llu Bytes (%.1f%%)", 
                     (unsigned long long)total_read, (unsigned long long)file_size, fraction * 100.0);
            update_progress_bar(data, fraction, progress_text);
        }
    }
    
    sftp_close(remote_file);
    fclose(local_file);
    hide_progress_bar(data);
    gtk_label_set_text(GTK_LABEL(data->status_label), "File copied!");
    refresh_local_directory(data);
}

// Rekursives Kopieren eines Verzeichnisses nach Remote (SFTP)
void copy_directory_to_remote_sftp(AppData *data, const char *local_path, const char *remote_path) {
    if (data->copy_aborted) {
        return;
    }
    
    // Progress Bar für Verzeichnis-Kopie (unbestimmter Fortschritt)
    // Nur beim ersten Aufruf anzeigen
    static int depth = 0;
    if (!data || !data->progress_bar) {
        return;
    }
    if (depth == 0) {
        show_progress_bar(data);
        gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(data->progress_bar), 0.1);
        update_progress_bar(data, 0.0, "Copying directory...");
    }
    depth++;
    
    // Prüfe, ob Remote-Verzeichnis existiert
    sftp_attributes remote_attrs = sftp_stat(data->sftp, remote_path);
    if (remote_attrs && remote_attrs->type == SSH_FILEXFER_TYPE_DIRECTORY && depth == 1 && !data->overwrite_all && !data->skip_all) {
        // Konflikt: Verzeichnis existiert bereits (nur beim ersten Level prüfen)
        const char *dirname = strrchr(remote_path, '/');
        dirname = dirname ? dirname + 1 : remote_path;
        
        ConflictResponse response = show_directory_conflict_dialog(dirname);
        sftp_attributes_free(remote_attrs);
        
        if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            if (response == CONFLICT_SKIP_ALL) {
                data->skip_all = 1;
            }
            return;
        } else if (response == CONFLICT_OVERWRITE_ALL) {
            data->overwrite_all = 1;
        } else if (response == CONFLICT_ABORT) {
            data->copy_aborted = 1;
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            return;
        }
    } else if (remote_attrs) {
        sftp_attributes_free(remote_attrs);
    }
    
    // Erstelle Remote-Verzeichnis
    int mode = S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH;
    if (sftp_mkdir(data->sftp, remote_path, mode) != SSH_OK) {
        // Verzeichnis existiert möglicherweise bereits, ignoriere Fehler
        if (sftp_get_error(data->sftp) != SSH_FX_FILE_ALREADY_EXISTS) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Error creating directory: %s", ssh_get_error(data->session));
            gtk_label_set_text(GTK_LABEL(data->status_label), msg);
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            return;
        }
    }
    
    // Öffne lokales Verzeichnis
    DIR *dir = opendir(local_path);
    if (!dir) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Could not open directory: %s", local_path);
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char local_full[2048];
        char remote_full[2048];
        snprintf(local_full, sizeof(local_full), "%s/%s", local_path, entry->d_name);
        snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_path, entry->d_name);
        
        struct stat st;
        if (stat(local_full, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            // Rekursiv Verzeichnis kopieren
            copy_directory_to_remote_sftp(data, local_full, remote_full);
        } else {
            // Datei kopieren
            copy_file_to_remote(data, local_full, remote_full);
        }
        
        // Pulse für unbestimmten Fortschritt
        if (depth == 1 && data && data->progress_bar) {
            gtk_progress_bar_pulse(GTK_PROGRESS_BAR(data->progress_bar));
            while (gtk_events_pending()) {
                gtk_main_iteration();
            }
        }
    }
    
    closedir(dir);
    depth--;
    if (depth == 0 && data && data->progress_bar) {
        hide_progress_bar(data);
        if (data->status_label) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Directory copied!");
        }
        refresh_remote_directory(data);
    }
}

// Rekursives Kopieren eines Verzeichnisses von Remote (SFTP)
void copy_directory_from_remote_sftp(AppData *data, const char *remote_path, const char *local_path) {
    if (data->copy_aborted) {
        return;
    }
    
    // Progress Bar für Verzeichnis-Kopie (unbestimmter Fortschritt)
    static int depth = 0;
    if (!data || !data->progress_bar) {
        return;
    }
    if (depth == 0) {
        show_progress_bar(data);
        gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(data->progress_bar), 0.1);
        update_progress_bar(data, 0.0, "Loading directory...");
    }
    depth++;
    
    // Prüfe, ob lokales Verzeichnis existiert (nur beim ersten Level)
    struct stat st;
    int dir_exists = (stat(local_path, &st) == 0 && S_ISDIR(st.st_mode));
    if (dir_exists && depth == 1 && !data->overwrite_all && !data->skip_all) {
        // Konflikt: Verzeichnis existiert bereits
        const char *dirname = strrchr(local_path, '/');
        dirname = dirname ? dirname + 1 : local_path;
        
        ConflictResponse response = show_directory_conflict_dialog(dirname);
        
        if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            if (response == CONFLICT_SKIP_ALL) {
                data->skip_all = 1;
            }
            return;
        } else if (response == CONFLICT_OVERWRITE_ALL) {
            data->overwrite_all = 1;
        } else if (response == CONFLICT_ABORT) {
            data->copy_aborted = 1;
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            return;
        }
    }
    
    // Erstelle lokales Verzeichnis
    if (mkdir(local_path, 0755) != 0 && errno != EEXIST) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error creating directory: %s", local_path);
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    // Öffne Remote-Verzeichnis
    sftp_dir dir = sftp_opendir(data->sftp, remote_path);
    if (!dir) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error opening: %s", ssh_get_error(data->session));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    sftp_attributes attributes;
    while ((attributes = sftp_readdir(data->sftp, dir)) != NULL) {
        if (attributes->name[0] == '.') {
            sftp_attributes_free(attributes);
            continue;
        }
        
        char remote_full[2048];
        char local_full[2048];
        snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_path, attributes->name);
        snprintf(local_full, sizeof(local_full), "%s/%s", local_path, attributes->name);
        
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            // Rekursiv Verzeichnis kopieren
            copy_directory_from_remote_sftp(data, remote_full, local_full);
        } else {
            // Datei kopieren
            copy_file_from_remote(data, remote_full, local_full);
        }
        
        sftp_attributes_free(attributes);
        
        // Pulse für unbestimmten Fortschritt
        if (depth == 1 && data && data->progress_bar) {
            gtk_progress_bar_pulse(GTK_PROGRESS_BAR(data->progress_bar));
            while (gtk_events_pending()) {
                gtk_main_iteration();
            }
        }
    }
    
    sftp_closedir(dir);
    depth--;
    if (depth == 0 && data && data->progress_bar) {
        hide_progress_bar(data);
        if (data->status_label) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Directory copied!");
        }
        refresh_local_directory(data);
    }
}

// Rekursives Kopieren eines Verzeichnisses nach Remote (SCP)
// Verwende rekursive Datei-Kopie über normale SCP-Funktionen
void copy_directory_to_remote_scp(AppData *data, const char *local_path, const char *remote_path) {
    if (data->copy_aborted) {
        return;
    }
    
    // Progress Bar für Verzeichnis-Kopie
    static int depth = 0;
    if (!data || !data->progress_bar) {
        return;
    }
    if (depth == 0) {
        show_progress_bar(data);
        gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(data->progress_bar), 0.1);
        update_progress_bar(data, 0.0, "Copying directory...");
    }
    depth++;
    
    // Prüfe, ob Remote-Verzeichnis existiert (nur beim ersten Level)
    if (depth == 1 && !data->overwrite_all && !data->skip_all) {
        ssh_channel channel = ssh_channel_new(data->session);
        if (channel && ssh_channel_open_session(channel) == SSH_OK) {
            char test_cmd[2048];
            snprintf(test_cmd, sizeof(test_cmd), "test -d '%s' && echo 'exists' || echo ''", remote_path);
            
            if (ssh_channel_request_exec(channel, test_cmd) == SSH_OK) {
                char buffer[64];
                int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
                if (nbytes > 0) {
                    buffer[nbytes] = '\0';
                    char *newline = strchr(buffer, '\n');
                    if (newline) *newline = '\0';
                    
                    if (strcmp(buffer, "exists") == 0) {
                        // Verzeichnis existiert
                        const char *dirname = strrchr(remote_path, '/');
                        dirname = dirname ? dirname + 1 : remote_path;
                        
                        ssh_channel_send_eof(channel);
                        ssh_channel_close(channel);
                        ssh_channel_free(channel);
                        
                        ConflictResponse response = show_directory_conflict_dialog(dirname);
                        
                        if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
                            if (depth == 1) {
                                hide_progress_bar(data);
                            }
                            depth--;
                            if (response == CONFLICT_SKIP_ALL) {
                                data->skip_all = 1;
                            }
                            return;
                        } else if (response == CONFLICT_OVERWRITE_ALL) {
                            data->overwrite_all = 1;
                        } else if (response == CONFLICT_ABORT) {
                            data->copy_aborted = 1;
                            if (depth == 1) {
                                hide_progress_bar(data);
                            }
                            depth--;
                            return;
                        }
                    }
                }
            }
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        } else if (channel) {
            ssh_channel_free(channel);
        }
    }
    
    // Erstelle Remote-Verzeichnis über SSH-Befehl
    ssh_channel channel = ssh_channel_new(data->session);
    if (!channel) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating SSH channel");
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error opening SSH session");
        ssh_channel_free(channel);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    // Erstelle Remote-Verzeichnis
    char mkdir_cmd[2048];
    snprintf(mkdir_cmd, sizeof(mkdir_cmd), "mkdir -p '%s'", remote_path);
    ssh_channel_request_exec(channel, mkdir_cmd);
    ssh_channel_read(channel, NULL, 0, 0);
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    // Öffne lokales Verzeichnis und kopiere rekursiv
    DIR *dir = opendir(local_path);
    if (!dir) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Could not open directory: %s", local_path);
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;
        
        char local_full[2048];
        char remote_full[2048];
        snprintf(local_full, sizeof(local_full), "%s/%s", local_path, entry->d_name);
        snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_path, entry->d_name);
        
        struct stat st;
        if (stat(local_full, &st) != 0) continue;
        
        if (S_ISDIR(st.st_mode)) {
            // Rekursiv Verzeichnis kopieren
            copy_directory_to_remote_scp(data, local_full, remote_full);
        } else {
            // Datei kopieren
            copy_file_to_remote_scp(data, local_full, remote_full);
        }
        
        // Pulse für unbestimmten Fortschritt
        if (depth == 1 && data && data->progress_bar) {
            gtk_progress_bar_pulse(GTK_PROGRESS_BAR(data->progress_bar));
            while (gtk_events_pending()) {
                gtk_main_iteration();
            }
        }
    }
    
    closedir(dir);
    depth--;
    if (depth == 0 && data && data->progress_bar) {
        hide_progress_bar(data);
        if (data->status_label) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Directory copied!");
        }
        refresh_remote_directory(data);
    }
}

// Rekursives Kopieren eines Verzeichnisses von Remote (SCP)
// Verwende rekursive Datei-Kopie über normale SCP-Funktionen und SSH-Befehle für Verzeichnisauflistung
void copy_directory_from_remote_scp(AppData *data, const char *remote_path, const char *local_path) {
    if (data->copy_aborted) {
        return;
    }
    
    // Progress Bar für Verzeichnis-Kopie
    static int depth = 0;
    if (!data || !data->progress_bar) {
        return;
    }
    if (depth == 0) {
        show_progress_bar(data);
        gtk_progress_bar_set_pulse_step(GTK_PROGRESS_BAR(data->progress_bar), 0.1);
        update_progress_bar(data, 0.0, "Loading directory...");
    }
    depth++;
    
    // Prüfe, ob lokales Verzeichnis existiert (nur beim ersten Level)
    struct stat st;
    int dir_exists = (stat(local_path, &st) == 0 && S_ISDIR(st.st_mode));
    if (dir_exists && depth == 1 && !data->overwrite_all && !data->skip_all) {
        // Konflikt: Verzeichnis existiert bereits
        const char *dirname = strrchr(local_path, '/');
        dirname = dirname ? dirname + 1 : local_path;
        
        ConflictResponse response = show_directory_conflict_dialog(dirname);
        
        if (response == CONFLICT_SKIP || response == CONFLICT_SKIP_ALL) {
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            if (response == CONFLICT_SKIP_ALL) {
                data->skip_all = 1;
            }
            return;
        } else if (response == CONFLICT_OVERWRITE_ALL) {
            data->overwrite_all = 1;
        } else if (response == CONFLICT_ABORT) {
            data->copy_aborted = 1;
            if (depth == 1) {
                hide_progress_bar(data);
            }
            depth--;
            return;
        }
    }
    
    // Erstelle lokales Verzeichnis
    if (mkdir(local_path, 0755) != 0 && errno != EEXIST) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error creating directory: %s", local_path);
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    // Liste Remote-Verzeichnis auf über SSH-Befehl
    ssh_channel channel = ssh_channel_new(data->session);
    if (!channel) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating SSH channel");
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error opening SSH session");
        ssh_channel_free(channel);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    // Befehl: ls -1a für Verzeichnisauflistung
    char command[2048];
    snprintf(command, sizeof(command), "cd '%s' && ls -1a | while read f; do if [ \"$f\" != \".\" ] && [ \"$f\" != \"..\" ]; then if [ -d \"$f\" ]; then echo \"d $f\"; else echo \"f $f\"; fi; fi; done", remote_path);
    
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Error executing command");
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        if (depth == 1) {
            hide_progress_bar(data);
        }
        depth--;
        return;
    }
    
    // Ausgabe lesen
    char buffer[8192];
    int total_read = 0;
    int nbytes;
    
    while ((nbytes = ssh_channel_read(channel, buffer + total_read, sizeof(buffer) - total_read - 1, 0)) > 0) {
        total_read += nbytes;
        if (total_read >= (int)sizeof(buffer) - 1) break;
    }
    
    buffer[total_read] = '\0';
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    
    // Parse Ausgabe und kopiere rekursiv
    // Kopiere Buffer, da strtok() ihn modifiziert
    char *buffer_copy = g_strdup(buffer);
    if (!buffer_copy) {
        depth--;
        if (depth == 0) {
            hide_progress_bar(data);
        }
        return;
    }
    
    char *line = strtok(buffer_copy, "\n");
    
    while (line != NULL) {
        if (strlen(line) > 2) {
            char type_char = line[0];
            char *name_start = strchr(line, ' ');
            if (name_start) {
                name_start++; // Nach dem Leerzeichen
                
                char remote_full[2048];
                char local_full[2048];
                snprintf(remote_full, sizeof(remote_full), "%s/%s", remote_path, name_start);
                snprintf(local_full, sizeof(local_full), "%s/%s", local_path, name_start);
                
                if (type_char == 'd') {
                    // Rekursiv Verzeichnis kopieren
                    copy_directory_from_remote_scp(data, remote_full, local_full);
                } else {
                    // Datei kopieren
                    copy_file_from_remote_scp(data, remote_full, local_full);
                }
                
                // Pulse für unbestimmten Fortschritt
                if (depth == 1 && data && data->progress_bar) {
                    gtk_progress_bar_pulse(GTK_PROGRESS_BAR(data->progress_bar));
                    while (gtk_events_pending()) {
                        gtk_main_iteration();
                    }
                }
            }
        }
        
        line = strtok(NULL, "\n");
    }
    
    g_free(buffer_copy);
    
    depth--;
    if (depth == 0 && data && data->progress_bar) {
        hide_progress_bar(data);
        if (data->status_label) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Directory copied!");
        }
        refresh_local_directory(data);
    }
}

// Rekursives Kopieren eines Verzeichnisses nach Remote
void copy_directory_to_remote(AppData *data, const char *local_path, const char *remote_path) {
    if (data->use_scp) {
        copy_directory_to_remote_scp(data, local_path, remote_path);
    } else {
        copy_directory_to_remote_sftp(data, local_path, remote_path);
    }
}

// Rekursives Kopieren eines Verzeichnisses von Remote
void copy_directory_from_remote(AppData *data, const char *remote_path, const char *local_path) {
    if (data->use_scp) {
        copy_directory_from_remote_scp(data, remote_path, local_path);
    } else {
        copy_directory_from_remote_sftp(data, remote_path, local_path);
    }
}

// Callback für Doppelklick auf lokale Datei
void on_local_row_activated(GtkTreeView *tree_view, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeIter iter;
    GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
    
    if (gtk_tree_model_get_iter(model, &iter, path)) {
        gchar *filename;
        gchar *type;
        gtk_tree_model_get(model, &iter, 0, &filename, 1, &type, -1);
        
        if (g_strcmp0(type, "Directory") == 0) {
            const char *current_path = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
            char new_path[1024];
            char path_copy[1024];
            strncpy(path_copy, current_path, sizeof(path_copy) - 1);
            path_copy[sizeof(path_copy) - 1] = '\0';
            
            if (strcmp(filename, "..") == 0) {
                // Gehe zum übergeordneten Verzeichnis
                char *last_slash = strrchr(path_copy, '/');
                if (last_slash && strcmp(path_copy, "/") != 0) {
                    *last_slash = '\0';
                    if (strlen(path_copy) == 0) {
                        strcpy(path_copy, "/");
                    }
                    gtk_entry_set_text(GTK_ENTRY(app->local_path_entry), path_copy);
                } else if (strcmp(path_copy, "/") == 0) {
                    // Bereits im Root
                    return;
                }
            } else {
                if (strcmp(current_path, "/") == 0) {
                    snprintf(new_path, sizeof(new_path), "/%s", filename);
                } else {
                    snprintf(new_path, sizeof(new_path), "%s/%s", current_path, filename);
                }
                gtk_entry_set_text(GTK_ENTRY(app->local_path_entry), new_path);
            }
            refresh_local_directory(app);
        }
        
        g_free(filename);
        g_free(type);
    }
}

// Callback für Doppelklick auf Remote-Datei
void on_remote_row_activated(GtkTreeView *tree_view, GtkTreePath *path, GtkTreeViewColumn *column, gpointer data) {
    AppData *app = (AppData *)data;
    if (!app->connected) return;
    
    GtkTreeIter iter;
    GtkTreeModel *model = gtk_tree_view_get_model(tree_view);
    
    if (gtk_tree_model_get_iter(model, &iter, path)) {
        gchar *filename;
        gchar *type;
        gtk_tree_model_get(model, &iter, 0, &filename, 1, &type, -1);
        
        if (g_strcmp0(type, "Directory") == 0) {
            const char *current_path = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
            char new_path[1024];
            char path_copy[1024];
            strncpy(path_copy, current_path, sizeof(path_copy) - 1);
            path_copy[sizeof(path_copy) - 1] = '\0';
            
            if (strcmp(filename, "..") == 0) {
                // Gehe zum übergeordneten Verzeichnis
                if (strcmp(path_copy, "/") == 0) {
                    // Bereits im Root
                    return;
                } else if (strcmp(path_copy, ".") == 0 || strcmp(path_copy, "") == 0) {
                    // Bereits im aktuellen Verzeichnis oder leer
                    return;
                } else {
                    // Entferne das letzte Verzeichnis
                char *last_slash = strrchr(path_copy, '/');
                    if (last_slash != NULL) {
                        if (last_slash == path_copy) {
                            // Nur ein "/" am Anfang, gehe zu Root
                            strcpy(path_copy, "/");
                        } else {
                            // Entferne alles nach dem letzten "/"
                    *last_slash = '\0';
                            // Wenn jetzt leer oder nur "/" übrig bleibt, setze auf "."
                            if (strlen(path_copy) == 0) {
                                strcpy(path_copy, ".");
                            }
                        }
                    } else {
                        // Kein "/" gefunden, gehe zu "."
                        strcpy(path_copy, ".");
                    }
                    gtk_entry_set_text(GTK_ENTRY(app->remote_path_entry), path_copy);
                }
            } else {
                if (strcmp(current_path, ".") == 0) {
                    snprintf(new_path, sizeof(new_path), "%s", filename);
                } else if (strcmp(current_path, "/") == 0) {
                    snprintf(new_path, sizeof(new_path), "/%s", filename);
                } else {
                    snprintf(new_path, sizeof(new_path), "%s/%s", current_path, filename);
                }
                gtk_entry_set_text(GTK_ENTRY(app->remote_path_entry), new_path);
            }
            refresh_remote_directory(app);
        }
        
        g_free(filename);
        g_free(type);
    }
}

// Callback für Kopieren nach Rechts (Lokal -> Remote)
void on_copy_to_remote_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->local_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->local_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No file selected");
        return;
    }
    
    // Filtere ".." und "." aus der Auswahl
    GList *filtered_rows = NULL;
    GList *iter = selected_rows;
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
    gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                filtered_rows = g_list_append(filtered_rows, gtk_tree_path_copy(path));
            }
            
        g_free(filename);
        }
        
        iter = iter->next;
    }
    
    // Gib die ursprüngliche Liste frei
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    // Prüfe, ob nach dem Filtern noch Elemente übrig sind
    if (!filtered_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No valid files selected ('.' and '..' are ignored)");
        return;
    }
    
    selected_rows = filtered_rows;
    
    // Reset Konflikt-Flags
    app->overwrite_all = 0;
    app->skip_all = 0;
    app->copy_aborted = 0;
    
    const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
    const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
    
    iter = selected_rows;
    while (iter && !app->copy_aborted) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gchar *type;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, 1, &type, -1);
    
    char local_full_path[2048];
    char remote_full_path[2048];
    snprintf(local_full_path, sizeof(local_full_path), "%s/%s", local_path_text, filename);
    snprintf(remote_full_path, sizeof(remote_full_path), "%s/%s", remote_path_text, filename);
    
            if (g_strcmp0(type, "Directory") == 0) {
                copy_directory_to_remote(app, local_full_path, remote_full_path);
            } else {
    copy_file_to_remote(app, local_full_path, remote_full_path);
            }
    
    g_free(filename);
    g_free(type);
        }
        
        iter = iter->next;
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
}

// Callback für Kopieren nach Links (Remote -> Lokal)
void on_copy_to_local_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->remote_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->remote_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No file selected");
        return;
    }
    
    // Filtere ".." und "." aus der Auswahl
    GList *filtered_rows = NULL;
    GList *iter = selected_rows;
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                filtered_rows = g_list_append(filtered_rows, gtk_tree_path_copy(path));
            }
            
            g_free(filename);
        }
        
        iter = iter->next;
    }
    
    // Gib die ursprüngliche Liste frei
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    // Prüfe, ob nach dem Filtern noch Elemente übrig sind
    if (!filtered_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No valid files selected ('.' and '..' are ignored)");
        return;
    }
    
    selected_rows = filtered_rows;
    
    // Reset Konflikt-Flags
    app->overwrite_all = 0;
    app->skip_all = 0;
    app->copy_aborted = 0;
    
    const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
    const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
    
    iter = selected_rows;
    while (iter && !app->copy_aborted) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
    gchar *filename;
    gchar *type;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, 1, &type, -1);
            
            char local_full_path[2048];
            char remote_full_path[2048];
            snprintf(local_full_path, sizeof(local_full_path), "%s/%s", local_path_text, filename);
            snprintf(remote_full_path, sizeof(remote_full_path), "%s/%s", remote_path_text, filename);
            
            if (g_strcmp0(type, "Directory") == 0) {
                copy_directory_from_remote(app, remote_full_path, local_full_path);
            } else {
                copy_file_from_remote(app, remote_full_path, local_full_path);
            }
            
        g_free(filename);
        g_free(type);
        }
        
        iter = iter->next;
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
}

// Lokales Verzeichnis rekursiv löschen
void delete_local_directory_recursive(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) {
        return;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[2048];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                delete_local_directory_recursive(full_path);
                rmdir(full_path);
            } else {
                remove(full_path);
            }
        }
    }
    closedir(dir);
    rmdir(path);
}

// Lokale Datei oder Verzeichnis löschen
void delete_local_file(AppData *data, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
        refresh_local_directory(data);
        return;
    }
    
    if (S_ISDIR(st.st_mode)) {
        delete_local_directory_recursive(path);
    } else {
        if (remove(path) != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Error deleting file: %s", strerror(errno));
            gtk_label_set_text(GTK_LABEL(data->status_label), msg);
            return;
        }
    }
    
    refresh_local_directory(data);
    char msg[256];
    snprintf(msg, sizeof(msg), "Deleted: %s", path);
    gtk_label_set_text(GTK_LABEL(data->status_label), msg);
}

// Remote-Verzeichnis rekursiv löschen (SFTP)
void delete_remote_directory_sftp(AppData *data, const char *path) {
    sftp_dir dir = sftp_opendir(data->sftp, path);
    if (!dir) {
        return;
    }
    
    sftp_attributes attributes;
    while ((attributes = sftp_readdir(data->sftp, dir)) != NULL) {
        if (strcmp(attributes->name, ".") == 0 || strcmp(attributes->name, "..") == 0) {
            sftp_attributes_free(attributes);
            continue;
        }
        
        char full_path[2048];
        snprintf(full_path, sizeof(full_path), "%s/%s", path, attributes->name);
        
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            delete_remote_directory_sftp(data, full_path);
            sftp_rmdir(data->sftp, full_path);
        } else {
            sftp_unlink(data->sftp, full_path);
        }
        
        sftp_attributes_free(attributes);
    }
    sftp_closedir(dir);
    sftp_rmdir(data->sftp, path);
}

// Remote-Verzeichnis rekursiv löschen (SCP)
void delete_remote_directory_scp(AppData *data, const char *path) {
    ssh_channel channel = ssh_channel_new(data->session);
    if (!channel) {
        return;
    }
    
    if (ssh_channel_open_session(channel) != SSH_OK) {
        ssh_channel_free(channel);
        return;
    }
    
    // Führe rm -rf aus
    char command[2048];
    snprintf(command, sizeof(command), "rm -rf '%s'", path);
    
    if (ssh_channel_request_exec(channel, command) != SSH_OK) {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        return;
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
}

// Remote-Datei oder Verzeichnis löschen
void delete_remote_file(AppData *data, const char *path) {
    if (!data->connected || !data->session) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    if (data->use_scp) {
        // SCP-Modus: Verwende SSH-Befehle
        ssh_channel channel = ssh_channel_new(data->session);
        if (!channel) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating channel");
            return;
        }
        
        if (ssh_channel_open_session(channel) != SSH_OK) {
            ssh_channel_free(channel);
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error opening channel");
            return;
        }
        
        // Prüfe, ob Datei/Verzeichnis existiert
        char test_command[2048];
        snprintf(test_command, sizeof(test_command), "test -e '%s' && echo 'exists' || echo ''", path);
        
        if (ssh_channel_request_exec(channel, test_command) == SSH_OK) {
            char buffer[64];
            int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
            if (nbytes > 0) {
                buffer[nbytes] = '\0';
                char *newline = strchr(buffer, '\n');
                if (newline) *newline = '\0';
                
                if (strcmp(buffer, "exists") != 0) {
                    // Datei/Verzeichnis existiert nicht mehr, GUI aktualisieren und fortfahren
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    refresh_remote_directory(data);
                    return;
                }
            }
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            
            // Prüfe, ob es ein Verzeichnis ist
            channel = ssh_channel_new(data->session);
            if (channel && ssh_channel_open_session(channel) == SSH_OK) {
                snprintf(test_command, sizeof(test_command), "test -d '%s'", path);
                
                if (ssh_channel_request_exec(channel, test_command) == SSH_OK) {
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    
                    // Es ist ein Verzeichnis
                    delete_remote_directory_scp(data, path);
                } else {
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    
                    // Es ist eine Datei
                    channel = ssh_channel_new(data->session);
                    if (channel && ssh_channel_open_session(channel) == SSH_OK) {
                        char command[2048];
                        snprintf(command, sizeof(command), "rm -f '%s'", path);
                        ssh_channel_request_exec(channel, command);
                        ssh_channel_send_eof(channel);
                        ssh_channel_close(channel);
                    }
                    if (channel) {
                        ssh_channel_free(channel);
                    }
                }
            } else if (channel) {
                ssh_channel_free(channel);
            }
        } else {
            ssh_channel_send_eof(channel);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
        }
    } else {
        // SFTP-Modus
        sftp_attributes attributes = sftp_stat(data->sftp, path);
        if (!attributes) {
            // Datei existiert nicht mehr, GUI aktualisieren und fortfahren
            refresh_remote_directory(data);
            return;
        }
        
        if (attributes->type == SSH_FILEXFER_TYPE_DIRECTORY) {
            delete_remote_directory_sftp(data, path);
        } else {
            if (sftp_unlink(data->sftp, path) != SSH_OK) {
                gtk_label_set_text(GTK_LABEL(data->status_label), "Error deleting remote file");
                sftp_attributes_free(attributes);
                return;
            }
        }
        
        sftp_attributes_free(attributes);
    }
    
    refresh_remote_directory(data);
    char msg[256];
    snprintf(msg, sizeof(msg), "Deleted: %s", path);
    gtk_label_set_text(GTK_LABEL(data->status_label), msg);
}

// Callback für Delete-Button (Lokal)
// Keyboard-Handler für lokale TreeView
gboolean on_local_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data) {
    if (event->keyval == GDK_KEY_Delete || event->keyval == GDK_KEY_KP_Delete) {
        on_delete_local_clicked(widget, data);
        return TRUE; // Event wurde behandelt
    }
    return FALSE; // Event weiterleiten
}

// Keyboard-Handler für Remote TreeView
gboolean on_remote_tree_key_press(GtkWidget *widget, GdkEventKey *event, gpointer data) {
    if (event->keyval == GDK_KEY_Delete || event->keyval == GDK_KEY_KP_Delete) {
        on_delete_remote_clicked(widget, data);
        return TRUE; // Event wurde behandelt
    }
    return FALSE; // Event weiterleiten
}

// Drag-and-Drop: Lokale TreeView - Drag-Beginn (sichert Auswahl)
gboolean on_local_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->local_tree));
    
    // Stelle sicher, dass die Auswahl beibehalten wird
    // Die Auswahl wird bereits in drag-data-get verwendet
    (void)widget;
    (void)context;
    (void)selection;
    
    return FALSE; // Weiterleiten
}

// Drag-and-Drop: Remote TreeView - Drag-Beginn (sichert Auswahl)
gboolean on_remote_drag_begin(GtkWidget *widget, GdkDragContext *context, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->remote_tree));
    
    // Stelle sicher, dass die Auswahl beibehalten wird
    // Die Auswahl wird bereits in drag-data-get verwendet
    (void)widget;
    (void)context;
    (void)selection;
    
    return FALSE; // Weiterleiten
}

// Drag-and-Drop: Lokale TreeView - Daten für Drag bereitstellen
void on_local_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->local_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->local_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        return;
    }
    
    // Sammle alle ausgewählten Dateinamen
    GString *file_list = g_string_new("");
    GList *iter = selected_rows;
    int count = 0;
    
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                if (count > 0) {
                    g_string_append(file_list, "\n");
                }
                g_string_append(file_list, filename);
                count++;
            }
            
            g_free(filename);
        }
        
        iter = iter->next;
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    if (file_list->len > 0) {
        gtk_selection_data_set_text(data, file_list->str, -1);
    }
    
    g_string_free(file_list, TRUE);
}

// Drag-and-Drop: Remote TreeView - Daten beim Drop empfangen
void on_remote_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    
    if (!app->connected) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Not connected!");
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    if (gtk_selection_data_get_length(data) < 0) {
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    gchar *text = (gchar *)gtk_selection_data_get_text(data);
    if (!text) {
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    // Parse die Dateiliste (durch \n getrennt)
    gchar **lines = g_strsplit(text, "\n", -1);
    if (!lines || !lines[0]) {
        g_free(text);
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    // Reset Konflikt-Flags
    app->overwrite_all = 0;
    app->skip_all = 0;
    app->copy_aborted = 0;
    
    const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
    const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
    
    // Kopiere alle Dateien
    for (int i = 0; lines[i] != NULL && !app->copy_aborted; i++) {
        if (strlen(lines[i]) == 0) continue;
    
    char local_full_path[2048];
    char remote_full_path[2048];
        snprintf(local_full_path, sizeof(local_full_path), "%s/%s", local_path_text, lines[i]);
        snprintf(remote_full_path, sizeof(remote_full_path), "%s/%s", remote_path_text, lines[i]);
        
        // Prüfe, ob es ein Verzeichnis ist
        struct stat st;
        if (stat(local_full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                copy_directory_to_remote(app, local_full_path, remote_full_path);
            } else {
                copy_file_to_remote(app, local_full_path, remote_full_path);
            }
        }
    }
    
    g_strfreev(lines);
    g_free(text);
    gtk_drag_finish(context, TRUE, FALSE, time);
}

// Drag-and-Drop: Remote TreeView - Daten für Drag bereitstellen
void on_remote_drag_data_get(GtkWidget *widget, GdkDragContext *context, GtkSelectionData *data, guint info, guint time, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->remote_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->remote_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        return;
    }
    
    // Sammle alle ausgewählten Dateinamen
    GString *file_list = g_string_new("");
    GList *iter = selected_rows;
    int count = 0;
    
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                if (count > 0) {
                    g_string_append(file_list, "\n");
                }
                g_string_append(file_list, filename);
                count++;
            }
            
            g_free(filename);
        }
        
        iter = iter->next;
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    if (file_list->len > 0) {
        gtk_selection_data_set_text(data, file_list->str, -1);
    }
    
    g_string_free(file_list, TRUE);
}

// Drag-and-Drop: Lokale TreeView - Daten beim Drop empfangen
void on_local_drag_data_received(GtkWidget *widget, GdkDragContext *context, gint x, gint y, GtkSelectionData *data, guint info, guint time, gpointer user_data) {
    AppData *app = (AppData *)user_data;
    
    if (!app->connected) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Not connected!");
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    if (gtk_selection_data_get_length(data) < 0) {
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    gchar *text = (gchar *)gtk_selection_data_get_text(data);
    if (!text) {
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    // Parse die Dateiliste (durch \n getrennt)
    gchar **lines = g_strsplit(text, "\n", -1);
    if (!lines || !lines[0]) {
        g_free(text);
        gtk_drag_finish(context, FALSE, FALSE, time);
        return;
    }
    
    // Reset Konflikt-Flags
    app->overwrite_all = 0;
    app->skip_all = 0;
    app->copy_aborted = 0;
    
    const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
    const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
    
    // Kopiere alle Dateien
    for (int i = 0; lines[i] != NULL && !app->copy_aborted; i++) {
        if (strlen(lines[i]) == 0) continue;
        
        char local_full_path[2048];
        char remote_full_path[2048];
        snprintf(local_full_path, sizeof(local_full_path), "%s/%s", local_path_text, lines[i]);
        snprintf(remote_full_path, sizeof(remote_full_path), "%s/%s", remote_path_text, lines[i]);
        
        // Prüfe, ob es ein Verzeichnis ist (Remote)
        if (app->use_scp) {
            // Für SCP: Prüfe über SSH-Befehl
            ssh_channel channel = ssh_channel_new(app->session);
            if (channel && ssh_channel_open_session(channel) == SSH_OK) {
                char test_cmd[2048];
                snprintf(test_cmd, sizeof(test_cmd), "test -d '%s' && echo 'dir' || echo 'file'", remote_full_path);
                
                if (ssh_channel_request_exec(channel, test_cmd) == SSH_OK) {
                    char buffer[64];
                    int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer) - 1, 0);
                    if (nbytes > 0) {
                        buffer[nbytes] = '\0';
                        char *newline = strchr(buffer, '\n');
                        if (newline) *newline = '\0';
                        
                        if (strcmp(buffer, "dir") == 0) {
                            copy_directory_from_remote(app, remote_full_path, local_full_path);
                        } else {
                            copy_file_from_remote(app, remote_full_path, local_full_path);
                        }
                    }
                }
                ssh_channel_send_eof(channel);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
            } else if (channel) {
                ssh_channel_free(channel);
            }
        } else {
            // Für SFTP: Prüfe über sftp_stat
            sftp_attributes attrs = sftp_stat(app->sftp, remote_full_path);
            if (attrs) {
                if (attrs->type == SSH_FILEXFER_TYPE_DIRECTORY) {
                    copy_directory_from_remote(app, remote_full_path, local_full_path);
                } else {
                    copy_file_from_remote(app, remote_full_path, local_full_path);
                }
                sftp_attributes_free(attrs);
            }
        }
    }
    
    g_strfreev(lines);
    g_free(text);
    gtk_drag_finish(context, TRUE, FALSE, time);
}

void on_delete_local_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->local_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->local_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No file selected");
        return;
    }
    
    // Filtere ".." und "." aus der Auswahl
    GList *filtered_rows = NULL;
    GList *iter = selected_rows;
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                filtered_rows = g_list_append(filtered_rows, gtk_tree_path_copy(path));
            }
            
            g_free(filename);
        }
        
        iter = iter->next;
    }
    
    // Gib die ursprüngliche Liste frei
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    // Prüfe, ob nach dem Filtern noch Elemente übrig sind
    if (!filtered_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No valid files selected ('.' and '..' are ignored)");
        return;
    }
    
    selected_rows = filtered_rows;
    
    // Zähle ausgewählte Elemente
    int count = g_list_length(selected_rows);
    
    // Bestätigungsdialog anzeigen
    GtkWidget *confirm_dialog;
    if (count == 1) {
        GtkTreePath *path = (GtkTreePath *)selected_rows->data;
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter(model, &iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &iter, 0, &filename, -1);
            const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
            char local_full_path[2048];
    snprintf(local_full_path, sizeof(local_full_path), "%s/%s", local_path_text, filename);
            
            confirm_dialog = gtk_message_dialog_new(NULL,
                                                    GTK_DIALOG_MODAL,
                                                    GTK_MESSAGE_QUESTION,
                                                    GTK_BUTTONS_YES_NO,
                                                    "Are you sure you want to delete '%s'?",
                                                    local_full_path);
            g_free(filename);
        } else {
            g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
            return;
        }
    } else {
        confirm_dialog = gtk_message_dialog_new(NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_MESSAGE_QUESTION,
                                                GTK_BUTTONS_YES_NO,
                                                "Are you sure you want to delete %d selected items?",
                                                count);
    }
    gtk_window_set_title(GTK_WINDOW(confirm_dialog), "Confirm Delete");
    
    gint response = gtk_dialog_run(GTK_DIALOG(confirm_dialog));
    gtk_widget_destroy(confirm_dialog);
    
    if (response == GTK_RESPONSE_YES) {
        const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(app->local_path_entry));
        
        // Sammle zuerst alle Pfade in einer Liste (als Strings), damit die TreePaths nicht ungültig werden
        GList *paths_to_delete = NULL;
        GList *iter = selected_rows;
        while (iter) {
            GtkTreePath *path = (GtkTreePath *)iter->data;
            GtkTreeIter tree_iter;
            
            if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
                gchar *filename;
                gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
                
                char *local_full_path = g_malloc(2048);
                snprintf(local_full_path, 2048, "%s/%s", local_path_text, filename);
                paths_to_delete = g_list_append(paths_to_delete, local_full_path);
                
                g_free(filename);
            }
            
            iter = iter->next;
        }
        
        // Lösche alle Elemente (ohne die Liste zwischenzeitig zu aktualisieren)
        iter = paths_to_delete;
        while (iter) {
            char *local_full_path = (char *)iter->data;
            
            // Lösche die Datei direkt, ohne refresh_local_directory aufzurufen
            struct stat st;
            if (stat(local_full_path, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    delete_local_directory_recursive(local_full_path);
                } else {
                    remove(local_full_path);
                }
            }
            
            iter = iter->next;
        }
        
        // Liste am Ende einmal aktualisieren
        refresh_local_directory(app);
        if (count > 1) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Deleted %d items", count);
            gtk_label_set_text(GTK_LABEL(app->status_label), msg);
        } else {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Deleted");
        }
        
        // Speicher freigeben
        g_list_free_full(paths_to_delete, g_free);
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
}

// Callback für Delete-Button (Remote)
void on_delete_remote_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    
    if (!app->connected) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Not connected!");
        return;
    }
    
    GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(app->remote_tree));
    GtkTreeModel *model = GTK_TREE_MODEL(app->remote_store);
    
    GList *selected_rows = gtk_tree_selection_get_selected_rows(selection, &model);
    if (!selected_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No file selected");
        return;
    }
    
    // Filtere ".." und "." aus der Auswahl
    GList *filtered_rows = NULL;
    GList *iter = selected_rows;
    while (iter) {
        GtkTreePath *path = (GtkTreePath *)iter->data;
        GtkTreeIter tree_iter;
        
        if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &tree_iter, 0, &filename, -1);
            
            // Ignoriere ".." und "."
            if (filename && strcmp(filename, "..") != 0 && strcmp(filename, ".") != 0) {
                filtered_rows = g_list_append(filtered_rows, gtk_tree_path_copy(path));
            }
            
            g_free(filename);
        }
        
        iter = iter->next;
    }
    
    // Gib die ursprüngliche Liste frei
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
    
    // Prüfe, ob nach dem Filtern noch Elemente übrig sind
    if (!filtered_rows) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "No valid files selected ('.' and '..' are ignored)");
        return;
    }
    
    selected_rows = filtered_rows;
    
    // Zähle ausgewählte Elemente
    int count = g_list_length(selected_rows);
    
    // Bestätigungsdialog anzeigen
    GtkWidget *confirm_dialog;
    if (count == 1) {
        GtkTreePath *path = (GtkTreePath *)selected_rows->data;
        GtkTreeIter iter;
        if (gtk_tree_model_get_iter(model, &iter, path)) {
            gchar *filename;
            gtk_tree_model_get(model, &iter, 0, &filename, -1);
            const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
            char remote_full_path[2048];
    snprintf(remote_full_path, sizeof(remote_full_path), "%s/%s", remote_path_text, filename);
    
            confirm_dialog = gtk_message_dialog_new(NULL,
                                                    GTK_DIALOG_MODAL,
                                                    GTK_MESSAGE_QUESTION,
                                                    GTK_BUTTONS_YES_NO,
                                                    "Are you sure you want to delete '%s'?",
                                                    remote_full_path);
            g_free(filename);
        } else {
            g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
            return;
        }
    } else {
        confirm_dialog = gtk_message_dialog_new(NULL,
                                                GTK_DIALOG_MODAL,
                                                GTK_MESSAGE_QUESTION,
                                                GTK_BUTTONS_YES_NO,
                                                "Are you sure you want to delete %d selected items?",
                                                count);
    }
    gtk_window_set_title(GTK_WINDOW(confirm_dialog), "Confirm Delete");
    
    gint response = gtk_dialog_run(GTK_DIALOG(confirm_dialog));
    gtk_widget_destroy(confirm_dialog);
    
    if (response == GTK_RESPONSE_YES) {
        const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(app->remote_path_entry));
        
        // Sammle zuerst alle Pfade in einer Liste (als Strings), damit die TreePaths nicht ungültig werden
        GList *paths_to_delete = NULL;
        GList *iter = selected_rows;
        while (iter) {
            GtkTreePath *path = (GtkTreePath *)iter->data;
            GtkTreeIter tree_iter;
            
            if (gtk_tree_model_get_iter(model, &tree_iter, path)) {
                gchar *filename;
                gchar *type;
                gtk_tree_model_get(model, &tree_iter, 0, &filename, 1, &type, -1);
                
                char *remote_full_path = g_malloc(2048);
                snprintf(remote_full_path, 2048, "%s/%s", remote_path_text, filename);
                
                // Speichere auch den Typ für später
                char *item_info = g_malloc(2048);
                snprintf(item_info, 2048, "%s|%s", remote_full_path, type);
                paths_to_delete = g_list_append(paths_to_delete, item_info);
    
    g_free(filename);
    g_free(type);
                g_free(remote_full_path);
            }
            
            iter = iter->next;
        }
        
        // Lösche alle Elemente (ohne die Liste zwischenzeitig zu aktualisieren)
        iter = paths_to_delete;
        while (iter) {
            char *item_info = (char *)iter->data;
            
            // Parse item_info: "path|type"
            char *pipe_pos = strchr(item_info, '|');
            if (pipe_pos) {
                *pipe_pos = '\0';
                char *remote_full_path = item_info;
                char *type = pipe_pos + 1;
                
                // Lösche direkt, ohne refresh_remote_directory aufzurufen
                if (app->use_scp) {
                    // SCP-Modus: Verwende SSH-Befehle
                    ssh_channel channel = ssh_channel_new(app->session);
                    if (channel && ssh_channel_open_session(channel) == SSH_OK) {
                        char command[2048];
                        if (g_strcmp0(type, "Directory") == 0) {
                            snprintf(command, sizeof(command), "rm -rf '%s'", remote_full_path);
                        } else {
                            snprintf(command, sizeof(command), "rm -f '%s'", remote_full_path);
                        }
                        ssh_channel_request_exec(channel, command);
                        ssh_channel_send_eof(channel);
                        ssh_channel_close(channel);
                        ssh_channel_free(channel);
                    } else if (channel) {
                        ssh_channel_free(channel);
                    }
                } else {
                    // SFTP-Modus
                    if (g_strcmp0(type, "Directory") == 0) {
                        delete_remote_directory_sftp(app, remote_full_path);
                    } else {
                        sftp_unlink(app->sftp, remote_full_path);
                    }
                }
            }
            
            iter = iter->next;
        }
        
        // Liste am Ende einmal aktualisieren
        refresh_remote_directory(app);
        if (count > 1) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Deleted %d items", count);
            gtk_label_set_text(GTK_LABEL(app->status_label), msg);
        } else {
            gtk_label_set_text(GTK_LABEL(app->status_label), "Deleted");
        }
        
        // Speicher freigeben
        g_list_free_full(paths_to_delete, g_free);
    }
    
    g_list_free_full(selected_rows, (GDestroyNotify)gtk_tree_path_free);
}

// Lokales Verzeichnis erstellen
void create_local_directory(AppData *data, const char *dirname) {
    const char *local_path_text = gtk_entry_get_text(GTK_ENTRY(data->local_path_entry));
    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s/%s", local_path_text, dirname);
    
    if (mkdir(full_path, 0755) != 0) {
        char msg[256];
        snprintf(msg, sizeof(msg), "Error creating directory: %s", strerror(errno));
        gtk_label_set_text(GTK_LABEL(data->status_label), msg);
        return;
    }
    
    refresh_local_directory(data);
    char msg[256];
    snprintf(msg, sizeof(msg), "Created directory: %s", full_path);
    gtk_label_set_text(GTK_LABEL(data->status_label), msg);
}

// Remote-Verzeichnis erstellen
void create_remote_directory(AppData *data, const char *dirname) {
    if (!data->connected || !data->session) {
        gtk_label_set_text(GTK_LABEL(data->status_label), "Not connected!");
        return;
    }
    
    const char *remote_path_text = gtk_entry_get_text(GTK_ENTRY(data->remote_path_entry));
    char full_path[2048];
    snprintf(full_path, sizeof(full_path), "%s/%s", remote_path_text, dirname);
    
    if (data->use_scp) {
        // SCP-Modus: Verwende SSH-Befehl
        ssh_channel channel = ssh_channel_new(data->session);
        if (!channel) {
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating channel");
            return;
        }
        
        if (ssh_channel_open_session(channel) != SSH_OK) {
            ssh_channel_free(channel);
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error opening channel");
            return;
        }
        
        char command[2048];
        snprintf(command, sizeof(command), "mkdir -p '%s'", full_path);
        
        if (ssh_channel_request_exec(channel, command) != SSH_OK) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            gtk_label_set_text(GTK_LABEL(data->status_label), "Error creating remote directory");
            return;
        }
        
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
    } else {
        // SFTP-Modus
        if (sftp_mkdir(data->sftp, full_path, 0755) != SSH_OK) {
            char msg[256];
            snprintf(msg, sizeof(msg), "Error creating remote directory: %s", ssh_get_error(data->session));
            gtk_label_set_text(GTK_LABEL(data->status_label), msg);
            return;
        }
    }
    
    refresh_remote_directory(data);
    char msg[256];
    snprintf(msg, sizeof(msg), "Created directory: %s", full_path);
    gtk_label_set_text(GTK_LABEL(data->status_label), msg);
}

// Callback für mkdir-Button (Lokal)
void on_mkdir_local_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    
    // Dialog für Verzeichnisname erstellen
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Create Directory",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Create", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    
    GtkWidget *label = gtk_label_new("Enter directory name:");
    gtk_container_add(GTK_CONTAINER(content), label);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Directory name");
    gtk_container_add(GTK_CONTAINER(content), entry);
    
    gtk_widget_show_all(dialog);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    const char *dirname = gtk_entry_get_text(GTK_ENTRY(entry));
    
    if (response == GTK_RESPONSE_ACCEPT && dirname && strlen(dirname) > 0) {
        create_local_directory(app, dirname);
    }
    
    gtk_widget_destroy(dialog);
}

// Callback für mkdir-Button (Remote)
void on_mkdir_remote_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    
    if (!app->connected) {
        gtk_label_set_text(GTK_LABEL(app->status_label), "Not connected!");
        return;
    }
    
    // Dialog für Verzeichnisname erstellen
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Create Directory",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Create", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    
    GtkWidget *label = gtk_label_new("Enter directory name:");
    gtk_container_add(GTK_CONTAINER(content), label);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "Directory name");
    gtk_container_add(GTK_CONTAINER(content), entry);
    
    gtk_widget_show_all(dialog);
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    const char *dirname = gtk_entry_get_text(GTK_ENTRY(entry));
    
    if (response == GTK_RESPONSE_ACCEPT && dirname && strlen(dirname) > 0) {
        create_remote_directory(app, dirname);
    }
    
    gtk_widget_destroy(dialog);
}

// Key-File-Passwort abfragen
char* prompt_key_file_password(void) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Key File Password",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "OK", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
    
    GtkWidget *label = gtk_label_new("The key file is password protected.\nPlease enter the password:");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE); // Passwort verstecken
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(content), vbox);
    gtk_widget_show_all(dialog);
    
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    
    char *password = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *text = gtk_entry_get_text(GTK_ENTRY(entry));
        if (text && strlen(text) > 0) {
            password = g_strdup(text);
        }
    }
    
    gtk_widget_destroy(dialog);
    return password;
}

// SSH-Passwort abfragen
char* prompt_ssh_password(void) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("SSH Password",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "OK", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
    
    GtkWidget *label = gtk_label_new("Please enter the SSH password:");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE); // Passwort verstecken
    gtk_entry_set_activates_default(GTK_ENTRY(entry), TRUE);
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(content), vbox);
    gtk_widget_show_all(dialog);
    
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_ACCEPT);
    
    char *password = NULL;
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *text = gtk_entry_get_text(GTK_ENTRY(entry));
        if (text && strlen(text) > 0) {
            password = g_strdup(text);
        }
    }
    
    gtk_widget_destroy(dialog);
    return password;
}

// Konfigurationsdatei-Pfad ermitteln
char* get_config_file_path(void) {
    const char *home = g_get_home_dir();
    char *config_dir = g_build_filename(home, ".guiscp", NULL);
    
    // Erstelle Verzeichnis falls nicht vorhanden
    if (!g_file_test(config_dir, G_FILE_TEST_IS_DIR)) {
        g_mkdir_with_parents(config_dir, 0700);
    }
    
    char *config_file = g_build_filename(config_dir, "connections.ini", NULL);
    g_free(config_dir);
    return config_file;
}

// Pfad zur known_hosts Datei
char* get_known_hosts_file_path(void) {
    const char *home = g_get_home_dir();
    char *config_dir = g_build_filename(home, ".guiscp", NULL);
    
    // Erstelle Verzeichnis falls nicht vorhanden
    if (!g_file_test(config_dir, G_FILE_TEST_IS_DIR)) {
        g_mkdir_with_parents(config_dir, 0700);
    }
    
    char *known_hosts_file = g_build_filename(config_dir, "known_hosts", NULL);
    g_free(config_dir);
    
    return known_hosts_file;
}

// Prüfe, ob Fingerprint bekannt ist
gboolean is_fingerprint_known(const char *host, int port, unsigned char *hash, size_t hlen) {
    char *known_hosts_file = get_known_hosts_file_path();
    FILE *fp = fopen(known_hosts_file, "r");
    g_free(known_hosts_file);
    
    if (!fp) {
        return FALSE;
    }
    
    char line[1024];
    char host_port[256];
    snprintf(host_port, sizeof(host_port), "%s:%d", host, port);
    
    while (fgets(line, sizeof(line), fp)) {
        // Format: host:port hash_hex
        char *space = strchr(line, ' ');
        if (space) {
            *space = '\0';
            if (strcmp(line, host_port) == 0) {
                // Host gefunden, prüfe Hash
                space++;
                char *hash_str = space;
                // Entferne Newline
                char *newline = strchr(hash_str, '\n');
                if (newline) *newline = '\0';
                
                // Konvertiere Hex-String zu Bytes
                size_t hash_len = strlen(hash_str) / 2;
                if (hash_len == hlen) {
                    unsigned char stored_hash[64];
                    int match = 1;
                    for (size_t i = 0; i < hash_len; i++) {
                        char hex[3] = {hash_str[i*2], hash_str[i*2+1], '\0'};
                        stored_hash[i] = (unsigned char)strtoul(hex, NULL, 16);
                        if (stored_hash[i] != hash[i]) {
                            match = 0;
                            break;
                        }
                    }
                    fclose(fp);
                    return match ? TRUE : FALSE;
                }
            }
        }
    }
    
    fclose(fp);
    return FALSE;
}

// Speichere Fingerprint
void save_fingerprint(const char *host, int port, unsigned char *hash, size_t hlen) {
    char *known_hosts_file = get_known_hosts_file_path();
    FILE *fp = fopen(known_hosts_file, "a");
    g_free(known_hosts_file);
    
    if (!fp) {
        return;
    }
    
    fprintf(fp, "%s:%d ", host, port);
    for (size_t i = 0; i < hlen; i++) {
        fprintf(fp, "%02x", hash[i]);
    }
    fprintf(fp, "\n");
    
    fclose(fp);
}

// Fingerprint-Überprüfung
gboolean verify_ssh_fingerprint(ssh_session session, const char *host, int port) {
    ssh_key srv_pubkey = NULL;
    unsigned char *hash = NULL;
    size_t hlen = 0;
    
    // Hole Server-Public-Key
    if (ssh_get_server_publickey(session, &srv_pubkey) != SSH_OK) {
        return FALSE;
    }
    
    // Hole Hash (MD5)
    if (ssh_get_publickey_hash(srv_pubkey, SSH_PUBLICKEY_HASH_MD5, &hash, &hlen) != SSH_OK) {
        ssh_key_free(srv_pubkey);
        return FALSE;
    }
    
    // Prüfe, ob Fingerprint bekannt ist
    if (is_fingerprint_known(host, port, hash, hlen)) {
        ssh_key_free(srv_pubkey);
        ssh_clean_pubkey_hash(&hash);
        return TRUE;
    }
    
    // Fingerprint ist unbekannt - zeige Warnung
    char fingerprint_str[128];
    fingerprint_str[0] = '\0';
    for (size_t i = 0; i < hlen; i++) {
        char hex[4];
        snprintf(hex, sizeof(hex), "%02x", hash[i]);
        if (i > 0) {
            strcat(fingerprint_str, ":");
        }
        strcat(fingerprint_str, hex);
    }
    
    char msg[1024];
    snprintf(msg, sizeof(msg),
        "WARNING: The authenticity of host '%s:%d' can't be established.\n\n"
        "The server's fingerprint is:\n"
        "MD5: %s\n\n"
        "This is the first time you are connecting to this server.\n"
        "If you trust this server, click 'Accept' to save the fingerprint.\n"
        "If you don't trust this server, click 'Cancel' to abort the connection.",
        host, port, fingerprint_str);
    
    GtkWidget *dialog = gtk_message_dialog_new(NULL,
                                               GTK_DIALOG_MODAL,
                                               GTK_MESSAGE_WARNING,
                                               GTK_BUTTONS_NONE,
                                               "%s", msg);
    gtk_window_set_title(GTK_WINDOW(dialog), "SSH Host Key Verification");
    
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Accept", GTK_RESPONSE_ACCEPT);
    gtk_dialog_add_button(GTK_DIALOG(dialog), "Cancel", GTK_RESPONSE_CANCEL);
    
    gtk_dialog_set_default_response(GTK_DIALOG(dialog), GTK_RESPONSE_CANCEL);
    
    gint response = gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
    
    if (response == GTK_RESPONSE_ACCEPT) {
        // Speichere Fingerprint
        save_fingerprint(host, port, hash, hlen);
        ssh_key_free(srv_pubkey);
        ssh_clean_pubkey_hash(&hash);
        return TRUE;
    } else {
        // Benutzer hat abgebrochen
        ssh_key_free(srv_pubkey);
        ssh_clean_pubkey_hash(&hash);
        return FALSE;
    }
}

// Gespeicherte Verbindungsnamen abrufen
GList* get_saved_connection_names(void) {
    char *config_file = get_config_file_path();
    GKeyFile *key_file = g_key_file_new();
    GError *error = NULL;
    GList *names = NULL;
    
    if (g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, &error)) {
        gsize length;
        gchar **groups = g_key_file_get_groups(key_file, &length);
        
        for (gsize i = 0; i < length; i++) {
            names = g_list_append(names, g_strdup(groups[i]));
        }
        
        g_strfreev(groups);
    }
    
    if (error) {
        g_error_free(error);
    }
    
    g_key_file_free(key_file);
    g_free(config_file);
    return names;
}

// Verbindung speichern
void save_connection(AppData *data) {
    // Dialog zum Eingeben des Namens
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Save Connection",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Cancel", GTK_RESPONSE_CANCEL,
                                                     "Save", GTK_RESPONSE_ACCEPT,
                                                     NULL);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 10);
    
    GtkWidget *label = gtk_label_new("Name for this connection:");
    gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    
    GtkWidget *entry = gtk_entry_new();
    gtk_box_pack_start(GTK_BOX(vbox), entry, FALSE, FALSE, 0);
    
    gtk_container_add(GTK_CONTAINER(content), vbox);
    gtk_widget_show_all(dialog);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        const char *name = gtk_entry_get_text(GTK_ENTRY(entry));
        if (strlen(name) > 0) {
            char *config_file = get_config_file_path();
            GKeyFile *key_file = g_key_file_new();
            GError *error = NULL;
            
            // Lade existierende Konfiguration
            g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, NULL);
            
            // Speichere Einstellungen
            const char *host = gtk_entry_get_text(GTK_ENTRY(data->host_entry));
            const char *user = gtk_entry_get_text(GTK_ENTRY(data->user_entry));
            const char *port = gtk_entry_get_text(GTK_ENTRY(data->port_entry));
            const char *key_file_path = gtk_entry_get_text(GTK_ENTRY(data->key_file_entry));
            int protocol = gtk_combo_box_get_active(GTK_COMBO_BOX(data->protocol_combo));
            
            g_key_file_set_string(key_file, name, "host", host);
            g_key_file_set_string(key_file, name, "user", user);
            // Speichere immer ein leeres Passwort aus Sicherheitsgründen
            g_key_file_set_string(key_file, name, "password", "");
            g_key_file_set_string(key_file, name, "port", port);
            g_key_file_set_string(key_file, name, "key_file", key_file_path ? key_file_path : "");
            g_key_file_set_integer(key_file, name, "protocol", protocol);
            
            // Speichere in Datei
            gsize length;
            gchar *data_str = g_key_file_to_data(key_file, &length, &error);
            if (!error) {
                g_file_set_contents(config_file, data_str, length, &error);
            }
            
            if (error) {
                char msg[256];
                snprintf(msg, sizeof(msg), "Error saving: %s", error->message);
                gtk_label_set_text(GTK_LABEL(data->status_label), msg);
                g_error_free(error);
            } else {
                gtk_label_set_text(GTK_LABEL(data->status_label), "Connection saved!");
            }
            
            g_free(data_str);
            g_key_file_free(key_file);
            g_free(config_file);
        }
    }
    
    gtk_widget_destroy(dialog);
}

// Verbindung laden
void load_connection(AppData *data, const char *name) {
    char *config_file = get_config_file_path();
    GKeyFile *key_file = g_key_file_new();
    GError *error = NULL;
    
    if (g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, &error)) {
        gchar *host = g_key_file_get_string(key_file, name, "host", NULL);
        gchar *user = g_key_file_get_string(key_file, name, "user", NULL);
        gchar *password = g_key_file_get_string(key_file, name, "password", NULL);
        gchar *port = g_key_file_get_string(key_file, name, "port", NULL);
        gchar *key_file_path = g_key_file_get_string(key_file, name, "key_file", NULL);
        gint protocol = g_key_file_get_integer(key_file, name, "protocol", NULL);
        
        if (host) gtk_entry_set_text(GTK_ENTRY(data->host_entry), host);
        if (user) gtk_entry_set_text(GTK_ENTRY(data->user_entry), user);
        if (password) gtk_entry_set_text(GTK_ENTRY(data->password_entry), password);
        if (port) gtk_entry_set_text(GTK_ENTRY(data->port_entry), port);
        if (key_file_path) gtk_entry_set_text(GTK_ENTRY(data->key_file_entry), key_file_path);
        if (protocol >= 0 && protocol <= 1) {
            gtk_combo_box_set_active(GTK_COMBO_BOX(data->protocol_combo), protocol);
        }
        
        g_free(host);
        g_free(user);
        g_free(password);
        g_free(port);
        g_free(key_file_path);
        
        gtk_label_set_text(GTK_LABEL(data->status_label), "Connection loaded!");
    }
    
    if (error) {
        g_error_free(error);
    }
    
    g_key_file_free(key_file);
    g_free(config_file);
}

// Verbindung löschen
void delete_connection(const char *name) {
    char *config_file = get_config_file_path();
    GKeyFile *key_file = g_key_file_new();
    GError *error = NULL;
    
    // Lade existierende Konfiguration
    g_key_file_load_from_file(key_file, config_file, G_KEY_FILE_NONE, NULL);
    
    // Entferne Gruppe
    g_key_file_remove_group(key_file, name, &error);
    
    if (!error) {
        // Speichere aktualisierte Konfiguration
        gsize length;
        gchar *data_str = g_key_file_to_data(key_file, &length, NULL);
        if (data_str) {
            g_file_set_contents(config_file, data_str, length, NULL);
            g_free(data_str);
        }
    }
    
    if (error) {
        g_error_free(error);
    }
    
    g_key_file_free(key_file);
    g_free(config_file);
}

// Callback für Delete-Button in Load-Dialog
void on_delete_connection_clicked(GtkWidget *widget, gpointer user_data) {
    char *name = (char*)user_data;
    
    // Bestätigungsdialog anzeigen
    GtkWidget *confirm_dialog = gtk_message_dialog_new(NULL,
                                                        GTK_DIALOG_MODAL,
                                                        GTK_MESSAGE_QUESTION,
                                                        GTK_BUTTONS_YES_NO,
                                                        "Are you sure you want to delete the connection '%s'?",
                                                        name);
    gtk_window_set_title(GTK_WINDOW(confirm_dialog), "Confirm Delete");
    
    gint response = gtk_dialog_run(GTK_DIALOG(confirm_dialog));
    gtk_widget_destroy(confirm_dialog);
    
    if (response == GTK_RESPONSE_YES) {
        delete_connection(name);
        
        // Schließe den Dialog und öffne ihn neu
        GtkWidget *dialog = gtk_widget_get_toplevel(widget);
        if (GTK_IS_DIALOG(dialog)) {
            gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
            // Öffne Dialog neu nach kurzer Verzögerung
            g_timeout_add(100, load_connection_dialog_func, app_data);
        }
    }
    
    g_free(name);
}

// Callback für Load-Button in Load-Dialog
void on_load_connection_clicked(GtkWidget *widget, gpointer user_data) {
    char *name = (char*)user_data;
    AppData *app = app_data;
    
    if (app) {
        load_connection(app, name);
        g_free(name);
        
        // Schließe den Dialog
        GtkWidget *dialog = gtk_widget_get_toplevel(widget);
        if (GTK_IS_DIALOG(dialog)) {
            gtk_dialog_response(GTK_DIALOG(dialog), GTK_RESPONSE_CLOSE);
        }
        
        // Automatisch Verbindung öffnen, wenn nicht bereits verbunden
        if (!app->connected) {
            connect_ssh(app);
        }
    }
}

// Load-Dialog anzeigen (kann als GSourceFunc verwendet werden)
gboolean load_connection_dialog_func(gpointer data) {
    AppData *app = (AppData*)data;
    load_connection_dialog(app);
    return FALSE; // Nur einmal ausführen
}

// Load-Dialog anzeigen
void load_connection_dialog(AppData *data) {
    GtkWidget *dialog = gtk_dialog_new_with_buttons("Saved Connections",
                                                     NULL,
                                                     GTK_DIALOG_MODAL,
                                                     "Close", GTK_RESPONSE_CLOSE,
                                                     NULL);
    
    // Setze die Fenstergröße (2.5 mal so breit wie bisher)
    // Standard-Dialog-Breite ist etwa 400px, daher 400 * 2.5 = 1000px
    gtk_window_set_default_size(GTK_WINDOW(dialog), 1000, 400);
    
    GtkWidget *content = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    gtk_container_set_border_width(GTK_CONTAINER(content), 10);
    
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_scrolled_window_set_min_content_height(GTK_SCROLLED_WINDOW(scroll), 300);
    gtk_scrolled_window_set_min_content_width(GTK_SCROLLED_WINDOW(scroll), 950);
    
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    
    GList *names = get_saved_connection_names();
    GList *iter = names;
    
    if (names == NULL) {
        GtkWidget *label = gtk_label_new("No saved connections");
        gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
    } else {
        while (iter != NULL) {
            char *name = (char*)iter->data;
            
            GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
            
            GtkWidget *load_btn = gtk_button_new_with_label("Load");
            g_signal_connect(load_btn, "clicked", G_CALLBACK(on_load_connection_clicked), g_strdup(name));
            
            GtkWidget *delete_btn = gtk_button_new_with_label("Delete");
            g_signal_connect(delete_btn, "clicked", G_CALLBACK(on_delete_connection_clicked), g_strdup(name));
            
            GtkWidget *label = gtk_label_new(name);
            gtk_label_set_xalign(GTK_LABEL(label), 0.0);
            gtk_widget_set_hexpand(label, TRUE);
            
            gtk_box_pack_start(GTK_BOX(hbox), load_btn, FALSE, FALSE, 0);
            gtk_box_pack_start(GTK_BOX(hbox), delete_btn, FALSE, FALSE, 0);
            gtk_box_pack_start(GTK_BOX(hbox), label, TRUE, TRUE, 0);
            
            gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);
            
            iter = iter->next;
        }
        
        // Liste freigeben
        g_list_free_full(names, g_free);
    }
    
    gtk_container_add(GTK_CONTAINER(scroll), vbox);
    gtk_container_add(GTK_CONTAINER(content), scroll);
    
    gtk_widget_show_all(dialog);
    gtk_dialog_run(GTK_DIALOG(dialog));
    gtk_widget_destroy(dialog);
}

// Callback für Browse-Key-File-Button
void on_browse_key_file_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    
    GtkWidget *dialog = gtk_file_chooser_dialog_new("Select Key File",
                                                      NULL,
                                                      GTK_FILE_CHOOSER_ACTION_OPEN,
                                                      "Cancel", GTK_RESPONSE_CANCEL,
                                                      "Open", GTK_RESPONSE_ACCEPT,
                                                      NULL);
    
    // Filter für Key-Files
    GtkFileFilter *filter = gtk_file_filter_new();
    gtk_file_filter_set_name(filter, "SSH Key Files");
    gtk_file_filter_add_pattern(filter, "*.pem");
    gtk_file_filter_add_pattern(filter, "*.key");
    gtk_file_filter_add_pattern(filter, "id_rsa");
    gtk_file_filter_add_pattern(filter, "id_ed25519");
    gtk_file_filter_add_pattern(filter, "id_ecdsa");
    gtk_file_filter_add_pattern(filter, "*");
    gtk_file_chooser_add_filter(GTK_FILE_CHOOSER(dialog), filter);
    
    if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
        char *filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if (filename) {
            gtk_entry_set_text(GTK_ENTRY(app->key_file_entry), filename);
            g_free(filename);
        }
    }
    
    gtk_widget_destroy(dialog);
}

// Callback für Save-Button
void on_save_connection_clicked(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    save_connection(app);
}

// Callback für Load-Button
void on_load_connection_clicked_main(GtkWidget *widget, gpointer data) {
    AppData *app = (AppData *)data;
    load_connection_dialog(app);
}

// Callback für Support-Button
void on_support_clicked(GtkWidget *widget, gpointer data) {
    const char *uri = "https://buymeacoffee.com/retos";
    GError *error = NULL;
    gboolean success = FALSE;
    
    // Versuche zuerst gtk_show_uri_on_window (falls verfügbar)
    GtkWindow *window = GTK_WINDOW(gtk_widget_get_toplevel(widget));
    if (window) {
        success = gtk_show_uri_on_window(window, uri, GDK_CURRENT_TIME, &error);
    }
    
    // Falls das nicht funktioniert, versuche g_app_info_launch_default_for_uri
    if (!success) {
        if (error) {
            g_error_free(error);
            error = NULL;
        }
        success = g_app_info_launch_default_for_uri(uri, NULL, &error);
    }
    
    // Falls das auch nicht funktioniert, verwende xdg-open direkt
    if (!success) {
        if (error) {
            g_error_free(error);
            error = NULL;
        }
        gchar *command = g_strdup_printf("xdg-open '%s'", uri);
        success = g_spawn_command_line_async(command, &error);
        g_free(command);
        
        // Falls xdg-open auch nicht funktioniert, versuche andere Browser
        if (!success && error) {
            g_error_free(error);
            error = NULL;
            
            // Versuche firefox
            gchar *cmd = g_strdup_printf("firefox %s &", uri);
            g_spawn_command_line_async(cmd, NULL);
            g_free(cmd);
            
            // Oder versuche chromium/chrome
            cmd = g_strdup_printf("chromium %s &", uri);
            g_spawn_command_line_async(cmd, NULL);
            g_free(cmd);
        }
    }
    
    if (error) {
        g_error_free(error);
    }
}

// GUI erstellen
GtkWidget* create_gui(AppData *data) {
    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    char title[256];
    snprintf(title, sizeof(title), "GuiSCP %s - File Transfer", VERSION);
    gtk_window_set_title(GTK_WINDOW(window), title);
    gtk_window_set_default_size(GTK_WINDOW(window), 1200, 700);
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    
    GtkWidget *main_box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_add(GTK_CONTAINER(window), main_box);
    
    // Verbindungsbereich
    GtkWidget *connection_frame = gtk_frame_new("SSH Connection");
    GtkWidget *connection_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(connection_box), 10);
    gtk_container_add(GTK_CONTAINER(connection_frame), connection_box);
    
    data->host_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(data->host_entry), "Host");
    gtk_box_pack_start(GTK_BOX(connection_box), data->host_entry, FALSE, FALSE, 0);
    
    data->user_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(data->user_entry), "User");
    gtk_box_pack_start(GTK_BOX(connection_box), data->user_entry, FALSE, FALSE, 0);
    
    data->password_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(data->password_entry), "Password");
    gtk_entry_set_visibility(GTK_ENTRY(data->password_entry), FALSE);
    gtk_box_pack_start(GTK_BOX(connection_box), data->password_entry, FALSE, FALSE, 0);
    
    data->port_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(data->port_entry), "Port (22)");
    gtk_entry_set_text(GTK_ENTRY(data->port_entry), "22");
    gtk_box_pack_start(GTK_BOX(connection_box), data->port_entry, FALSE, FALSE, 0);
    
    // Key-File-Auswahl
    GtkWidget *key_file_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 2);
    data->key_file_entry = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(data->key_file_entry), "Key File (optional)");
    gtk_box_pack_start(GTK_BOX(key_file_box), data->key_file_entry, TRUE, TRUE, 0);
    
    GtkWidget *key_file_btn = gtk_button_new_with_label("...");
    gtk_widget_set_size_request(key_file_btn, 30, -1);
    g_signal_connect(key_file_btn, "clicked", G_CALLBACK(on_browse_key_file_clicked), data);
    gtk_box_pack_start(GTK_BOX(key_file_box), key_file_btn, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(connection_box), key_file_box, FALSE, FALSE, 0);
    
    // Protokollauswahl
    GtkWidget *protocol_label = gtk_label_new("Protocol:");
    gtk_box_pack_start(GTK_BOX(connection_box), protocol_label, FALSE, FALSE, 0);
    
    data->protocol_combo = gtk_combo_box_text_new();
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(data->protocol_combo), "SFTP");
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(data->protocol_combo), "SCP");
    gtk_combo_box_set_active(GTK_COMBO_BOX(data->protocol_combo), 0); // SFTP als Standard
    gtk_box_pack_start(GTK_BOX(connection_box), data->protocol_combo, FALSE, FALSE, 0);
    
    data->connect_button = gtk_button_new_with_label("Connect");
    g_signal_connect(data->connect_button, "clicked", G_CALLBACK(on_connect_clicked), data);
    gtk_box_pack_start(GTK_BOX(connection_box), data->connect_button, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(main_box), connection_frame, FALSE, FALSE, 0);
    
    // Save/Load Buttons
    GtkWidget *save_load_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(save_load_box), 5);
    
    GtkWidget *load_btn = gtk_button_new_with_label("Load Connection");
    g_signal_connect(load_btn, "clicked", G_CALLBACK(on_load_connection_clicked_main), data);
    gtk_box_pack_start(GTK_BOX(save_load_box), load_btn, FALSE, FALSE, 0);
    
    GtkWidget *save_btn = gtk_button_new_with_label("Save Connection");
    g_signal_connect(save_btn, "clicked", G_CALLBACK(on_save_connection_clicked), data);
    gtk_box_pack_start(GTK_BOX(save_load_box), save_btn, FALSE, FALSE, 0);
    
    // Support-Button
    GtkWidget *support_btn = gtk_button_new_with_label("☕ Support");
    g_signal_connect(support_btn, "clicked", G_CALLBACK(on_support_clicked), data);
    gtk_box_pack_end(GTK_BOX(save_load_box), support_btn, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(main_box), save_load_box, FALSE, FALSE, 0);
    
    // Hauptbereich mit zwei Panels
    GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
    gtk_paned_set_position(GTK_PANED(paned), 600);
    
    // Linkes Panel (Lokal)
    GtkWidget *local_frame = gtk_frame_new("Local Files");
    GtkWidget *local_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(local_vbox), 5);
    gtk_container_add(GTK_CONTAINER(local_frame), local_vbox);
    
    GtkWidget *local_path_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    data->local_path_entry = gtk_entry_new();
    struct passwd *pw = getpwuid(getuid());
    gtk_entry_set_text(GTK_ENTRY(data->local_path_entry), pw->pw_dir);
    gtk_box_pack_start(GTK_BOX(local_path_box), data->local_path_entry, TRUE, TRUE, 0);
    
    GtkWidget *local_refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(local_refresh, "clicked", G_CALLBACK(on_local_refresh_clicked), data);
    gtk_box_pack_start(GTK_BOX(local_path_box), local_refresh, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(local_vbox), local_path_box, FALSE, FALSE, 0);
    
    // Lokale Dateiliste
    data->local_store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    data->local_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(data->local_store));
    
    // Multi-Selection aktivieren
    GtkTreeSelection *local_selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(data->local_tree));
    gtk_tree_selection_set_mode(local_selection, GTK_SELECTION_MULTIPLE);
    
    GtkCellRenderer *renderer = gtk_cell_renderer_text_new();
    GtkTreeViewColumn *column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", 0, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->local_tree), column);
    
    column = gtk_tree_view_column_new_with_attributes("Type", renderer, "text", 1, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 1);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->local_tree), column);
    
    column = gtk_tree_view_column_new_with_attributes("Size", renderer, "text", 2, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 2);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->local_tree), column);
    
    // Standard-Sortierung nach Dateiname (Spalte 0, aufsteigend)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(data->local_store), 0, GTK_SORT_ASCENDING);
    
    g_signal_connect(data->local_tree, "row-activated", G_CALLBACK(on_local_row_activated), data);
    g_signal_connect(data->local_tree, "key-press-event", G_CALLBACK(on_local_tree_key_press), data);
    gtk_widget_set_can_focus(data->local_tree, TRUE);
    
    // Drag-and-Drop: Lokale TreeView als Drag-Source (für Drag zu Remote)
    GtkTargetEntry targets[] = {
        { "text/plain", 0, 0 }
    };
    gtk_tree_view_enable_model_drag_source(GTK_TREE_VIEW(data->local_tree), GDK_BUTTON1_MASK, targets, 1, GDK_ACTION_COPY);
    g_signal_connect(data->local_tree, "drag-begin", G_CALLBACK(on_local_drag_begin), data);
    g_signal_connect(data->local_tree, "drag-data-get", G_CALLBACK(on_local_drag_data_get), data);
    
    // Drag-and-Drop: Lokale TreeView als Drop-Target (für Drop von Remote)
    gtk_tree_view_enable_model_drag_dest(GTK_TREE_VIEW(data->local_tree), targets, 1, GDK_ACTION_COPY);
    g_signal_connect(data->local_tree, "drag-data-received", G_CALLBACK(on_local_drag_data_received), data);
    
    GtkWidget *local_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(local_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(local_scroll), data->local_tree);
    gtk_box_pack_start(GTK_BOX(local_vbox), local_scroll, TRUE, TRUE, 0);
    
    GtkWidget *copy_to_remote_btn = gtk_button_new_with_label("→ Copy to Remote");
    g_signal_connect(copy_to_remote_btn, "clicked", G_CALLBACK(on_copy_to_remote_clicked), data);
    gtk_box_pack_start(GTK_BOX(local_vbox), copy_to_remote_btn, FALSE, FALSE, 0);
    
    GtkWidget *delete_local_btn = gtk_button_new_with_label("🗑 Delete");
    g_signal_connect(delete_local_btn, "clicked", G_CALLBACK(on_delete_local_clicked), data);
    gtk_box_pack_start(GTK_BOX(local_vbox), delete_local_btn, FALSE, FALSE, 0);
    
    GtkWidget *mkdir_local_btn = gtk_button_new_with_label("📁 Mkdir");
    g_signal_connect(mkdir_local_btn, "clicked", G_CALLBACK(on_mkdir_local_clicked), data);
    gtk_box_pack_start(GTK_BOX(local_vbox), mkdir_local_btn, FALSE, FALSE, 0);
    
    gtk_paned_add1(GTK_PANED(paned), local_frame);
    
    // Rechtes Panel (Remote)
    GtkWidget *remote_frame = gtk_frame_new("Remote Files");
    GtkWidget *remote_vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 5);
    gtk_container_set_border_width(GTK_CONTAINER(remote_vbox), 5);
    gtk_container_add(GTK_CONTAINER(remote_frame), remote_vbox);
    
    GtkWidget *remote_path_box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 5);
    data->remote_path_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(data->remote_path_entry), ".");
    gtk_box_pack_start(GTK_BOX(remote_path_box), data->remote_path_entry, TRUE, TRUE, 0);
    
    GtkWidget *remote_refresh = gtk_button_new_with_label("Refresh");
    g_signal_connect(remote_refresh, "clicked", G_CALLBACK(on_remote_refresh_clicked), data);
    gtk_box_pack_start(GTK_BOX(remote_path_box), remote_refresh, FALSE, FALSE, 0);
    
    gtk_box_pack_start(GTK_BOX(remote_vbox), remote_path_box, FALSE, FALSE, 0);
    
    // Remote-Dateiliste
    data->remote_store = gtk_list_store_new(3, G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING);
    data->remote_tree = gtk_tree_view_new_with_model(GTK_TREE_MODEL(data->remote_store));
    
    // Multi-Selection aktivieren
    GtkTreeSelection *remote_selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(data->remote_tree));
    gtk_tree_selection_set_mode(remote_selection, GTK_SELECTION_MULTIPLE);
    
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Name", renderer, "text", 0, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 0);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->remote_tree), column);
    
    column = gtk_tree_view_column_new_with_attributes("Type", renderer, "text", 1, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 1);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->remote_tree), column);
    
    column = gtk_tree_view_column_new_with_attributes("Size", renderer, "text", 2, NULL);
    gtk_tree_view_column_set_clickable(column, TRUE);
    gtk_tree_view_column_set_sort_column_id(column, 2);
    gtk_tree_view_append_column(GTK_TREE_VIEW(data->remote_tree), column);
    
    // Standard-Sortierung nach Dateiname (Spalte 0, aufsteigend)
    gtk_tree_sortable_set_sort_column_id(GTK_TREE_SORTABLE(data->remote_store), 0, GTK_SORT_ASCENDING);
    
    g_signal_connect(data->remote_tree, "row-activated", G_CALLBACK(on_remote_row_activated), data);
    g_signal_connect(data->remote_tree, "key-press-event", G_CALLBACK(on_remote_tree_key_press), data);
    gtk_widget_set_can_focus(data->remote_tree, TRUE);
    
    // Drag-and-Drop: Remote TreeView als Drag-Source (für Drag zu Local)
    GtkTargetEntry targets_remote[] = {
        { "text/plain", 0, 0 }
    };
    gtk_tree_view_enable_model_drag_source(GTK_TREE_VIEW(data->remote_tree), GDK_BUTTON1_MASK, targets_remote, 1, GDK_ACTION_COPY);
    g_signal_connect(data->remote_tree, "drag-begin", G_CALLBACK(on_remote_drag_begin), data);
    g_signal_connect(data->remote_tree, "drag-data-get", G_CALLBACK(on_remote_drag_data_get), data);
    
    // Drag-and-Drop: Remote TreeView als Drop-Target (für Drop von Local)
    gtk_tree_view_enable_model_drag_dest(GTK_TREE_VIEW(data->remote_tree), targets_remote, 1, GDK_ACTION_COPY);
    g_signal_connect(data->remote_tree, "drag-data-received", G_CALLBACK(on_remote_drag_data_received), data);
    
    GtkWidget *remote_scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(remote_scroll), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    gtk_container_add(GTK_CONTAINER(remote_scroll), data->remote_tree);
    gtk_box_pack_start(GTK_BOX(remote_vbox), remote_scroll, TRUE, TRUE, 0);
    
    GtkWidget *copy_to_local_btn = gtk_button_new_with_label("← Copy to Local");
    g_signal_connect(copy_to_local_btn, "clicked", G_CALLBACK(on_copy_to_local_clicked), data);
    gtk_box_pack_start(GTK_BOX(remote_vbox), copy_to_local_btn, FALSE, FALSE, 0);
    
    GtkWidget *delete_remote_btn = gtk_button_new_with_label("🗑 Delete");
    g_signal_connect(delete_remote_btn, "clicked", G_CALLBACK(on_delete_remote_clicked), data);
    gtk_box_pack_start(GTK_BOX(remote_vbox), delete_remote_btn, FALSE, FALSE, 0);
    
    GtkWidget *mkdir_remote_btn = gtk_button_new_with_label("📁 Mkdir");
    g_signal_connect(mkdir_remote_btn, "clicked", G_CALLBACK(on_mkdir_remote_clicked), data);
    gtk_box_pack_start(GTK_BOX(remote_vbox), mkdir_remote_btn, FALSE, FALSE, 0);
    
    gtk_paned_add2(GTK_PANED(paned), remote_frame);
    
    gtk_box_pack_start(GTK_BOX(main_box), paned, TRUE, TRUE, 0);
    
    // Statuszeile
    data->status_label = gtk_label_new("Ready");
    gtk_box_pack_start(GTK_BOX(main_box), data->status_label, FALSE, FALSE, 0);
    
    // Fortschrittsbalken
    data->progress_bar = gtk_progress_bar_new();
    gtk_progress_bar_set_show_text(GTK_PROGRESS_BAR(data->progress_bar), TRUE);
    gtk_progress_bar_set_fraction(GTK_PROGRESS_BAR(data->progress_bar), 0.0);
    gtk_widget_set_visible(data->progress_bar, FALSE); // Versteckt, bis ein Transfer startet
    gtk_box_pack_start(GTK_BOX(main_box), data->progress_bar, FALSE, FALSE, 0);
    
    return window;
}

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);
    
    app_data = g_malloc0(sizeof(AppData));
    app_data->connected = 0;
    app_data->session = NULL;
    app_data->sftp = NULL;
    app_data->use_scp = 0;  // Standard ist SFTP
    app_data->overwrite_all = 0;
    app_data->skip_all = 0;
    app_data->copy_aborted = 0;
    
    GtkWidget *window = create_gui(app_data);
    
    // Initial lokales Verzeichnis laden
    refresh_local_directory(app_data);
    
    gtk_widget_show_all(window);
    gtk_main();
    
    // Cleanup
    if (app_data->connected) {
        disconnect_ssh(app_data);
    }
    g_free(app_data);
    
    return 0;
}

