#include <stdio.h>
#include <stdlib.h>
#include <libpq-fe.h>

int main() {
    printf("Starting database connection...\n");
    
    const char* db_host = "localhost";
    const char* db_port = "5432";
    const char* db_name = "production_db";
    const char* db_user = "admin";
    const char* db_password = "secret_password_123";
    
    // Build connection string with hard-coded credentials
    char conninfo[512];
    snprintf(conninfo, sizeof(conninfo), 
             "host=%s port=%s dbname=%s user=%s password=%s",
             db_host, db_port, db_name, db_user, db_password);
    
    printf("Connecting to database with hard-coded credentials...\n");
    printf("Host: %s\n", db_host);
    printf("Database: %s\n", db_name);
    printf("User: %s\n", db_user);
    
    // SINK CWE 798
    PGconn* conn = PQconnectdb(conninfo);
    
    if (PQstatus(conn) == CONNECTION_OK) {
        printf("Database connection successful!\n");
        
        // Perform multiple database operations using hardcoded credentials
        PGresult* res = PQexec(conn, "SELECT version();");
        if (res != NULL) {
            printf("Database version: %s\n", PQgetvalue(res, 0, 0));
            PQclear(res);
        }
        
        // Query user table using hardcoded credentials
        res = PQexec(conn, "SELECT username, email FROM users WHERE role = 'admin';");
        if (res != NULL && PQntuples(res) > 0) {
            printf("Admin users found: %d\n", PQntuples(res));
            for (int i = 0; i < PQntuples(res); i++) {
                printf("  User: %s, Email: %s\n", 
                       PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
            }
            PQclear(res);
        }
        
        // Update last login using hardcoded credentials
        char updateQuery[256];
        snprintf(updateQuery, sizeof(updateQuery), 
                "UPDATE users SET last_login = NOW() WHERE username = '%s';", db_user);
        res = PQexec(conn, updateQuery);
        if (res != NULL) {
            printf("Last login updated for user: %s\n", db_user);
            PQclear(res);
        }
        
        // Create backup table using hardcoded credentials
        res = PQexec(conn, "CREATE TABLE IF NOT EXISTS backup_log (id SERIAL PRIMARY KEY, timestamp TIMESTAMP, user_name VARCHAR(50));");
        if (res != NULL) {
            printf("Backup table created/verified\n");
            PQclear(res);
        }
        
        // Insert backup log entry
        char insertQuery[256];
        snprintf(insertQuery, sizeof(insertQuery), 
                "INSERT INTO backup_log (timestamp, user_name) VALUES (NOW(), '%s');", db_user);
        res = PQexec(conn, insertQuery);
        if (res != NULL) {
            printf("Backup log entry created for user: %s\n", db_user);
            PQclear(res);
        }
        
        PQfinish(conn);
    } else {
        printf("Database connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }
    
    return 0;
}