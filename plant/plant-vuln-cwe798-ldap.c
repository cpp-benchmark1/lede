#include <stdio.h>
#include <stdlib.h>
#include <ldap.h>

int main() {
    printf("Starting LDAP authentication...\n");
    
    const char* ldap_host = "ldap.company.com";
    const int ldap_port = 389;
    const char* ldap_user = "cn=admin,dc=company,dc=com";
    const char* ldap_password = "admin_password_456";
    
    printf("Connecting to LDAP server with hard-coded credentials...\n");
    printf("Host: %s:%d\n", ldap_host, ldap_port);
    printf("User: %s\n", ldap_user);
    
    // Initialize LDAP connection
    LDAP* ld = ldap_init(ldap_host, ldap_port);
    if (ld == NULL) {
        printf("Failed to initialize LDAP connection\n");
        return 1;
    }
    
    // Set LDAP version
    int version = LDAP_VERSION3;
    if (ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version) != LDAP_OPT_SUCCESS) {
        printf("Failed to set LDAP version\n");
        ldap_unbind(ld);
        return 1;
    }
    
    // SINK CWE 798
    int result = ldap_simple_bind_s(ld, ldap_user, ldap_password);
    
    if (result == LDAP_SUCCESS) {
        printf("LDAP authentication successful!\n");
        
        // Search for users in the directory
        char searchFilter[] = "(objectClass=person)";
        char* attributes[] = {"cn", "mail", NULL};
        
        LDAPMessage* searchResult = NULL;
        result = ldap_search_s(ld, "dc=company,dc=com", LDAP_SCOPE_SUBTREE, 
                              searchFilter, attributes, 0, &searchResult);
        
        if (result == LDAP_SUCCESS) {
            int numEntries = ldap_count_entries(ld, searchResult);
            printf("Found %d user entries in LDAP directory\n", numEntries);
            
            // Show first entry
            LDAPMessage* entry = ldap_first_entry(ld, searchResult);
            if (entry != NULL) {
                char* dn = ldap_get_dn(ld, entry);
                printf("First entry: %s\n", dn);
                ldap_memfree(dn);
            }
            
            ldap_msgfree(searchResult);
        }
        
    } else {
        printf("LDAP authentication failed: %s\n", ldap_err2string(result));
        ldap_unbind(ld);
        return 1;
    }
    
    ldap_unbind(ld);
    return 0;
}