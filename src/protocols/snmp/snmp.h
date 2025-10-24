#ifndef SNMP_H
#define SNMP_H

#include <stdint.h>
#include <pcap.h>  // for u_char

// SNMP Protocol Constants
#define SNMP_PORT 161
#define SNMP_TRAP_PORT 162
#define SNMP_MAX_COMMUNITY_LEN 255
#define SNMP_MAX_OID_LEN 128

// SNMP Versions
#define SNMP_VERSION_1 0
#define SNMP_VERSION_2C 1
#define SNMP_VERSION_3 3

// SNMP PDU Types
#define SNMP_PDU_GET_REQUEST 0xA0
#define SNMP_PDU_GET_NEXT_REQUEST 0xA1
#define SNMP_PDU_GET_RESPONSE 0xA2
#define SNMP_PDU_SET_REQUEST 0xA3
#define SNMP_PDU_TRAP_V1 0xA4
#define SNMP_PDU_GET_BULK_REQUEST 0xA5
#define SNMP_PDU_INFORM_REQUEST 0xA6
#define SNMP_PDU_TRAP_V2 0xA7
#define SNMP_PDU_REPORT 0xA8

// SNMP Error Status
#define SNMP_ERROR_NO_ERROR 0
#define SNMP_ERROR_TOO_BIG 1
#define SNMP_ERROR_NO_SUCH_NAME 2
#define SNMP_ERROR_BAD_VALUE 3
#define SNMP_ERROR_READ_ONLY 4
#define SNMP_ERROR_GEN_ERR 5
#define SNMP_ERROR_NO_ACCESS 6
#define SNMP_ERROR_WRONG_TYPE 7
#define SNMP_ERROR_WRONG_LENGTH 8
#define SNMP_ERROR_WRONG_ENCODING 9
#define SNMP_ERROR_WRONG_VALUE 10
#define SNMP_ERROR_NO_CREATION 11
#define SNMP_ERROR_INCONSISTENT_VALUE 12
#define SNMP_ERROR_RESOURCE_UNAVAILABLE 13
#define SNMP_ERROR_COMMIT_FAILED 14
#define SNMP_ERROR_UNDO_FAILED 15
#define SNMP_ERROR_AUTHORIZATION_ERROR 16
#define SNMP_ERROR_NOT_WRITABLE 17
#define SNMP_ERROR_INCONSISTENT_NAME 18

// ASN.1 BER Tags
#define ASN1_SEQUENCE 0x30
#define ASN1_INTEGER 0x02
#define ASN1_OCTET_STRING 0x04
#define ASN1_NULL 0x05
#define ASN1_OBJECT_IDENTIFIER 0x06
#define ASN1_COUNTER32 0x41
#define ASN1_GAUGE32 0x42
#define ASN1_TIMETICKS 0x43
#define ASN1_OPAQUE 0x44
#define ASN1_COUNTER64 0x46

// SNMP Message Structure
typedef struct {
    int version;
    char community[SNMP_MAX_COMMUNITY_LEN + 1];
    uint8_t pdu_type;
    uint32_t request_id;
    uint32_t error_status;
    uint32_t error_index;
    int varbind_count;
} snmp_message_t;

// SNMP Variable Binding
typedef struct {
    char oid[SNMP_MAX_OID_LEN];
    uint8_t value_type;
    union {
        int32_t integer_value;
        uint32_t counter_value;
        uint32_t gauge_value;
        uint32_t timeticks_value;
        char string_value[256];
    } value;
} snmp_varbind_t;

// Function declarations
void parse_snmp(const u_char *payload, int payload_len, int src_port, int dst_port);
int parse_snmp_message(const u_char *data, int len, snmp_message_t *msg);
int parse_asn1_length(const u_char *data, int len, int *length_bytes);
int parse_asn1_integer(const u_char *data, int len, int32_t *value);
int parse_asn1_string(const u_char *data, int len, char *buffer, int buf_size);
int parse_asn1_oid(const u_char *data, int len, char *oid_str, int oid_size);
int parse_snmp_pdu(const u_char *data, int len, snmp_message_t *msg);
int parse_snmp_varbinds(const u_char *data, int len, snmp_varbind_t *varbinds, int max_varbinds);
const char* get_snmp_version_name(int version);
const char* get_snmp_pdu_type_name(uint8_t pdu_type);
const char* get_snmp_error_name(uint32_t error_code);
const char* get_asn1_type_name(uint8_t type);
const char* resolve_oid_name(const char *oid);
void analyze_snmp_security(const snmp_message_t *msg);
int is_snmp_traffic(int src_port, int dst_port);

#endif // SNMP_H
