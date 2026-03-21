package manager

import (
    "errors"
    "net"
    "strings"
    "sync"

    "github.com/amnezia-vpn/amneziawg-windows-client/services"
)

const localDNSRecordsKey = "LocalDNSRecords"

// LocalDNSRecord represents a local DNS record (domain -> IP)
type LocalDNSRecord struct {
    Domain string
    IP     string
}

var (
    localRecords     []LocalDNSRecord
    localRecordsLock sync.Mutex
)

func loadLocalRecordsLocked() {
    // Always reload from persistent storage so changes made from another process
    // (UI <-> manager service) are visible immediately.
    s := services.UserKeyString(localDNSRecordsKey)
    if s == "" {
        localRecords = []LocalDNSRecord{}
        return
    }
    // Format: domain1=ip1;domain2=ip2;...
    items := strings.Split(s, ";")
    out := make([]LocalDNSRecord, 0, len(items))
    for _, it := range items {
        it = strings.TrimSpace(it)
        if it == "" {
            continue
        }
        parts := strings.SplitN(it, "=", 2)
        if len(parts) == 2 {
            domain := strings.TrimSpace(parts[0])
            ip := strings.TrimSpace(parts[1])
            if domain != "" && ip != "" {
                out = append(out, LocalDNSRecord{Domain: domain, IP: ip})
            }
        }
    }
    localRecords = out
}

func saveLocalRecordsLocked() error {
    var parts []string
    for _, r := range localRecords {
        parts = append(parts, r.Domain+"="+r.IP)
    }
    s := strings.Join(parts, ";")
    return services.SetUserKeyString(localDNSRecordsKey, s)
}

// GetLocalDNSRecords returns a copy of current local DNS records.
func GetLocalDNSRecords() []LocalDNSRecord {
    localRecordsLock.Lock()
    defer localRecordsLock.Unlock()
    loadLocalRecordsLocked()
    result := make([]LocalDNSRecord, len(localRecords))
    copy(result, localRecords)
    return result
}

// AddLocalDNSRecord adds a local DNS record (domain -> IP) if not present.
func AddLocalDNSRecord(domain, ip string) error {
    domain = strings.TrimSpace(strings.ToLower(domain))
    domain = strings.TrimPrefix(domain, "*.")
    domain = strings.TrimSuffix(domain, ".")
    ip = strings.TrimSpace(ip)
    if domain == "" {
        return errors.New("domain cannot be empty")
    }
    if ip == "" {
        return errors.New("IP address cannot be empty")
    }
    // Validate IP
    if net.ParseIP(ip) == nil {
        return errors.New("invalid IP address: " + ip)
    }
    localRecordsLock.Lock()
    defer localRecordsLock.Unlock()
    loadLocalRecordsLocked()
    // Check if exists and update
    for i, r := range localRecords {
        if strings.EqualFold(r.Domain, domain) {
            localRecords[i].IP = ip
            return saveLocalRecordsLocked()
        }
    }
    localRecords = append(localRecords, LocalDNSRecord{Domain: domain, IP: ip})
    return saveLocalRecordsLocked()
}

// RemoveLocalDNSRecord removes a local DNS record by domain.
func RemoveLocalDNSRecord(domain string) error {
    domain = strings.TrimSpace(strings.ToLower(domain))
    domain = strings.TrimPrefix(domain, "*.")
    domain = strings.TrimSuffix(domain, ".")
    if domain == "" {
        return nil
    }
    localRecordsLock.Lock()
    defer localRecordsLock.Unlock()
    loadLocalRecordsLocked()
    newList := make([]LocalDNSRecord, 0, len(localRecords))
    for _, r := range localRecords {
        if !strings.EqualFold(r.Domain, domain) {
            newList = append(newList, r)
        }
    }
    localRecords = newList
    return saveLocalRecordsLocked()
}

// LookupLocalDNS looks up a domain in local records.
// Returns IP if found, empty string if not.
func LookupLocalDNS(domain string) string {
    domain = strings.TrimSpace(strings.ToLower(domain))
    domain = strings.TrimPrefix(domain, "*.")
    domain = strings.TrimSuffix(domain, ".")
    localRecordsLock.Lock()
    defer localRecordsLock.Unlock()
    loadLocalRecordsLocked()
    for _, r := range localRecords {
        if strings.EqualFold(r.Domain, domain) {
            return r.IP
        }
        // Also check if domain is a subdomain
        if strings.HasSuffix(domain, "."+strings.ToLower(r.Domain)) {
            return r.IP
        }
    }
    return ""
}

// Legacy compatibility - keep old functions but make them no-ops or redirect
func GetDNSBlocklist() []string {
    return nil // Deprecated
}

func AddDNSBlocked(addr string) error {
    return nil // Deprecated
}

func RemoveDNSBlocked(addr string) error {
    return nil // Deprecated
}
