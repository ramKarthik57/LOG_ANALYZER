# Sample Authentication Log Analysis Results

## Input: sample_auth.log
```
Jan 15 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:46 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:30:47 server sshd[1234]: Failed password for root from 192.168.1.100 port 22 ssh2
Jan 15 10:31:12 server sshd[1235]: Accepted password for user1 from 192.168.1.50 port 22 ssh2
Jan 15 10:31:15 server sshd[1236]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 10:31:16 server sshd[1236]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 10:31:17 server sshd[1236]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 10:31:18 server sshd[1236]: Failed password for admin from 10.0.0.5 port 22 ssh2
Jan 15 10:31:19 server sshd[1236]: Failed password for admin from 10.0.0.5 port 22 ssh2
```

## SENTINEL Analysis Results

### Detected Anomalies
- **Brute Force Attack**: 5 failed login attempts from 10.0.0.5 targeting 'admin' account
- **Suspicious IP**: 192.168.1.100 shows 3 rapid failed attempts

### Risk Scores
- IP 10.0.0.5: High Risk (Score: 8.5/10)
- IP 192.168.1.100: Medium Risk (Score: 6.2/10)
- IP 192.168.1.50: Low Risk (Score: 2.1/10)

### Attack Chain Reconstruction
1. Reconnaissance: Initial failed attempts from 192.168.1.100
2. Brute Force: Sustained attack from 10.0.0.5
3. Potential Success: If continued, could lead to account compromise

### Recommendations
- Block IP 10.0.0.5 temporarily
- Monitor 'admin' account closely
- Review SSH configuration for fail2ban integration
- Consider geo-blocking non-local IPs