# container security monitor

runtime attack detection demo for docker/kubernetes containers.

## what it does

shows how a waf (web application firewall) protects against:
- malicious script execution (rm -rf, passwd access, reverse shells)
- xss attacks via image metadata
- remote code execution attempts

## quick start

```bash
make run
```

access at http://localhost:8080 (login: admin/admin)

## features

- login system (admin/admin or demo/demo)
- script upload & execution
- image upload with metadata scanning
- toggle protection on/off to demo vulnerabilities
- real xss attack with data exfiltration
- attacker server to capture stolen data

## demo flow

1. upload `scripts/xss_attack.png` with scanning enabled → blocked
2. toggle scan off → upload again → xss executes, data stolen
3. check http://localhost:9090/logs to see stolen data
4. try malicious scripts (scripts/normal.sh vs rm -rf payloads)

## structure

```
src/
  app/      - vulnerable web application
  waf/      - web application firewall (unused in current setup)
  attacker/ - attacker server for data exfiltration
scripts/    - test files (safe + malicious)
deployment/ - docker-compose & k8s configs
```

## cleanup

```bash
make down
```

## notes

- designed for demos, not production
- shows real vulnerabilities when protection disabled
- educational purposes only
