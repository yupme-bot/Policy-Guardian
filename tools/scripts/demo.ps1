$bin = '.\dist\policyguardian.exe'
& $bin policylock snapshot --created-at 2026-01-01T00:00:00Z --out demo_snapshot.zip fixtures/policylock/policy1.txt
& $bin consent record --subject 'Alice@example.com' --tenant-salt 0011 --pepper aabb --created-at 2026-01-01T00:00:01Z --out demo_consent.json demo_snapshot.zip
& $bin policylock verify demo_snapshot.zip
& $bin consent verify --resolve-snapshot demo_consent.json
