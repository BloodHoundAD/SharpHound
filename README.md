---
owern: SpecterOps
project: SharpHound Open Source Client
version: *.*
---

# SharpHound 

```csharp
dotnet restore .
dotnet build
dotnet run -- --ldap-username foo --ldap-password bar --loop True --loop-duration 00:00:00.0000020 --loop-interval 00:00:00.0000005 --override-user-name foobaruser
```