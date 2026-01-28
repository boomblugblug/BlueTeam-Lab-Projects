# 🚨 Splunk Detection Rules (Alert Rules)

เอกสารฉบับนี้อธิบาย Detection Rules ที่พัฒนาขึ้นสำหรับใช้ใน SOC Dashboard  
โดยเน้นการตรวจจับพฤติกรรมโจมตีที่พบบ่อยในระบบจริง เช่น  
- Brute Force
- SQL Injection
- RDP Attack
- DoS Web

---

## 🔐 Rule 1: Brute Force Attack – Web Application

### 🎯 Objective
ตรวจจับความพยายามสุ่มรหัสผ่าน (Brute Force) บน Web Application  
โดยพิจารณาจากพฤติกรรม Login ซ้ำ ๆ ภายในช่วงเวลาสั้น

### 🔎 Detection Logic
- ตรวจเฉพาะ HTTP `POST` ที่เข้าหน้า `login.php`
- แยกสถานะการ Login:
  - `302` → Login Success
  - `200` → Login Fail
- นับจำนวน Success และ Fail ต่อ IP ภายใน 5 นาที
- Trigger Alert เมื่อ:
  - มี Success ≥ 1
  - มี Fail ≥ 10

### 🧠 SPL Rule
```spl
sourcetype=access_combined referer="http://192.168.70.142:8080/login.php*"
| bucket _time span=5m
| eval status_login = if(like(method,"%POST%") AND like(uri,"%login.php%") AND status=302,"Success",
                          if(like(method,"%POST%") AND like(uri,"%login.php%") AND status=200,"Fail","None"))
| where status_login="Success" OR status_login="Fail"
| stats count(eval(status_login="Success")) as Success 
        count(eval(status_login="Fail")) as Fail 
        by _time, clientip
| eval alert="Brute Force Attack"
| where Success >= 1 AND Fail >= 10
```


## 💉 Rule 2: SQL Injection Detection
### 🎯 Objective
ตรวจจับความพยายามโจมตี SQL Injection จาก Request URI และ User-Agent

### 🔎 Detection Logic
- ตรวจ pattern ที่พบบ่อย:
 - union select
 - information_schema
 - sqlmap
- Decode URI เพื่อป้องกัน evasion
- นับจำนวน URI ต่อ IP

### 🧠 SPL Rule
```spl
sourcetype=access_combined uri="*union*select*" OR uri="*information_schema*" OR useragent="*sqlmap*"
| bucket _time span=1m
| eval uri = urldecode(uri)
| stats values(uri), dc(uri) as count 
        by _time, clientip, method, status, useragent
| where count > 1
```


## 🖥️ Rule 3: Brute Force Login – RDP
### 🎯 Objective
ตรวจจับการสุ่มรหัสผ่านผ่าน Remote Desktop Protocol (RDP)

## 🔎 Detection Logic
- EventCode:
 - `4624` → Login Success
 - `4625` → Login Failure
- Logon_Type = 10 (Remote Interactive)
- Trigger เมื่อ Fail > 3 ภายใน 5 นาที

### 🧠 SPL Rule
```spl
sourcetype="WinEventLog:Security" (EventCode=4624 AND Logon_Type=10) OR EventCode=4625
| eval rule_name="Brute Force Login"
| eval severity="Medium"
| eval Account_Name=mvindex(Account_Name,1)
| bucket _time span=5m
| eval action=if(EventCode=4624,"Success","Fail")
| stats count(eval(action="Success")) as Success 
        count(eval(action="Fail")) as Fail 
        by _time, rule_name, severity, Source_Network_Address, Account_Name, ComputerName
| rename Source_Network_Address as source, 
         ComputerName as destination, 
         Account_Name as target_user
| search Fail > 3
```


## 🌐 Rule 4: DoS Web Detection
### 🎯 Objective
ตรวจจับพฤติกรรม Flood Request ที่อาจนำไปสู่ Denial of Service

## 🔎 Detection Logic
- นับจำนวน Request ต่อ IP ต่อ URI
- ใช้ Time Window = 1 นาที
- Trigger เมื่อ Request > 1000

### 🧠 SPL Rule
```spl
sourcetype=access_combined
| eval rule_name="DoS Web"
| eval severity="Low"
| bucket _time span=1m
| stats count by _time, clientip, uri, rule_name, severity
| where count > 1000
```
