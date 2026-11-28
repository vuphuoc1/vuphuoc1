---
render_with_liquid: false
title: "DFIR 2025 Ⅱ - fake news"
date: 2025-11-27 10:27:00 +0700
categories: [DFIR]
tags: [CTF,DFIR Labs, Memory Dump,PCAP,]
---
Phần hai của chuỗi DFIR 2025, nối tiếp ngay sau Lost In Router. Ở bài trước, router của công ty bị chiếm và tên miền nội bộ portal.r3.internal bị trỏ sang một trang giả trên Netlify. Bài này đi tiếp phía nạn nhân: một nhân viên thấy thông báo "cần cập nhật Chrome", làm theo hướng dẫn, rồi mới nhận ra máy mình làm gì có Chrome. Độ khó Insane, flag format r3ctf{...}. Tài liệu giao gồm một memory dump Windows (dump.raw) và một file capture.pcapng
Mình bắt đầu bằng windows.pslist để xem trong máy có gì bất thường. Có hai tiến trình đáng ngờ ngay từ đầu:

plaintext
PID   PPID  Name            Create (UTC)          Exit (UTC)
7336  3816  powershell.exe  2025-07-05 12:39:48   2025-07-05 12:40:07
9020  804   chrome.exe      2025-07-05 12:49:07   N/A

Đề nói máy không cài Chrome, vậy mà lại có chrome.exe đang chạy, chỉ 4 thread, không có tiến trình con nào (Chrome thật luôn kéo theo một đống renderer/gpu process), và tiến trình cha 804 đã biến mất kể cả với psscan. windows.netscan xác nhận nghi ngờ:





