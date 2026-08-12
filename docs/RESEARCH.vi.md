# Bản nghiên cứu tiếng Việt

## Kết luận ngắn

Hướng này khả thi trên Codespace 2 CPU, nhưng đột phá hợp lý không phải là thu
nhỏ một LLM tổng quát rồi bắt nó đọc toàn bộ source. Hướng có cơ hội tốt hơn là:

> Biên dịch source thành ngôn ngữ hành vi bảo mật MalIR, giữ bằng chứng theo
> dòng code, xử lý ca rõ ràng bằng rule/mô hình sparse, và chỉ gọi mô hình µMal
> dưới một triệu tham số cho ca không chắc chắn.

Prototype hiện tại chứng minh được chi phí kỹ thuật. Nó chưa chứng minh được độ
chính xác ngoài thực tế và chưa thể thay thế VirusTotal.

## Vì sao không nên “clone VirusTotal”

VirusTotal có nhiều engine, reputation, telemetry, sandbox và mạng lưới dữ liệu
lớn. Một máy 2 CPU không cạnh tranh được ở toàn bộ lớp đó. Nhưng phân tích source
cục bộ lại có ba lợi thế riêng:

- không cần upload source riêng tư;
- chỉ ra chính xác file, dòng và chuỗi hành vi đáng ngờ;
- có thể chạy sớm trong CI trước khi package được cài hoặc phát hành.

Vì vậy sản phẩm đúng nên là một lớp triage source-aware, sau này có thể kết hợp
với signature, sandbox hoặc analyst; không nên tự nhận là antivirus hoàn chỉnh.

## Khoảng trống nghiên cứu

| Công trình | Điều đã có | Phần ITCS muốn cải thiện |
|---|---|---|
| Cerebro | Behavior sequence + BERT/RoBERTa | Giảm model và chi phí biểu diễn |
| SCORE | AST/structure + mô hình nhẹ | Chuẩn hóa IR chuyên cho hành vi malware |
| MalGuard | 132 feature + RF/XGBoost mạnh | Thêm thứ tự hành vi và evidence |
| MOLOT | Call graph + BERT + SHAP | Loại full call graph/SHAP khỏi common path |
| MalTotal | Semantic slicing có LLM hỗ trợ | Pipeline local không phụ thuộc LLM lớn |
| OMCBench | Benchmark Python/JavaScript mở | Bổ sung time/campaign split và hard negatives |

Điểm cần nói thật: behavior sequence không mới. µMal nhỏ cũng chưa đủ là novelty.
Đóng góp có thể công bố nằm ở tổ hợp:

1. IR hành vi có kiểu và có vị trí bằng chứng;
2. frontend nhiều ngôn ngữ cùng biên dịch về một IR;
3. extraction bị chặn tài nguyên và không chạy code;
4. selective/conditional inference theo vùng bất định;
5. đánh giá low-FPR, temporal drift và chi phí CPU cùng lúc.

## Những gì đã triển khai

### Frontend Python an toàn

- Đọc source như bytes có giới hạn và dùng ast.parse.
- Không import, compile, pip install hoặc chạy file được quét.
- Resolve alias phổ biến, kể cả requests.Session và socket factory.
- Bỏ heuristic rộng kiểu “mọi .get là network” để giảm false positive.
- Skip symlink, virtualenv, dependency/build/VCS folder.
- Chặn số file, kích thước từng file, tổng byte và số event.
- Parse error, recursion error và event truncation đều được báo ra.
- Manifest dataset không được đọc path thoát khỏi thư mục của nó.

### MalIR v1

Mỗi event giữ operation, category, target, file, dòng, function và phase.
Operation độc lập ngôn ngữ gồm ENV_READ, SENSITIVE_FILE_READ, NETWORK_SEND,
NETWORK_RECEIVE, ENCODE, DECODE, PROCESS_EXEC, DYNAMIC_EXEC,
UNSAFE_DESERIALIZE, PERSISTENCE_WRITE và các context khác.

Motif hiện là proximity path trong cùng function, ví dụ:

- credential_or_file_exfil;
- download_execute;
- encoded_execution;
- install_time_execution;
- persistence_write;
- destructive_file_action.

Motif chưa phải data flow chính xác. Event index được giữ lại để analyst tự
kiểm chứng.

### Hai mô hình

Mô hình sparse dùng signed feature hashing trên MalIR n-gram và online logistic
regression tự viết bằng standard library. Smoke checkpoint chỉ 7.259 byte.

µMal là Transformer encoder 567.746 tham số, vocabulary hash 4.096, sequence
256, hai layer, width 96, bốn attention head. Nó học classification cùng
masked-behavior-token prediction từ đầu, không tải foundation model.

Rule score nằm ngoài 20–80 thì không gọi model. Đây là conditional compute:
chi phí trung bình bằng extraction cộng tỷ lệ ca bất định nhân chi phí µMal.

## Kết quả trên codespaces-a90760

Máy: 2 vCPU, khoảng 8 GB RAM, Python 3.12.1, Linux x86-64.

| Đo lường | Kết quả |
|---|---:|
| Quét 1.000 file tổng hợp trơ | 889,23 file/giây |
| Latency tree 1.000 file | median 1.111,24 ms; p95 1.190,57 ms |
| Python allocation peak | 2.725.883 byte qua tracemalloc |
| Sparse checkpoint | 7.259 byte |
| µMal FP32 checkpoint | 2.280.321 byte |
| µMal inference, 2 thread | median 6,49 ms; p95 12,50 ms |
| Test | 21 test pass |
| Môi trường train PyTorch | 992 MB; không cần cho core/sparse |

Corpus benchmark là template trơ với 95% mẫu thông thường và 5% source có hình
dạng đáng ngờ. Dataset train có 32 dòng tổng hợp và được dùng lại để smoke
evaluation. Vì vậy 100% training score chỉ chứng minh model học/chạy/save/load
được; tuyệt đối không phải số liệu detection thực tế.

Đã thử dynamic quantization cũ của torch.ao nhưng API bị đánh dấu deprecated và
Transformer quantized bị lỗi inference trong môi trường hiện tại. Nhánh đó
không được đưa vào sản phẩm. INT8 chỉ nên quay lại bằng torchao hoặc ONNX khi
benchmark thật sự tốt hơn FP32.

## Thiết kế thí nghiệm thật

### Dữ liệu

Bắt đầu với 400 package Python của OMCBench: 200 benign, 200 malicious. Sau đó
bổ sung benign theo thời gian, nhóm download và loại package; bổ sung hard
negative như installer, deployment, backup, networking, browser automation và
security tools.

Không tải hoặc bung malware ngay trong Codespace này. Archive thật phải được xử
lý ở worker cô lập, không credential, tắt network và có giới hạn path traversal,
symlink, nesting, compression ratio, số file và tổng byte.

### Chia tập để chống leakage

- Gom mọi version/fork của cùng package vào một split.
- Gom cùng family/campaign vào một split.
- Deduplicate hash, normalized AST và near-duplicate MalIR.
- Random split chỉ dùng debug.
- Kết quả chính phải có family-disjoint và forward time split.
- Threshold chỉ chọn trên validation, khóa trước khi chạy test.

### Baseline bắt buộc

- rule-only;
- lexical hash + logistic;
- MalIR hash + logistic;
- feature tĩnh + RF/XGBoost;
- raw-source Transformer cùng số tham số với µMal;
- µMal always-on;
- cascade rule + sparse + µMal;
- code model lớn chỉ làm upper bound offline.

Nếu µMal không thắng sparse ở recall tại cùng false-positive rate thì bỏ µMal,
không cố giữ vì tên gọi LLM.

### Metric chính

- recall tại FPR 0,1% và 1%;
- PR-AUC / average precision;
- số false alert trên 10.000 package benign;
- calibration Brier/ECE;
- median/p95/p99 latency và CPU-second trên 1.000 package;
- peak RSS, model size, tỷ lệ package đi vào uncertainty gate;
- evidence precision, deletion faithfulness và thời gian analyst review.

Accuracy/F1 đơn lẻ không đủ cho môi trường mất cân bằng.

## Điều kiện trước khi gọi là “đột phá”

- Tập test thật khóa trước, package/family/time-disjoint.
- Hàng chục nghìn benign để đo low false-positive có ý nghĩa.
- Confidence interval và paired comparison với baseline rẻ mạnh.
- Chi phí p95/RSS đo trên phân bố package thật.
- Evidence được analyst đánh giá mù và qua faithfulness test.
- Frontend JavaScript dùng lại được cùng IR/model.
- Gain chất lượng có ý nghĩa thống kê tại cùng budget CPU.

Nếu chưa đạt các cổng này, mô tả đúng là “prototype nghiên cứu CPU-first”.

## Việc nên làm tiếp theo

1. Viết worker ingest OMCBench an toàn bên ngoài Codespace.
2. Thêm bounded local value-flow và function summaries cho Python.
3. Tạo hard-negative corpus đủ lớn và forward time split.
4. Chạy baseline/ablation bằng scripts/evaluate.py.
5. Calibrate gate để đo p_uncertain thật.
6. Chỉ sau đó mới thử INT8 và frontend JavaScript.

Bản kế hoạch tiếng Anh đầy đủ, nguồn tham khảo và claim gates nằm trong
[RESEARCH.md](RESEARCH.md). Đặc tả IR nằm trong
[MALIR_SPEC.md](MALIR_SPEC.md), còn ranh giới an toàn nằm trong
[THREAT_MODEL.md](THREAT_MODEL.md).