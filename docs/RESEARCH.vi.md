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
| Donapi | Tín hiệu đơn/API set thiếu thứ tự gây nhiều false positive | Đo behavior combination, thứ tự và hard negative |
| MOLOT | Call graph + BERT + SHAP; bỏ data flow vì xử lý quá chậm | Loại full call graph/SHAP khỏi common path |
| CodeQL local data flow | Local flow rẻ và chính xác hơn global flow cho nhiều query | Bắt đầu bằng provenance nội hàm có giới hạn |
| MalTotal | Semantic slicing có LLM hỗ trợ | Pipeline local không phụ thuộc LLM lớn |
| PyGuard | Mining behavior từ false positive/negative + LLM abstraction | Hard negative và ranh giới ngữ cảnh, nhưng novelty này đã có |
| PYPILINE | AST/API graph + knowledge base + agent/RAG | Học API context, nhưng không hợp mục tiêu offline 2 CPU |
| Leakage study | Temporal split vẫn có thể trùng representation | Audit cả representation sau khi sinh MalIR |
| Aurora | Risk-coverage/AURC và độ ổn định khi drift | Không dùng ECE để biện minh cho uncertainty gate |
| OMCBench | 200 benign + 200 malicious cho mỗi ecosystem | Chỉ đủ pilot, không đủ chứng minh FPR 0,1% |

Điểm cần nói thật: behavior sequence không mới. µMal nhỏ cũng chưa đủ là novelty.
Đóng góp có thể công bố nằm ở tổ hợp:

1. IR hành vi có kiểu và có vị trí bằng chứng;
2. frontend nhiều ngôn ngữ cùng biên dịch về một IR;
3. extraction bị chặn tài nguyên và không chạy code;
4. selective/conditional inference theo vùng bất định;
5. đánh giá low-FPR, temporal drift và chi phí CPU cùng lúc.

### Phát hiện mới làm thay đổi thiết kế thí nghiệm

- Time split chỉ ngăn “nhìn tương lai”, không ngăn hai artifact khác nhau bị
  phép biến đổi mất thông tin nén thành cùng feature/MalIR. Vì vậy manifest phải
  khóa SHA-256 của artifact và `representation_hash` của đúng chuỗi token mà
  model thấy, rồi audit cả hai sau khi gán split.
- Calibration và khả năng xếp hạng độ không chắc là hai câu hỏi khác nhau. Một
  model cho mọi mẫu score 0,5 có thể có ECE bằng 0 trên tập cân bằng nhưng không
  biết ca nào nên chuyển analyst. ITCS vì vậy đo cả Brier/ECE và
  risk-coverage/AURC, đồng thời giữ nguyên toàn bộ nhóm score bằng nhau.
- “0 false positive” không có nghĩa FPR thật bằng 0. Với n nhóm benign độc lập
  và không có lỗi, cận trên một phía 95% là `1 - 0,05 ** (1/n)`. Muốn cận này
  không quá 0,1% cần ít nhất 2.995 nhóm benign. OMCBench Python chỉ có 200
  benign nên chỉ làm pilot; nó không đủ lực thống kê cho claim low-FPR.

Repo hiện có `itcs audit-manifest`, `itcs evaluate-predictions` và
`itcs compare-predictions` để biến các điều trên thành kiểm tra tự động, không
đụng vào nội dung malware.

Một kết luận kỹ thuật khác đến từ đối chiếu CodeQL, MOLOT và PyGuard: local
value flow đủ rẻ và chính xác hơn proximity/global flow cho nhiều bài toán,
trong khi full call graph, data flow toàn cục và SHAP không hợp common path 2
CPU. Vì vậy từ bản 0.4, pass provenance thứ hai chỉ chạy khi event gate tìm thấy
cặp source/sink có thể tạo path. Thiết kế này không dựng call graph và không
đi qua ranh giới function.

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

Behavior path có ba loại bằng chứng:

- `dataflow:high`: pass nội hàm đã mang provenance của value từ source được
  hỗ trợ tới payload/command của sink;
- `proximity:low`: source/transform chỉ xuất hiện gần sink trong cùng function,
  chưa chứng minh value flow và chỉ nhận trọng số nhỏ;
- `structural:high`: chính event đã đủ tạo motif, không cần value flow.

`high/low` là mức bằng chứng định tính, không phải xác suất hay malware
likelihood. Pass local flow theo assignment, biểu thức/container, transform,
comprehension, loop và branch join bảo thủ. Nó bị chặn ở 16 trace mỗi value,
16 event mỗi trace và 256 path; event gate bỏ qua toàn bộ pass khi không có
cặp source/sink phù hợp.

Motif gồm credential/file exfiltration, fingerprint transfer, file-to-network,
download-execute, encoded execution, install-time execution, persistence và
destructive file action. Mỗi path giữ event index để analyst kiểm chứng.

Giới hạn quan trọng: đây chưa phải interprocedural/whole-program flow. Function
return, global, object attribute, mutation và dynamic dispatch chưa được theo
dõi chính xác.

### Hai mô hình

Mô hình sparse dùng signed feature hashing trên MalIR n-gram và online logistic
regression tự viết bằng standard library. Smoke checkpoint chỉ 7.259 byte.

µMal là Transformer encoder 567.746 tham số, vocabulary hash 4.096, sequence
256, hai layer, width 96, bốn attention head. Nó học classification cùng
masked-behavior-token prediction từ đầu, không tải foundation model.

Rule score nằm ngoài 20–80 thì không gọi model. Đây là conditional compute:
chi phí trung bình bằng extraction cộng tỷ lệ ca bất định nhân chi phí µMal.

### Lớp audit và evaluation mới

Manifest JSONL chỉ chứa metadata, bị giới hạn kích thước, từ chối payload/path
mẫu và không mở archive. Audit bắt duplicate ID/SHA, conflicting label,
group/family/campaign qua split, temporal overlap và representation leakage; nó
cũng sinh fingerprint canonical cho experiment record.

Prediction evaluator bắt buộc có validation/test. Threshold tại target FPR chỉ
được chọn trên validation rồi khóa khi áp dụng test. Báo cáo gồm raw confusion
count, AP, Brier, ECE, AURC, risk tại nhiều coverage, group bootstrap, metric
theo thời gian, tỷ lệ gọi µMal và cận tin cậy FPR.

Comparator v0.5 bắt buộc hai file có cùng sample và metadata bất biến. Mỗi hệ
thống tự chọn threshold trên validation ở cùng target FPR, sau đó cả hai được
khóa trên test và bootstrap theo cùng `group_id`. Báo cáo chỉ mở claim gate khi
CI của recall tăng, FPR không tăng và cả hai tập benign đủ lực thống kê. Cổng
chung 95% dùng bound 97,5% cho từng hệ thống theo Bonferroni hai phía so sánh.

~~~bash
itcs audit-manifest examples/research_manifest.jsonl --strict --json
itcs evaluate-predictions examples/research_predictions.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
itcs compare-predictions examples/research_predictions.jsonl \
  examples/research_predictions_candidate.jsonl \
  --target-fpr 0.001 --bootstrap 2000 --seed 0 --json
~~~

Các file ví dụ đều tổng hợp; không phải kết quả detection.

## Kết quả trên codespaces-a90760

Máy: 2 vCPU, khoảng 8 GB RAM, Python 3.12.1, Linux x86-64.

| Đo lường | Kết quả |
|---|---:|
| Candidate gate, tắt local flow | median 1.159,24 ms; p95 1.272,15 ms; 854,23 file/s |
| Candidate gate, bật local flow | median 1.193,69 ms; p95 1.331,91 ms; 823,67 file/s |
| Overhead local flow trên corpus 95/5 | median +2,97%; mean +3,71%; p95 +4,70% |
| Python allocation peak | 2.782.985 byte; +0,82% so với tắt flow |
| Sparse checkpoint | 7.259 byte |
| µMal FP32 checkpoint | 2.280.321 byte |
| µMal inference, 2 thread | median 6,49 ms; p95 12,50 ms |
| Test | 70 Python + 6 browser test pass |
| Môi trường train PyTorch | 992 MB; không cần cho core/sparse |

Mỗi mode được warm-up rồi đo 21 lượt với tracemalloc. Một probe bảy lượt trước
khi có candidate gate từng cho median overhead khoảng 20%; kết quả đó dẫn tới
tối ưu chỉ chạy pass hai trên file có candidate. Corpus benchmark là template
trơ với 95% mẫu thông thường và 5% source có hình dạng đáng ngờ. Dataset train
có 32 dòng tổng hợp và được dùng lại để smoke
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
- calibration Brier/ECE và confidence ranking bằng risk-coverage/AURC;
- cận trên một phía cho FPR và cảnh báo thiếu lực thống kê;
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
2. Dùng OMCBench làm pilot cho ablation proximity-only so với local flow.
3. Thêm bounded function summaries nhưng không dựng whole-program call graph.
4. Tạo hard-negative corpus đủ lực cho FPR, audit manifest và khóa prediction.
5. Calibrate gate trên validation; đo AURC và reject-rate drift thật.
6. Chỉ sau đó mới thử INT8 và frontend JavaScript.

Bản kế hoạch tiếng Anh đầy đủ, nguồn tham khảo và claim gates nằm trong
[RESEARCH.md](RESEARCH.md). Contract manifest/prediction nằm trong
[RESEARCH_DATA_FORMAT.md](RESEARCH_DATA_FORMAT.md), đặc tả IR nằm trong
[MALIR_SPEC.md](MALIR_SPEC.md), còn ranh giới an toàn nằm trong
[THREAT_MODEL.md](THREAT_MODEL.md).
