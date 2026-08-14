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
cặp source/sink có thể tạo path. Thiết kế không dựng call graph toàn chương
trình. Bản cập nhật 2026-08-14 chỉ đi qua bare call tới một định nghĩa
top-level duy nhất, không bị rebind và không bị lexical binding che khuất, với
depth mặc định 3 và tối đa 64 lần mở rộng mỗi file. Alias callable, định nghĩa
trùng, module rebind và star import mơ hồ đều bị từ chối thay vì đoán. Async
callee chỉ mở rộng dưới `await` trực tiếp; lúc tạo generator không bị coi là đã
chạy thân generator. Cách này dựa trên ý tưởng function summary và call/return
hợp lệ, nhưng không phải global data flow hay IFDS đầy đủ.

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

Behavior path có bốn loại bằng chứng:

- `dataflow:high`: pass nội hàm đã mang provenance của value từ source được
  hỗ trợ tới payload/command của sink;
- `summary:medium`: provenance đi qua bare call đủ điều kiện tới một định
  nghĩa top-level duy nhất, không rebind/lexical-shadow; argument được bind vào
  frame callee riêng và return được hợp nhất;
- `proximity:low`: source/transform chỉ xuất hiện gần sink trong cùng function,
  chưa chứng minh value flow và chỉ nhận trọng số nhỏ;
- `structural:high`: chính event đã đủ tạo motif, không cần value flow.

`high/medium/low` là mức bằng chứng định tính, không phải xác suất hay malware
likelihood. Pass local flow theo assignment, biểu thức/container, transform,
comprehension, loop và branch join bảo thủ. Nó bị chặn ở 16 trace mỗi value,
16 event thật mỗi trace, 256 path, depth lời gọi 3 và 64 lần mở rộng mỗi
file; event gate bỏ qua toàn bộ pass khi không có cặp source/sink phù hợp.
Legacy scorer mặc định bỏ các điểm event source/sink đã được summary bao phủ,
nên path mới không tự cộng trùng với chính nó. Có thể giữ local flow nhưng tắt
summary bằng `--no-call-summaries`.

Motif gồm credential/file exfiltration, fingerprint transfer, file-to-network,
download-execute, encoded execution, install-time execution, persistence và
destructive file action. Mỗi path giữ event index để analyst kiểm chứng.

Giới hạn quan trọng: đây chưa phải interprocedural/whole-program flow tổng
quát. Summary chỉ hỗ trợ bare call tới function top-level duy nhất, không bị
rebind trong cùng module. Callable alias, định nghĩa trùng, generator và async
không có `await` trực tiếp đều không được đoán. Imported/nested function,
method, global/closure, object attribute, mutation, decorator, exception và
dynamic dispatch chưa được theo dõi chính xác. Chi tiết thiết kế và
counterexample nằm ở
[BOUNDED_CALL_SUMMARIES.md](BOUNDED_CALL_SUMMARIES.md).

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
| Local-only trên mix 95/5 direct-call | median 1.287,35 ms; p95 1.472,37 ms; 770,33 file/s |
| Bật summary trên cùng mix | median 1.298,90 ms; p95 1.468,30 ms; 750,89 file/s |
| Overhead riêng của summary | mean +2,59%; median +0,90%; p95 -0,28%; allocation +5,27% |
| Sparse checkpoint | 7.259 byte |
| µMal FP32 checkpoint | 2.280.321 byte |
| µMal inference, 2 thread | median 6,49 ms; p95 12,50 ms |
| Test | 165 Python + 14 browser test pass |
| Môi trường train PyTorch | 992 MB; không cần cho core/sparse |

Các hàng dataflow đầu tiên được đo ngày 2026-08-12. Ba hàng direct-call được
đo ngày 2026-08-14 trên 1.000 file sinh trơ, trong đó 5% có source và sink tách
qua function trực tiếp; hai mode đều bật local flow và chạy tuần tự 21 lượt dưới
`tracemalloc`. Lượt 21-repeat ngay trước đó đo mean +3,33%, median +3,30%,
p95 +1,13% và allocation +5,28%. Độ dao động và p95 âm ở lượt mới phản ánh
nhiễu host, không phải claim tăng tốc. Đây là số chi phí kỹ thuật, không phải
bằng chứng summary tăng độ chính xác; vẫn cần chạy interleave và đo process RSS.
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

## Pilot thật trên OMCBench Python

Ngày 2026-08-12, ITCS đã chạy đủ 400 archive Python của OMCBench được khóa theo
commit và manifest hash: 200 benign, 200 malicious. Payload ở ngoài git và chỉ
được đọc trong Docker worker thứ hai: tắt network, root/corpus read-only, không
credential, non-root, bỏ toàn bộ capability, giới hạn 2 CPU, 3 GiB RAM, 64 PID,
số member, byte và compression ratio. Runner không extract ra đĩa, không pip
install, import, compile hay chạy code trong package.

Sau khi hash source-set và AST đã ẩn identifier/literal, 400 package chỉ còn 338
nhóm phân tích tạm thời. Có 78 package thuộc 16 nhóm biến thể; nhóm lớn nhất có 21
package. Tất cả package trong cùng nhóm được giữ chung một split và bootstrap
2.000 lượt theo nhóm, không theo từng row.

Kết quả chính tại target FPR 1% là âm: cả proximity-only và local-flow đều phải
chọn threshold lớn hơn 1 trên validation, nên test phát hiện 0/100 malicious và
có 0/100 false positive. Với chỉ 100 nhóm benign, cận trên FPR 97,5% vẫn là
3,62%; chưa đủ lực chứng minh target 1%.

Local flow vẫn cải thiện xếp hạng exploratory:

| Metric test | Proximity | Local flow | Delta, CI 95% theo nhóm |
|---|---:|---:|---:|
| Average precision | 0,5837 | 0,5954 | +0,0117 [+0,0021; +0,0240] |
| Decision-margin AURC | 0,3775 | 0,3737 | -0,0038 [-0,0082; -0,0006] |

Ở threshold post-hoc 0,50, local flow thêm 4 true positive và không thêm false
positive, nhưng FPR vẫn 44% và paired group test không có ý nghĩa (`p=0,125`).
Một hard negative quan trọng là database client hợp lệ có flow thật
`FILE_READ -> NETWORK_SEND`: dataflow chứng minh dữ liệu di chuyển, không chứng
minh ý đồ xấu.

Kết luận: giữ local flow làm lớp bằng chứng, nhưng phải thay cách cộng điểm toàn
package bằng aggregation theo file/function, chuẩn hóa size và context benign
trước khi tăng kích thước LLM. Xem
[báo cáo đầy đủ](OMCBENCH_PILOT_2026-08-12.md) và
[metadata không chứa payload](../research/results/omcbench-python-2026-08-12/).

## Thiết kế thí nghiệm thật

### Dữ liệu

Bắt đầu với 400 package Python của OMCBench: 200 benign, 200 malicious. Sau đó
bổ sung benign theo thời gian, nhóm download và loại package; bổ sung hard
negative như installer, deployment, backup, networking, browser automation và
security tools.

Repo không chứa malware. Pilot đã tải corpus vào vùng quarantine ngoài git và
đọc archive bằng worker con cô lập, không credential, tắt network và có giới hạn
path traversal, symlink, compression ratio, số file và tổng byte. Mọi lượt sau
phải giữ cùng ranh giới này; không được install hoặc chạy sample.

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

`context-causal-v6` cùng staged-file provenance hiện đã vượt gate development
với threshold `>38` và 15/53 nhóm malicious OMCBench validation được phát hiện.
Trên 451 artifact PyPI development, extension này không làm thay đổi score của
artifact nào; PyPI holdout vẫn chưa được mở. Báo cáo chi tiết nằm ở
[CONTEXT_CAUSAL_V6_DEVELOPMENT_2026-08-13.md](CONTEXT_CAUSAL_V6_DEVELOPMENT_2026-08-13.md).

1. Đóng băng V6 thành một commit sạch và study lock bất biến; chỉ sau đó mới
   chạy PyPI holdout đúng một lần. Không chỉnh threshold sau khi thấy holdout.
2. Nếu holdout thất bại, công bố negative result và dùng corpus xác nhận mới cho
   V7; không tái dùng holdout đã lộ để tune.
3. Đánh giá `inline remote shell execution` ở event-level (ví dụ direct
   `Invoke-WebRequest` + `Invoke-Expression`) trước khi thêm motif; không flag
   text nằm trong test/assert/Dockerfile template.
4. So sánh summary-enabled với local-only trên cùng artifact đã khóa; đo delta
   false positive/false negative trước khi đổi trọng số policy. Benchmark tổng
   hợp mới nhất cho median +0,90% (lượt trước +3,30%), nhưng vẫn cần
   interleave và process RSS.
5. Đánh giá recall bị mất do các guard lexical mới. Pass hiện chặn parameter
   và assignment shadowing, duplicate/module rebinding, callable alias mơ hồ,
   generator creation và async không `await`; chỉ mở lại từng trường hợp khi có
   resolver và counterexample đủ chặt.
6. Nghiên cứu activation/import reachability có giới hạn để phân biệt code thư
   viện dormant với hành vi chạy khi import/install mà không dựng full call graph.
7. So V6 với sparse MalIR trên split mới và đo AURC/calibration/CPU sau khi gate
   reference-benign được xác nhận.
8. Chỉ sau các gate trên mới mở rộng frontend JavaScript hoặc tối ưu model/INT8.

Bản kế hoạch tiếng Anh đầy đủ, nguồn tham khảo và claim gates nằm trong
[RESEARCH.md](RESEARCH.md). Contract manifest/prediction nằm trong
[RESEARCH_DATA_FORMAT.md](RESEARCH_DATA_FORMAT.md), đặc tả IR nằm trong
[MALIR_SPEC.md](MALIR_SPEC.md), còn ranh giới an toàn nằm trong
[THREAT_MODEL.md](THREAT_MODEL.md).
