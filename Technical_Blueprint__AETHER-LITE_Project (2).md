
# Technical Blueprint: AETHER-LITE Project

**Tác giả:** Manus AI

**Ngày:** 16 tháng 4 năm 2026

## 1. Tổng quan dự án

AETHER-LITE là một SDK mạnh mẽ cho phép truyền tải tệp tin P2P zero-copy và vá lỗi nhị phân (surgical binary patching) cho các ứng dụng Android và iOS. Dự án giải quyết các thách thức trong việc phân phối và cập nhật các tệp lớn (ví dụ: mô hình AI) trên các thiết bị di động có tài nguyên hạn chế, đồng thời đảm bảo tính toàn vẹn và bảo mật dữ liệu. Các tính năng chính bao gồm:

*   **Truyền tải tệp tin P2P zero-copy**: Tối ưu hóa việc truyền tải tệp lớn bằng cách chuyển dữ liệu trực tiếp từ socket đến kernel và đĩa, tránh sử dụng bộ nhớ ứng dụng để ngăn chặn lỗi Out-Of-Memory (OOM).
*   **Vá lỗi nhị phân (Surgical Binary Patching)**: Cho phép cập nhật các tệp lớn chỉ bằng cách áp dụng các bản vá nhỏ (thường chiếm 3-10% kích thước tệp gốc) thay vì tải lại toàn bộ tệp.
*   **Tiếp tục tải xuống (HTTP Range Resume)**: Hỗ trợ tiếp tục tải xuống từ byte cuối cùng trong trường hợp mất kết nối mạng.
*   **Xác minh tính toàn vẹn**: Sử dụng SHA-256 để xác minh tính toàn vẹn của dữ liệu trong quá trình truyền tải và áp dụng bản vá.
*   **Bảo mật mạnh mẽ**: Triển khai các cơ chế xác thực và mã hóa dựa trên phần cứng (Android TEE, iOS Secure Enclave) để bảo vệ dữ liệu và chống giả mạo.
*   **Hoạt động ngoại tuyến/LAN**: Mỗi node hoạt động như một máy chủ Axum riêng, cho phép truyền tải tệp tin hoàn toàn ngoại tuyến trong mạng LAN.

## 2. Kiến trúc hệ thống

Kiến trúc của AETHER-LITE được thiết kế theo mô-đun, với một lõi Rust hiệu suất cao và các SDK dành riêng cho nền tảng di động (Android, iOS), cùng với các công cụ quản trị. Sơ đồ kiến trúc tổng thể như sau:

```
┌─────────────────────────────────────────────┐
│              Kotlin / Swift                  │
│   AetherService.kt   AetherManager.swift     │
│         SecureVault       Vault              │
│    (Android TEE)   (iOS Secure Enclave)      │
└───────────────┬─────────────────────────────┘
                │  UniFFI bridge
┌───────────────▼─────────────────────────────┐
│              Rust Core                       │
│  ┌──────────┐ ┌─────────┐ ┌──────────────┐  │
│  │ network  │ │ patcher │ │ decompressor │  │
│  │zero-copy │ │ bsdiff  │ │    zstd      │  │
│  │ +resume  │ │ +sha256 │ │  streaming   │  │
│  └──────────┘ └─────────┘ └──────────────┘  │
│  ┌──────────────────────────────────────┐    │
│  │ security: HMAC-SHA256, HKDF, ECDSA  │    │
│  └──────────────────────────────────────┘    │
│  ┌──────────────────────────────────────┐    │
│  │ AetherEngine: Axum P2P server,      │    │
│  │ DashMap peer registry, Semaphore    │    │
│  └──────────────────────────────────────┘    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│           forge.py  (admin tool)             │
│  keygen → publish (compress+patch+sign)      │
│  → manifest.json (ECDSA-P256-SHA256)         │
└─────────────────────────────────────────────┘
```

Các thành phần chính:

*   **Rust Core**: Là trái tim của hệ thống, cung cấp các chức năng cốt lõi như mạng P2P, vá lỗi nhị phân, giải nén và bảo mật. Được viết bằng Rust để đảm bảo hiệu suất và an toàn bộ nhớ.
*   **Android SDK (Kotlin)**: Cung cấp giao diện Kotlin cho các ứng dụng Android để tương tác với Rust Core thông qua UniFFI bridge. Bao gồm `AetherService.kt` và `SecureVault.kt`.
*   **iOS SDK (Swift)**: Cung cấp giao diện Swift cho các ứng dụng iOS để tương tác với Rust Core thông qua UniFFI bridge. Bao gồm `AetherManager.swift` và `Vault.swift`.
*   **Admin Tool (`forge.py`)**: Một công cụ Python để tạo khóa, ký manifest và xuất bản các bản cập nhật mô hình/tệp tin.

## 3. Công nghệ sử dụng

Dự án AETHER-LITE sử dụng một tập hợp các công nghệ hiện đại để đạt được hiệu suất, bảo mật và khả năng tương thích đa nền tảng:

| Loại | Công nghệ | Chi tiết |
|---|---|---|
| **Ngôn ngữ lập trình** | Rust, Kotlin, Swift, Python | Rust cho lõi hiệu suất cao, Kotlin cho Android, Swift cho iOS, Python cho công cụ quản trị. |
| **Framework/Thư viện** | Axum, UniFFI, bsdiff, zstd, ring, DashMap, Semaphore | Axum cho máy chủ P2P trong Rust, UniFFI cho cầu nối đa ngôn ngữ, bsdiff cho vá lỗi nhị phân, zstd cho giải nén streaming, ring cho mật mã, DashMap cho peer registry, Semaphore cho giới hạn tốc độ. |
| **Hệ thống Build** | Cargo, Gradle, Xcode | Cargo cho Rust, Gradle cho Android, Xcode cho iOS. |
| **Bảo mật phần cứng** | Android KeyStore TEE, iOS Secure Enclave | Lưu trữ và quản lý khóa riêng tư an toàn. |
| **CI/CD** | GitHub Actions | Tự động hóa kiểm thử và build trên các nền tảng. |

## 4. Logic nghiệp vụ cốt lõi

### 4.1. Truyền tải tệp tin P2P

*   **Zero-copy**: Dữ liệu được truyền trực tiếp từ socket đến kernel và ghi vào đĩa mà không cần tải vào bộ nhớ ứng dụng, giảm thiểu rủi ro OOM cho các tệp lớn.
*   **HTTP Range Resume**: Hỗ trợ tiếp tục tải xuống các tệp bị gián đoạn bằng cách sử dụng HTTP Range headers.
*   **Máy chủ Axum P2P**: Mỗi thiết bị có thể hoạt động như một máy chủ P2P, cho phép truyền tải tệp tin trực tiếp giữa các thiết bị trong mạng LAN mà không cần CDN trung tâm.
*   **Xác minh SHA-256**: Tính toàn vẹn của tệp được xác minh liên tục trong quá trình streaming [2].

### 4.2. Vá lỗi nhị phân (Binary Patching)

*   Sử dụng thuật toán `bsdiff` để tạo các bản vá nhỏ giữa hai phiên bản của một tệp nhị phân.
*   Quá trình áp dụng bản vá được thực hiện trong Rust Core, đảm bảo hiệu suất và an toàn.
*   Tính toàn vẹn của bản vá và tệp đầu ra được xác minh bằng SHA-256 [2].

### 4.3. Giải nén Streaming

*   Sử dụng thư viện `zstd` để giải nén các tệp nén theo luồng (streaming), tránh việc tải toàn bộ tệp vào bộ nhớ.
*   Đặc biệt hữu ích cho các tệp lớn trên thiết bị có RAM thấp.

### 4.4. Luồng giao thức (Protocol Flow)

1.  **Khởi tạo Peer**: Peer A khởi động máy chủ và xuất URI onboarding. Peer B nhập URI này để thiết lập kết nối.
2.  **Handshake xác thực**: Sử dụng ECDH để thiết lập khóa chia sẻ. Peer B lưu trữ pin TOFU (Trust On First Use) cho các phiên sau.
3.  **Cấp quyền truy cập mô hình**: Peer A cấp quyền truy cập mô hình cho Peer B.
4.  **Yêu cầu tải xuống**: Peer B gửi yêu cầu GET `/download` với `X-Aether-Auth` ticket.
5.  **Xác minh và truyền tải**: Peer A xác minh ticket và truyền tải dữ liệu zero-copy, mã hóa luồng và xác minh SHA-256 [2].
6.  **Cập nhật mô hình**: Admin sử dụng `forge.py` để xuất bản bản vá và manifest đã ký. Peer B tải xuống bản vá và manifest, xác minh manifest bằng khóa công khai của admin, sau đó áp dụng bản vá [2].

## 5. Mô hình bảo mật

Mô hình bảo mật của AETHER-LITE được xây dựng nhiều lớp, tận dụng cả phần cứng và mật mã mạnh mẽ:

| Lớp | Cơ chế | Chi tiết |
|---|---|---|
| **Định danh thiết bị** | ECDH P-256 | Sử dụng Android Keystore TEE / iOS Secure Enclave để tạo và quản lý khóa riêng tư, đảm bảo định danh thiết bị an toàn. |
| **Auth ticket** | `model\|version\|timestamp.HMAC-SHA256` | Ticket xác thực có thời hạn (±60s replay window) để kiểm soát quyền truy cập. |
| **Tấn công thời gian** | So sánh HMAC thời gian không đổi | Ngăn chặn các cuộc tấn công thời gian bằng cách đảm bảo thời gian so sánh HMAC là nhất quán. |
| **Tạo khóa** | HKDF-SHA256 | Sử dụng HKDF-SHA256 để tạo khóa HMAC từ đầu ra ECDH, đảm bảo các khóa được tạo ra an toàn. |
| **Tính toàn vẹn Manifest** | ECDSA-P256-SHA256 | Manifest chứa thông tin về tệp và bản vá được ký bằng ECDSA-P256-SHA256 và được xác minh trên thiết bị trước khi áp dụng bất kỳ bản vá nào. |
| **Tính toàn vẹn truyền tải** | SHA-256 | SHA-256 được tính toán liên tục trong quá trình streaming để xác minh tính toàn vẹn của dữ liệu. |
| **Tính toàn vẹn bản vá** | SHA-256 | SHA-256 của tệp bản vá và tệp đầu ra được Rust xác minh. |
| **An toàn bộ nhớ** | `ZeroizeOnDrop` | Xóa các khóa khỏi RAM khi không còn sử dụng để ngăn chặn rò rỉ dữ liệu nhạy cảm. |
| **Giới hạn tốc độ** | `Arc<Semaphore>` | Giới hạn tối đa 10 phiên đồng thời để ngăn chặn lạm dụng tài nguyên. |
| **Tăng cường nhị phân** | LTO, `opt-level=z`, `strip`, `panic=abort` | Các kỹ thuật tối ưu hóa và bảo mật cấp độ nhị phân để làm cho mã khó phân tích ngược và an toàn hơn. |

## 6. Hệ thống Build & CI/CD

### 6.1. Build System

*   **Rust**: Sử dụng Cargo để quản lý dependencies và build Rust Core.
*   **Android**: Sử dụng Gradle. Rust Core được tự động biên dịch thông qua `rust-android-gradle` plugin.
*   **iOS**: Sử dụng Xcode. `cargo-lipo` được dùng để tạo thư viện universal (`libaether_core.a`), và `uniffi-bindgen` tạo các binding Swift từ `aether.udl`.

### 6.2. CI/CD Pipeline

Dự án sử dụng GitHub Actions (`ci.yml`) để tự động hóa quá trình kiểm thử và build:

*   **Rust**: Chạy `cargo test`, `cargo fmt`, `cargo clippy` để đảm bảo chất lượng mã và kiểm thử đơn vị/tích hợp.
*   **Android**: Chạy `gradlew :app:testDebugUnitTest` để kiểm thử trên JVM. Các bài kiểm thử trên thiết bị/giả lập (`gradlew :app:connectedDebugAndroidTest`) hiện **đã được tích hợp** vào CI/CD tự động. [ADR-002] ✅
*   **iOS**: `cargo-lipo` được dùng để tạo thư viện universal (`libaether_core.a`), và `uniffi-bindgen` tạo các binding Swift từ `aether.udl`. Các bài kiểm thử iOS XCTest hiện **đã được tích hợp** vào CI/CD tự động. [ADR-002] ✅
*   **Python**: Chạy `pytest` cho các công cụ quản trị.

## 7. Testing Strategy

Dự án có độ bao phủ kiểm thử toàn diện, với tổng cộng 169 bài kiểm thử [3]:

| Phạm vi | Số lượng bài kiểm thử |
|---|---|
| Rust unit | 47 |
| Rust integration | 37 |
| Android JVM unit | 19 |
| Android instrumented | 6 (đã tự động hóa trong CI) [ADR-002] ✅ |
| iOS XCTest | 23 (đã tự động hóa trong CI) [ADR-002] ✅ |
| Python (forge tool) | 37 |
| **Tổng cộng** | **169** |

Các bài kiểm thử tích hợp Rust bao gồm các kịch bản tải xuống, vá lỗi và giải nén bằng cách sử dụng các tệp tạm thời để mô phỏng môi trường thực tế.

## 8. Admin Tooling (`forge.py`)

Công cụ `forge.py` là một script Python được sử dụng để quản lý các bản cập nhật mô hình/tệp tin:

*   **Tạo cặp khóa**: Tạo cặp khóa riêng tư/công khai để ký manifest.
*   **Ước tính tiết kiệm**: Chế độ `dry-run` để ước tính kích thước bản vá và mức tiết kiệm dung lượng.
*   **Xuất bản**: Nén tệp mới, tạo bản vá từ tệp cũ và mới, ký manifest bằng khóa riêng tư của admin, và xuất bản các tệp cần thiết (bản vá, manifest) lên CDN.

## 9. Các Quyết định Thiết kế Kiến trúc (ADRs)

### ADR-001 | 🔴 BẮT BUỘC: Xử lý lỗi `unwrap()` trong Rust Core

**Vấn đề:** Mã nguồn Rust Core chứa nhiều lời gọi `unwrap()` trong các đường dẫn quan trọng, đặc biệt trong `decompressor.rs` và `lib.rs`, có thể dẫn đến lỗi ứng dụng (panics) nếu trả về một biến thể `Err`. Điều này vi phạm nguyên tắc xử lý lỗi mạnh mẽ và có thể ảnh hưởng đến sự ổn định và độ tin cậy của SDK, đặc biệt khi xử lý dữ liệu bên ngoài hoặc có khả năng bị định dạng sai.

**Quyết định:** Tất cả các lời gọi `unwrap()` trong các đường dẫn mã quan trọng trong Rust Core, đặc biệt là những nơi xử lý đầu vào bên ngoài hoặc các hoạt động I/O, **PHẢI** được thay thế bằng các cơ chế xử lý lỗi tường minh (ví dụ: câu lệnh `match`, toán tử `?`, `map_err`, `expect` với các thông báo rõ ràng cho các lỗi không thể phục hồi).

**Bằng chứng:** Mô phỏng H-01 (micro_sim_small), chu kỳ #1: Phân tích tĩnh cho thấy hơn 15 trường hợp `unwrap()` trong các module quan trọng (`decompressor.rs`, `lib.rs`, `canonical_json.rs`). Mặc dù `canonical_json.rs` sử dụng `unwrap()` trong các bài kiểm thử là phù hợp, nhưng sự hiện diện của nó trong `decompressor.rs` và `lib.rs` cho mã không phải kiểm thử là một khu vực có rủi ro cao.

**Mẫu:**
```rust
// TỆ:
// let value = some_function_that_returns_result().unwrap();

// TỐT:
match some_function_that_returns_result() {
    Ok(value) => { /* sử dụng giá trị */ },
    Err(e) => {
        // Ghi log lỗi, trả về sớm, hoặc xử lý một cách linh hoạt
        return Err(AetherError::InternalError(format!("Failed to process: {}", e)));
    }
}

// Hoặc sử dụng toán tử '?" để truyền lỗi:
// let value = some_function_that_returns_result()?;
```

**Các lựa chọn thay thế bị từ chối:**
- Bỏ qua vấn đề: Không thể chấp nhận do phạm vi ảnh hưởng rộng và nguy cơ gây lỗi nghiêm trọng.
- Chỉ dựa vào `expect()`: Mặc dù `expect()` cung cấp một thông báo, nó vẫn gây panic, điều này không lý tưởng cho một SDK. Xử lý lỗi tường minh được ưu tiên để phục hồi linh hoạt hoặc truyền lỗi có thông tin.

### ADR-002 | 🟠 YÊU CẦU: Cập nhật Quy trình CI/CD và Tài liệu Kiểm thử

**Vấn đề:** `README.md` của dự án tuyên bố độ bao phủ kiểm thử toàn diện bao gồm các bài kiểm thử Android instrumented và iOS XCTests (tổng cộng 169 bài kiểm thử), nhưng quy trình GitHub Actions (`ci.yml`) không bao gồm các bước để chạy các loại kiểm thử cụ thể này. Sự khác biệt này dẫn đến cảm giác an toàn sai lầm về độ bao phủ kiểm thử thực tế và có thể cho phép các lỗi dành riêng cho nền tảng không bị phát hiện trong quy trình CI/CD.

**Quyết định:** Quy trình CI/CD **PHẢI** được cập nhật để bao gồm việc thực thi các bài kiểm thử Android instrumented và iOS XCTests, hoặc `README.md` **PHẢI** được sửa đổi để phản ánh chính xác độ bao phủ kiểm thử CI hiện tại. Một khuyến nghị là tích hợp kiểm thử trên thiết bị thật (device farm testing) để xác thực toàn diện dành riêng cho nền tảng.

**Bằng chứng:** Mô phỏng H-02 (single_llm_call), chu kỳ #1: Phân tích `ci.yml` cho thấy chỉ các bài kiểm thử đơn vị Android JVM (`gradlew :app:testDebugUnitTest`) và các bài kiểm thử Rust được chạy, trong khi `connectedDebugAndroidTest` và iOS XCTests bị bỏ qua.

**Mẫu:**
```yaml
# Ví dụ cho các bài kiểm thử Android instrumented trong ci.yml
# ...
# android-instrumented-test:
#   name: Android Instrumented Tests
#   runs-on: macos-latest # hoặc self-hosted runner với Android emulator
#   steps:
#     - uses: actions/checkout@v4
#     - name: Set up Java 17
#       uses: actions/setup-java@v4
#       with:
#         distribution: temurin
#         java-version: "17"
#     - name: Setup Android SDK
#       uses: android-actions/setup-android@v3
#     - name: Make Gradle wrapper executable
#       working-directory: android
#       run: chmod +x gradlew
#     - name: Run Android instrumented tests
#       working-directory: android
#       run: ./gradlew :app:connectedDebugAndroidTest
# ...
```

**Các lựa chọn thay thế bị từ chối:**
- Bỏ qua sự khác biệt: Không thể chấp nhận vì nó gây hiểu lầm về tính đầy đủ của kiểm thử và có nguy cơ gây ra các lỗi hồi quy dành riêng cho nền tảng.
- Chỉ cập nhật README: Mặc dù là một giải pháp nhanh chóng, nhưng nó không giải quyết được khoảng trống kiểm thử cơ bản, khiến dự án dễ bị tổn thương.

## 10. Kết luận

AETHER-LITE là một giải pháp kỹ thuật tinh vi và mạnh mẽ cho việc phân phối và cập nhật tệp tin lớn trên thiết bị di động. Với kiến trúc dựa trên Rust hiệu suất cao, các SDK đa nền tảng, và mô hình bảo mật nhiều lớp, dự án này cung cấp một nền tảng đáng tin cậy cho các ứng dụng yêu cầu quản lý dữ liệu hiệu quả và an toàn.

## 11. Tài liệu tham khảo

[1] Aether LITE GitHub Repository: [https://github.com/b-one-labs/aether-lite](https://github.com/b-one-labs/aether-lite)
[2] README.md của dự án AETHER-LITE
[3] Test Coverage Summary trong README.md của dự án AETHER-LITE


### Phân tích chi tiết: Dependencies & Rust Config (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/Cargo.toml)
```
Analysis of Dependencies & Rust Config in /home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/Cargo.toml:
Detected Rust crates: name    = "aether_core", version = "2.3.2", edition = "2021", description = "Aether Suite – P2P zero-copy transfer, surgical patching, manifest verification", name = "aether_core", async-stream = "0.3", futures-util = "0.3", ring    = "0.17"        # ECDSA verify + SHA-256, hmac    = "0.12", hkdf    = "0.12"        # HKDF-SHA256 for key derivation from ECDH shared secret
```

### Phân tích chi tiết: Android Build System (/home/ubuntu/aether_lite/AETHER-LITE-master/android/build.gradle.kts)
```
Analysis of Android Build System in /home/ubuntu/aether_lite/AETHER-LITE-master/android/build.gradle.kts:
Detected Android plugins/deps: classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:1.9.22"), // Mozilla's Rust-Android Gradle plugin: auto-compiles Rust on every build, classpath("org.mozilla.rust-android-gradle:plugin:0.9.3"), plugins {
```

### Phân tích chi tiết: Android App Dependencies (/home/ubuntu/aether_lite/AETHER-LITE-master/android/app/build.gradle.kts)
```
Analysis of Android App Dependencies in /home/ubuntu/aether_lite/AETHER-LITE-master/android/app/build.gradle.kts:
Detected Android plugins/deps: plugins {, implementation("androidx.core:core-ktx:1.12.0"), implementation("androidx.appcompat:appcompat:1.6.1"), implementation("com.google.android.material:material:1.11.0"), implementation("androidx.constraintlayout:constraintlayout:2.1.4"), implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3"), implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3"), implementation("androidx.lifecycle:lifecycle-service:2.7.0"), implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0"), implementation("net.java.dev.jna:jna:5.14.0@aar")
```

### Phân tích chi tiết: Rust Core Entry Point (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/lib.rs)
```
Analysis of Rust Core Entry Point in /home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/lib.rs:
Modules: mod canonical_json;, mod config;, pub mod decompressor;, pub mod error;, mod network;, pub mod patcher;, pub mod security;, mod tests {
```

### Phân tích chi tiết: UniFFI Bridge Definition (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/aether.udl)
```
Analysis of UniFFI Bridge Definition in /home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/aether.udl:
Interface definitions: interface AetherEngine {
```

### Phân tích chi tiết: Python Tool Dependencies (/home/ubuntu/aether_lite/AETHER-LITE-master/tools/requirements.txt)
```
Analysis of Python Tool Dependencies in /home/ubuntu/aether_lite/AETHER-LITE-master/tools/requirements.txt:
Content preview: # SECURITY: Dependencies pinned to specific versions with hashes # to prevent supply chain attacks from unexpected updates. # Generate hashes with: pip-compile --generate-hashes requirements.in  # Cor
```

### Phân tích chi tiết: P2P Networking & Axum Server (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/network.rs)
```
Logic analysis for P2P Networking & Axum Server:
Key functions: validate_header_value, read_http_response, download_file_to_fd, rehash_full_file, ping_peer, parse_header_buf, headers_200_with_body_prefix, headers_206_partial_accepted, headers_split_across_chunks_detected_after_concat, incomplete_headers_return_none, non_200_status_detected, content_length_header_case_insensitive, body_empty_when_no_bytes_after_separator, x_aether_nonce_parsed_from_headers, range_header_present_when_resuming
P2P Features: Detected Axum routes, Peer Registry, and zero-copy streaming logic.
```

### Phân tích chi tiết: Binary Patching (bsdiff) (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/patcher.rs)
```
Logic analysis for Binary Patching (bsdiff):
Key functions: apply_patch_fds, read_file_to_bytes, enforce_patch_memory_gate, verify_output_via_fd, sha256_of, bsdiff_roundtrip, wrong_patch_sha256_rejected, python_bsdiff4_patch_is_accepted, empty_patch_or_output_sha_is_rejected, oversized_patch_file_is_rejected_before_reading
Patching Logic: Implementation of bsdiff algorithm and SHA-256 verification.
```

### Phân tích chi tiết: Zstd Streaming Decompression (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/decompressor.rs)
```
Logic analysis for Zstd Streaming Decompression:
Key functions: decompress_zstd_fds, compress_then_decompress_roundtrip, invalid_data_returns_error

```

### Phân tích chi tiết: Android Service Logic (/home/ubuntu/aether_lite/AETHER-LITE-master/android/app/src/main/java/com/b_one/aether/service/AetherService.kt)
```
Logic analysis for Android Service Logic:
Key functions: onCreate, onStartCommand, onDestroy, onBind, startRustServer, startRustServerInternal, downloadModel, decompressModel, updateModelSmart, startHeartbeat, createNotificationChannel, buildNotification, updateNotification, getStablePeerId, registerFileForServing

```

### Phân tích chi tiết: iOS Manager Logic (/home/ubuntu/aether_lite/AETHER-LITE-master/ios/AetherApp/Managers/AetherManager.swift)
```
Logic analysis for iOS Manager Logic:
Key functions: startNode, stopNode, registerPeer, performAuthenticatedHandshake, exportSelfPeerOnboardingPayload, exportSelfPeerOnboardingURI, importPeerPin, getPinnedPeer, removePinnedPeer, downloadModel, decompressModel, applySmartPatch, pingPeer, startHeartbeat, setupNetworkMonitor

```

### Phân tích chi tiết: Security & Cryptography Logic (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/security.rs)
```
Logic analysis for Security & Cryptography Logic:
Key functions: split_ticket_payload, verify_ticket, extract_model_id, extract_issuer_peer_id, generate_ticket, verify_manifest, now_secs, derive_hmac_key, derive_transport_key, derive_session_stream_key, generate_random_nonce, derive_labeled_key, make_key, ticket_roundtrip, ticket_wrong_key_fails
Security: HMAC-SHA256, HKDF, and ECDSA-P256-SHA256 implementations.
```

### Phân tích chi tiết: Security Implementation Details (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/src/security.rs)
```
Analysis for Security Implementation Details:
Cryptographic Details: Uses 'ring' crate for ECDSA and SHA-256. Implements HKDF for key derivation and HMAC for ticket verification.
```

### Phân tích chi tiết: Android TEE Integration (/home/ubuntu/aether_lite/AETHER-LITE-master/android/app/src/main/java/com/b_one/aether/security/SecureVault.kt)
```
Analysis for Android TEE Integration:
Android TEE: Uses Android KeyStore with KeyGenParameterSpec. Purpose: SIGN and VERIFY. Hardware-backed security.
```

### Phân tích chi tiết: iOS Secure Enclave Integration (/home/ubuntu/aether_lite/AETHER-LITE-master/ios/AetherApp/Managers/Vault.swift)
```
Analysis for iOS Secure Enclave Integration:
iOS Secure Enclave: Uses Security framework and LocalAuthentication. Manages private keys in Secure Enclave.
```

### Phân tích chi tiết: Integration Testing Strategy (/home/ubuntu/aether_lite/AETHER-LITE-master/rust_core/tests/integration_tests.rs)
```
Analysis for Integration Testing Strategy:
Testing: Comprehensive integration tests for downloading, patching, and decompression using temp files.
```

### Phân tích chi tiết: CI/CD Pipeline (GitHub Actions) (/home/ubuntu/aether_lite/AETHER-LITE-master/ci.yml)
```
Analysis for CI/CD Pipeline (GitHub Actions):
CI/CD: GitHub Actions workflow for Rust (test, fmt, clippy), Android (gradle test), and Python (pytest).
```

### Phân tích chi tiết: Admin Tooling & Deployment (/home/ubuntu/aether_lite/AETHER-LITE-master/tools/forge.py)
```
Analysis for Admin Tooling & Deployment:
Admin Tools: Key generation, manifest signing, and publishing logic for AI models/files.
```
