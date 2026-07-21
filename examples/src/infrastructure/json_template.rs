//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JSON 模板与序列化示例：演示 GarrisonJsonTemplate 占位符渲染 + GarrisonSerializer 类型化序列化。
//!
//! 对应模块：`src/json/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin json_template --features full
//! ```

use garrison::error::GarrisonResult;
use garrison::json::{GarrisonJsonTemplate, GarrisonSerializer, GarrisonSerializerDefault};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 测试用的业务数据结构。
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct LoginResponse {
    code: i32,
    msg: String,
    data: UserInfo,
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    user_id: i64,
    user_name: String,
}

/// 运行 JSON 模板与序列化示例。
///
/// 演示 GarrisonJsonTemplate 占位符渲染与 GarrisonSerializerDefault 类型化序列化往返。
pub fn run() -> GarrisonResult<()> {
    println!("=== Garrison JSON 模板与序列化示例 ===\n");

    // ----------------------------------------------------------------
    // 1. GarrisonJsonTemplate：解析含占位符的 JSON 模板
    // ----------------------------------------------------------------
    let template_str = r#"{"code":0,"msg":"${msg}","data":{"token":"${token}","user":"${user}"}}"#;
    let template = GarrisonJsonTemplate::new(template_str)?;
    println!("[1] 模板解析成功");
    println!("    原始 value = {}", template.value());

    // 准备占位符参数
    let mut params = HashMap::new();
    params.insert("msg".to_string(), "ok".to_string());
    params.insert("token".to_string(), "T1-abc-123".to_string());
    params.insert("user".to_string(), "alice".to_string());

    // render 递归替换嵌套对象中的占位符
    let rendered = template.render(&params)?;
    println!("    渲染结果   = {}\n", rendered);

    // 验证渲染后可被 serde_json 再次解析
    let reparsed: serde_json::Value =
        serde_json::from_str(&rendered).expect("渲染结果应为合法 JSON");
    assert_eq!(reparsed["data"]["token"], "T1-abc-123");
    assert_eq!(reparsed["data"]["user"], "alice");
    println!("    ✓ 渲染结果通过 serde_json 二次解析校验\n");

    // ----------------------------------------------------------------
    // 2. 未提供的占位符保留原样
    // ----------------------------------------------------------------
    let template2 = GarrisonJsonTemplate::new(r#"{"msg":"${missing}"}"#)?;
    let empty_params = HashMap::new();
    let rendered2 = template2.render(&empty_params)?;
    println!("[2] 未提供的占位符保留原样:");
    println!("    渲染结果 = {}\n", rendered2);
    assert!(rendered2.contains("${missing}"));

    // ----------------------------------------------------------------
    // 3. GarrisonSerializerDefault：类型化序列化/反序列化往返
    // ----------------------------------------------------------------
    let serializer = GarrisonSerializerDefault;
    let data = LoginResponse {
        code: 0,
        msg: "登录成功".to_string(),
        data: UserInfo {
            user_id: 1001,
            user_name: "alice".to_string(),
        },
    };

    let json = serializer.serialize(&data)?;
    println!("[3] GarrisonSerializerDefault::serialize:");
    println!("    JSON = {}", json);

    let deserialized: LoginResponse = serializer.deserialize(&json)?;
    println!("    deserialize 往返 = {:?}", deserialized);
    assert_eq!(deserialized, data);
    println!("    ✓ 序列化/反序列化往返一致\n");

    println!("=== 示例执行完成 ===");
    Ok(())
}
