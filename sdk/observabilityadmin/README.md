# aws-sdk-observabilityadmin

Amazon CloudWatch Obsersavability Admin to control temletry config for your AWS Organization or account. Telemetry config conﬁg to discover and understand the state of telemetry conﬁguration for your AWS resources from a central view in the CloudWatch console. Telemetry conﬁg simpliﬁes the process of auditing your telemetry collection conﬁgurations across multiple resource types across your AWS Organization or account. For more information, see [Auditing CloudWatch telemetry conﬁgurations](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/telemetry-config-cloudwatch.html) in the CloudWatch User Guide.

For information on the permissions you need to use this API, see [Identity and access management for Amazon CloudWatch](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/auth-and-access-control-cw.html) in the CloudWatch User Guide.

## Getting Started

> Examples are available for many services and operations, check out the
> [examples folder in GitHub](https://github.com/awslabs/aws-sdk-rust/tree/main/examples).

The SDK provides one crate per AWS service. You must add [Tokio](https://crates.io/crates/tokio)
as a dependency within your Rust project to execute asynchronous code. To add `aws-sdk-observabilityadmin` to
your project, add the following to your **Cargo.toml** file:

```toml
[dependencies]
aws-config = { version = "1.1.7", features = ["behavior-version-latest"] }
aws-sdk-observabilityadmin = "0.0.0-local"
tokio = { version = "1", features = ["full"] }
```

Then in code, a client can be created with the following:

```rust,no_run
use aws_sdk_observabilityadmin as observabilityadmin;

#[::tokio::main]
async fn main() -> Result<(), observabilityadmin::Error> {
    let config = aws_config::load_from_env().await;
    let client = aws_sdk_observabilityadmin::Client::new(&config);

    // ... make some calls with the client

    Ok(())
}
```

See the [client documentation](https://docs.rs/aws-sdk-observabilityadmin/latest/aws_sdk_observabilityadmin/client/struct.Client.html)
for information on what calls can be made, and the inputs and outputs for each of those calls.

## Using the SDK

Until the SDK is released, we will be adding information about using the SDK to the
[Developer Guide](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/welcome.html). Feel free to suggest
additional sections for the guide by opening an issue and describing what you are trying to do.

## Getting Help

* [GitHub discussions](https://github.com/awslabs/aws-sdk-rust/discussions) - For ideas, RFCs & general questions
* [GitHub issues](https://github.com/awslabs/aws-sdk-rust/issues/new/choose) - For bug reports & feature requests
* [Generated Docs (latest version)](https://awslabs.github.io/aws-sdk-rust/)
* [Usage examples](https://github.com/awslabs/aws-sdk-rust/tree/main/examples)

## License

This project is licensed under the Apache-2.0 License.

