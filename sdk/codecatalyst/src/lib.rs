#![allow(deprecated)]
#![allow(unknown_lints)]
#![allow(clippy::module_inception)]
#![allow(clippy::upper_case_acronyms)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::wrong_self_convention)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::disallowed_names)]
#![allow(clippy::vec_init_then_push)]
#![allow(clippy::type_complexity)]
#![allow(clippy::needless_return)]
#![allow(clippy::derive_partial_eq_without_eq)]
#![allow(clippy::result_large_err)]
#![allow(clippy::unnecessary_map_on_constructor)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]
#![allow(rustdoc::invalid_html_tags)]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
//! Welcome to the Amazon CodeCatalyst API reference. This reference provides descriptions of operations and data types for Amazon CodeCatalyst. You can use the Amazon CodeCatalyst API to work with the following objects.
//!
//! Spaces, by calling the following:
//!   - DeleteSpace, which deletes a space.
//!   - GetSpace, which returns information about a space.
//!   - GetSubscription, which returns information about the Amazon Web Services account used for billing purposes and the billing plan for the space.
//!   - ListSpaces, which retrieves a list of spaces.
//!   - UpdateSpace, which changes one or more values for a space.
//!
//! Projects, by calling the following:
//!   - CreateProject which creates a project in a specified space.
//!   - GetProject, which returns information about a project.
//!   - ListProjects, which retrieves a list of projects in a space.
//!
//! Users, by calling the following:
//!   - GetUserDetails, which returns information about a user in Amazon CodeCatalyst.
//!
//! Source repositories, by calling the following:
//!   - CreateSourceRepository, which creates an empty Git-based source repository in a specified project.
//!   - CreateSourceRepositoryBranch, which creates a branch in a specified repository where you can work on code.
//!   - DeleteSourceRepository, which deletes a source repository.
//!   - GetSourceRepository, which returns information about a source repository.
//!   - GetSourceRepositoryCloneUrls, which returns information about the URLs that can be used with a Git client to clone a source repository.
//!   - ListSourceRepositories, which retrieves a list of source repositories in a project.
//!   - ListSourceRepositoryBranches, which retrieves a list of branches in a source repository.
//!
//! Dev Environments and the Amazon Web Services Toolkits, by calling the following:
//!   - CreateDevEnvironment, which creates a Dev Environment, where you can quickly work on the code stored in the source repositories of your project.
//!   - DeleteDevEnvironment, which deletes a Dev Environment.
//!   - GetDevEnvironment, which returns information about a Dev Environment.
//!   - ListDevEnvironments, which retrieves a list of Dev Environments in a project.
//!   - ListDevEnvironmentSessions, which retrieves a list of active Dev Environment sessions in a project.
//!   - StartDevEnvironment, which starts a specified Dev Environment and puts it into an active state.
//!   - StartDevEnvironmentSession, which starts a session to a specified Dev Environment.
//!   - StopDevEnvironment, which stops a specified Dev Environment and puts it into an stopped state.
//!   - StopDevEnvironmentSession, which stops a session for a specified Dev Environment.
//!   - UpdateDevEnvironment, which changes one or more values for a Dev Environment.
//!
//! Workflows, by calling the following:
//!   - GetWorkflow, which returns information about a workflow.
//!   - GetWorkflowRun, which returns information about a specified run of a workflow.
//!   - ListWorkflowRuns, which retrieves a list of runs of a specified workflow.
//!   - ListWorkflows, which retrieves a list of workflows in a specified project.
//!   - StartWorkflowRun, which starts a run of a specified workflow.
//!
//! Security, activity, and resource management in Amazon CodeCatalyst, by calling the following:
//!   - CreateAccessToken, which creates a personal access token (PAT) for the current user.
//!   - DeleteAccessToken, which deletes a specified personal access token (PAT).
//!   - ListAccessTokens, which lists all personal access tokens (PATs) associated with a user.
//!   - ListEventLogs, which retrieves a list of events that occurred during a specified time period in a space.
//!   - VerifySession, which verifies whether the calling user has a valid Amazon CodeCatalyst login and session.
//!
//! ## Getting Started
//!
//! > Examples are available for many services and operations, check out the
//! > [examples folder in GitHub](https://github.com/awslabs/aws-sdk-rust/tree/main/examples).
//!
//! The SDK provides one crate per AWS service. You must add [Tokio](https://crates.io/crates/tokio)
//! as a dependency within your Rust project to execute asynchronous code. To add `aws-sdk-codecatalyst` to
//! your project, add the following to your **Cargo.toml** file:
//!
//! ```toml
//! [dependencies]
//! aws-config = { version = "1.1.7", features = ["behavior-version-latest"] }
//! aws-sdk-codecatalyst = "0.0.0-local"
//! tokio = { version = "1", features = ["full"] }
//! ```
//!
//! Then in code, a client can be created with the following:
//!
//! ```rust,no_run
//! use aws_sdk_codecatalyst as codecatalyst;
//!
//! #[::tokio::main]
//! async fn main() -> Result<(), codecatalyst::Error> {
//!     let config = aws_config::load_from_env().await;
//!     let client = aws_sdk_codecatalyst::Client::new(&config);
//!
//!     // ... make some calls with the client
//!
//!     Ok(())
//! }
//! ```
//!
//! See the [client documentation](https://docs.rs/aws-sdk-codecatalyst/latest/aws_sdk_codecatalyst/client/struct.Client.html)
//! for information on what calls can be made, and the inputs and outputs for each of those calls.
//!
//! ## Using the SDK
//!
//! Until the SDK is released, we will be adding information about using the SDK to the
//! [Developer Guide](https://docs.aws.amazon.com/sdk-for-rust/latest/dg/welcome.html). Feel free to suggest
//! additional sections for the guide by opening an issue and describing what you are trying to do.
//!
//! ## Getting Help
//!
//! * [GitHub discussions](https://github.com/awslabs/aws-sdk-rust/discussions) - For ideas, RFCs & general questions
//! * [GitHub issues](https://github.com/awslabs/aws-sdk-rust/issues/new/choose) - For bug reports & feature requests
//! * [Generated Docs (latest version)](https://awslabs.github.io/aws-sdk-rust/)
//! * [Usage examples](https://github.com/awslabs/aws-sdk-rust/tree/main/examples)
//!
//!
//! # Crate Organization
//!
//! The entry point for most customers will be [`Client`], which exposes one method for each API
//! offered by Amazon CodeCatalyst. The return value of each of these methods is a "fluent builder",
//! where the different inputs for that API are added by builder-style function call chaining,
//! followed by calling `send()` to get a [`Future`](std::future::Future) that will result in
//! either a successful output or a [`SdkError`](crate::error::SdkError).
//!
//! Some of these API inputs may be structs or enums to provide more complex structured information.
//! These structs and enums live in [`types`](crate::types). There are some simpler types for
//! representing data such as date times or binary blobs that live in [`primitives`](crate::primitives).
//!
//! All types required to configure a client via the [`Config`](crate::Config) struct live
//! in [`config`](crate::config).
//!
//! The [`operation`](crate::operation) module has a submodule for every API, and in each submodule
//! is the input, output, and error type for that API, as well as builders to construct each of those.
//!
//! There is a top-level [`Error`](crate::Error) type that encompasses all the errors that the
//! client can return. Any other error type can be converted to this `Error` type via the
//! [`From`](std::convert::From) trait.
//!
//! The other modules within this crate are not required for normal usage.

// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
pub use error_meta::Error;

#[doc(inline)]
pub use config::Config;

/// Client for calling Amazon CodeCatalyst.
/// ## Constructing a `Client`
///
/// A [`Config`] is required to construct a client. For most use cases, the [`aws-config`]
/// crate should be used to automatically resolve this config using
/// [`aws_config::load_from_env()`], since this will resolve an [`SdkConfig`] which can be shared
/// across multiple different AWS SDK clients. This config resolution process can be customized
/// by calling [`aws_config::from_env()`] instead, which returns a [`ConfigLoader`] that uses
/// the [builder pattern] to customize the default config.
///
/// In the simplest case, creating a client looks as follows:
/// ```rust,no_run
/// # async fn wrapper() {
/// let config = aws_config::load_from_env().await;
/// let client = aws_sdk_codecatalyst::Client::new(&config);
/// # }
/// ```
///
/// Occasionally, SDKs may have additional service-specific values that can be set on the [`Config`] that
/// is absent from [`SdkConfig`], or slightly different settings for a specific client may be desired.
/// The [`Builder`](crate::config::Builder) struct implements `From<&SdkConfig>`, so setting these specific settings can be
/// done as follows:
///
/// ```rust,no_run
/// # async fn wrapper() {
/// let sdk_config = ::aws_config::load_from_env().await;
/// let config = aws_sdk_codecatalyst::config::Builder::from(&sdk_config)
/// # /*
///     .some_service_specific_setting("value")
/// # */
///     .build();
/// # }
/// ```
///
/// See the [`aws-config` docs] and [`Config`] for more information on customizing configuration.
///
/// _Note:_ Client construction is expensive due to connection thread pool initialization, and should
/// be done once at application start-up.
///
/// [`Config`]: crate::Config
/// [`ConfigLoader`]: https://docs.rs/aws-config/*/aws_config/struct.ConfigLoader.html
/// [`SdkConfig`]: https://docs.rs/aws-config/*/aws_config/struct.SdkConfig.html
/// [`aws-config` docs]: https://docs.rs/aws-config/*
/// [`aws-config`]: https://crates.io/crates/aws-config
/// [`aws_config::from_env()`]: https://docs.rs/aws-config/*/aws_config/fn.from_env.html
/// [`aws_config::load_from_env()`]: https://docs.rs/aws-config/*/aws_config/fn.load_from_env.html
/// [builder pattern]: https://rust-lang.github.io/api-guidelines/type-safety.html#builders-enable-construction-of-complex-values-c-builder
/// # Using the `Client`
///
/// A client has a function for every operation that can be performed by the service.
/// For example, the [`CreateAccessToken`](crate::operation::create_access_token) operation has
/// a [`Client::create_access_token`], function which returns a builder for that operation.
/// The fluent builder ultimately has a `send()` function that returns an async future that
/// returns a result, as illustrated below:
///
/// ```rust,ignore
/// let result = client.create_access_token()
///     .name("example")
///     .send()
///     .await;
/// ```
///
/// The underlying HTTP requests that get made by this can be modified with the `customize_operation`
/// function on the fluent builder. See the [`customize`](crate::client::customize) module for more
/// information.
pub mod client;

/// Configuration for Amazon CodeCatalyst.
pub mod config;

/// Common errors and error handling utilities.
pub mod error;

mod error_meta;

/// Information about this crate.
pub mod meta;

/// All operations that this crate can perform.
pub mod operation;

/// Primitives such as `Blob` or `DateTime` used by other types.
pub mod primitives;

/// Data structures used by operation inputs/outputs.
pub mod types;

mod auth_plugin;

pub(crate) mod client_idempotency_token;

mod idempotency_token;

pub(crate) mod protocol_serde;

mod sdk_feature_tracker;

mod serialization_settings;

mod endpoint_lib;

mod lens;

mod serde_util;

mod json_errors;

#[doc(inline)]
pub use client::Client;
