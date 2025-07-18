// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[derive(Debug)]
pub(crate) struct Handle {
    pub(crate) conf: crate::Config,
    #[allow(dead_code)] // unused when a service does not provide any operations
    pub(crate) runtime_plugins: ::aws_smithy_runtime_api::client::runtime_plugin::RuntimePlugins,
}

/// Client for Amazon Rekognition
///
/// Client for invoking operations on Amazon Rekognition. Each operation on Amazon Rekognition is a method on this
/// this struct. `.send()` MUST be invoked on the generated operations to dispatch the request to the service.
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
/// let client = aws_sdk_rekognition::Client::new(&config);
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
/// let config = aws_sdk_rekognition::config::Builder::from(&sdk_config)
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
/// For example, the [`AssociateFaces`](crate::operation::associate_faces) operation has
/// a [`Client::associate_faces`], function which returns a builder for that operation.
/// The fluent builder ultimately has a `send()` function that returns an async future that
/// returns a result, as illustrated below:
///
/// ```rust,ignore
/// let result = client.associate_faces()
///     .collection_id("example")
///     .send()
///     .await;
/// ```
///
/// The underlying HTTP requests that get made by this can be modified with the `customize_operation`
/// function on the fluent builder. See the [`customize`](crate::client::customize) module for more
/// information.
/// # Waiters
///
/// This client provides `wait_until` methods behind the [`Waiters`](crate::client::Waiters) trait.
/// To use them, simply import the trait, and then call one of the `wait_until` methods. This will
/// return a waiter fluent builder that takes various parameters, which are documented on the builder
/// type. Once parameters have been provided, the `wait` method can be called to initiate waiting.
///
/// For example, if there was a `wait_until_thing` method, it could look like:
/// ```rust,ignore
/// let result = client.wait_until_thing()
///     .thing_id("someId")
///     .wait(Duration::from_secs(120))
///     .await;
/// ```
#[derive(::std::clone::Clone, ::std::fmt::Debug)]
pub struct Client {
    handle: ::std::sync::Arc<Handle>,
}

impl Client {
    /// Creates a new client from the service [`Config`](crate::Config).
    ///
    /// # Panics
    ///
    /// This method will panic in the following cases:
    ///
    /// - Retries or timeouts are enabled without a `sleep_impl` configured.
    /// - Identity caching is enabled without a `sleep_impl` and `time_source` configured.
    /// - No `behavior_version` is provided.
    ///
    /// The panic message for each of these will have instructions on how to resolve them.
    #[track_caller]
    pub fn from_conf(conf: crate::Config) -> Self {
        let handle = Handle {
            conf: conf.clone(),
            runtime_plugins: crate::config::base_client_runtime_plugins(conf),
        };
        if let Err(err) = Self::validate_config(&handle) {
            panic!("Invalid client configuration: {err}");
        }
        Self {
            handle: ::std::sync::Arc::new(handle),
        }
    }

    /// Returns the client's configuration.
    pub fn config(&self) -> &crate::Config {
        &self.handle.conf
    }

    fn validate_config(handle: &Handle) -> ::std::result::Result<(), ::aws_smithy_runtime_api::box_error::BoxError> {
        let mut cfg = ::aws_smithy_types::config_bag::ConfigBag::base();
        handle
            .runtime_plugins
            .apply_client_configuration(&mut cfg)?
            .validate_base_client_config(&cfg)?;
        Ok(())
    }
}

///
/// Waiter functions for the client.
///
/// Import this trait to get `wait_until` methods on the client.
///
pub trait Waiters {
    /// Wait until the ProjectVersion is running.
    fn wait_until_project_version_running(&self) -> crate::waiters::project_version_running::ProjectVersionRunningFluentBuilder;
    /// Wait until the ProjectVersion training completes.
    fn wait_until_project_version_training_completed(
        &self,
    ) -> crate::waiters::project_version_training_completed::ProjectVersionTrainingCompletedFluentBuilder;
}
impl Waiters for Client {
    fn wait_until_project_version_running(&self) -> crate::waiters::project_version_running::ProjectVersionRunningFluentBuilder {
        crate::waiters::project_version_running::ProjectVersionRunningFluentBuilder::new(self.handle.clone())
    }
    fn wait_until_project_version_training_completed(
        &self,
    ) -> crate::waiters::project_version_training_completed::ProjectVersionTrainingCompletedFluentBuilder {
        crate::waiters::project_version_training_completed::ProjectVersionTrainingCompletedFluentBuilder::new(self.handle.clone())
    }
}

impl Client {
    /// Creates a new client from an [SDK Config](::aws_types::sdk_config::SdkConfig).
    ///
    /// # Panics
    ///
    /// - This method will panic if the `sdk_config` is missing an async sleep implementation. If you experience this panic, set
    ///   the `sleep_impl` on the Config passed into this function to fix it.
    /// - This method will panic if the `sdk_config` is missing an HTTP connector. If you experience this panic, set the
    ///   `http_connector` on the Config passed into this function to fix it.
    /// - This method will panic if no `BehaviorVersion` is provided. If you experience this panic, set `behavior_version` on the Config or enable the `behavior-version-latest` Cargo feature.
    #[track_caller]
    pub fn new(sdk_config: &::aws_types::sdk_config::SdkConfig) -> Self {
        Self::from_conf(sdk_config.into())
    }
}

mod associate_faces;

mod compare_faces;

mod copy_project_version;

mod create_collection;

mod create_dataset;

mod create_face_liveness_session;

mod create_project;

mod create_project_version;

mod create_stream_processor;

mod create_user;

/// Operation customization and supporting types.
///
/// The underlying HTTP requests made during an operation can be customized
/// by calling the `customize()` method on the builder returned from a client
/// operation call. For example, this can be used to add an additional HTTP header:
///
/// ```ignore
/// # async fn wrapper() -> ::std::result::Result<(), aws_sdk_rekognition::Error> {
/// # let client: aws_sdk_rekognition::Client = unimplemented!();
/// use ::http::header::{HeaderName, HeaderValue};
///
/// let result = client.associate_faces()
///     .customize()
///     .mutate_request(|req| {
///         // Add `x-example-header` with value
///         req.headers_mut()
///             .insert(
///                 HeaderName::from_static("x-example-header"),
///                 HeaderValue::from_static("1"),
///             );
///     })
///     .send()
///     .await;
/// # }
/// ```
pub mod customize;

mod delete_collection;

mod delete_dataset;

mod delete_faces;

mod delete_project;

mod delete_project_policy;

mod delete_project_version;

mod delete_stream_processor;

mod delete_user;

mod describe_collection;

mod describe_dataset;

mod describe_project_versions;

mod describe_projects;

mod describe_stream_processor;

mod detect_custom_labels;

mod detect_faces;

mod detect_labels;

mod detect_moderation_labels;

mod detect_protective_equipment;

mod detect_text;

mod disassociate_faces;

mod distribute_dataset_entries;

mod get_celebrity_info;

mod get_celebrity_recognition;

mod get_content_moderation;

mod get_face_detection;

mod get_face_liveness_session_results;

mod get_face_search;

mod get_label_detection;

mod get_media_analysis_job;

mod get_person_tracking;

mod get_segment_detection;

mod get_text_detection;

mod index_faces;

mod list_collections;

mod list_dataset_entries;

mod list_dataset_labels;

mod list_faces;

mod list_media_analysis_jobs;

mod list_project_policies;

mod list_stream_processors;

mod list_tags_for_resource;

mod list_users;

mod put_project_policy;

mod recognize_celebrities;

mod search_faces;

mod search_faces_by_image;

mod search_users;

mod search_users_by_image;

mod start_celebrity_recognition;

mod start_content_moderation;

mod start_face_detection;

mod start_face_search;

mod start_label_detection;

mod start_media_analysis_job;

mod start_person_tracking;

mod start_project_version;

mod start_segment_detection;

mod start_stream_processor;

mod start_text_detection;

mod stop_project_version;

mod stop_stream_processor;

mod tag_resource;

mod untag_resource;

mod update_dataset_entries;

mod update_stream_processor;
