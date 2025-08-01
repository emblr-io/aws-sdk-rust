// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an existing OpenSearch Ingestion pipeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Pipeline {
    /// <p>The name of the pipeline.</p>
    pub pipeline_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub pipeline_arn: ::std::option::Option<::std::string::String>,
    /// <p>The minimum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub min_units: i32,
    /// <p>The maximum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub max_units: i32,
    /// <p>The current status of the pipeline.</p>
    pub status: ::std::option::Option<crate::types::PipelineStatus>,
    /// <p>The reason for the current status of the pipeline.</p>
    pub status_reason: ::std::option::Option<crate::types::PipelineStatusReason>,
    /// <p>The Data Prepper pipeline configuration in YAML format.</p>
    pub pipeline_configuration_body: ::std::option::Option<::std::string::String>,
    /// <p>The date and time when the pipeline was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time when the pipeline was last updated.</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ingestion endpoints for the pipeline, which you can send data to.</p>
    pub ingest_endpoint_urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Key-value pairs that represent log publishing settings.</p>
    pub log_publishing_options: ::std::option::Option<crate::types::LogPublishingOptions>,
    /// <p>The VPC interface endpoints that have access to the pipeline.</p>
    pub vpc_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::VpcEndpoint>>,
    /// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
    pub buffer_options: ::std::option::Option<crate::types::BufferOptions>,
    /// <p>Options to control how OpenSearch encrypts buffer data.</p>
    pub encryption_at_rest_options: ::std::option::Option<crate::types::EncryptionAtRestOptions>,
    /// <p>The VPC endpoint service name for the pipeline.</p>
    pub vpc_endpoint_service: ::std::option::Option<::std::string::String>,
    /// <p>A list of VPC endpoints that OpenSearch Ingestion has created to other Amazon Web Services services.</p>
    pub service_vpc_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::ServiceVpcEndpoint>>,
    /// <p>Destinations to which the pipeline writes data.</p>
    pub destinations: ::std::option::Option<::std::vec::Vec<crate::types::PipelineDestination>>,
    /// <p>A list of tags associated with the given pipeline.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl Pipeline {
    /// <p>The name of the pipeline.</p>
    pub fn pipeline_name(&self) -> ::std::option::Option<&str> {
        self.pipeline_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn pipeline_arn(&self) -> ::std::option::Option<&str> {
        self.pipeline_arn.as_deref()
    }
    /// <p>The minimum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn min_units(&self) -> i32 {
        self.min_units
    }
    /// <p>The maximum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn max_units(&self) -> i32 {
        self.max_units
    }
    /// <p>The current status of the pipeline.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::PipelineStatus> {
        self.status.as_ref()
    }
    /// <p>The reason for the current status of the pipeline.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&crate::types::PipelineStatusReason> {
        self.status_reason.as_ref()
    }
    /// <p>The Data Prepper pipeline configuration in YAML format.</p>
    pub fn pipeline_configuration_body(&self) -> ::std::option::Option<&str> {
        self.pipeline_configuration_body.as_deref()
    }
    /// <p>The date and time when the pipeline was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time when the pipeline was last updated.</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>The ingestion endpoints for the pipeline, which you can send data to.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.ingest_endpoint_urls.is_none()`.
    pub fn ingest_endpoint_urls(&self) -> &[::std::string::String] {
        self.ingest_endpoint_urls.as_deref().unwrap_or_default()
    }
    /// <p>Key-value pairs that represent log publishing settings.</p>
    pub fn log_publishing_options(&self) -> ::std::option::Option<&crate::types::LogPublishingOptions> {
        self.log_publishing_options.as_ref()
    }
    /// <p>The VPC interface endpoints that have access to the pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_endpoints.is_none()`.
    pub fn vpc_endpoints(&self) -> &[crate::types::VpcEndpoint] {
        self.vpc_endpoints.as_deref().unwrap_or_default()
    }
    /// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
    pub fn buffer_options(&self) -> ::std::option::Option<&crate::types::BufferOptions> {
        self.buffer_options.as_ref()
    }
    /// <p>Options to control how OpenSearch encrypts buffer data.</p>
    pub fn encryption_at_rest_options(&self) -> ::std::option::Option<&crate::types::EncryptionAtRestOptions> {
        self.encryption_at_rest_options.as_ref()
    }
    /// <p>The VPC endpoint service name for the pipeline.</p>
    pub fn vpc_endpoint_service(&self) -> ::std::option::Option<&str> {
        self.vpc_endpoint_service.as_deref()
    }
    /// <p>A list of VPC endpoints that OpenSearch Ingestion has created to other Amazon Web Services services.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.service_vpc_endpoints.is_none()`.
    pub fn service_vpc_endpoints(&self) -> &[crate::types::ServiceVpcEndpoint] {
        self.service_vpc_endpoints.as_deref().unwrap_or_default()
    }
    /// <p>Destinations to which the pipeline writes data.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.destinations.is_none()`.
    pub fn destinations(&self) -> &[crate::types::PipelineDestination] {
        self.destinations.as_deref().unwrap_or_default()
    }
    /// <p>A list of tags associated with the given pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl Pipeline {
    /// Creates a new builder-style object to manufacture [`Pipeline`](crate::types::Pipeline).
    pub fn builder() -> crate::types::builders::PipelineBuilder {
        crate::types::builders::PipelineBuilder::default()
    }
}

/// A builder for [`Pipeline`](crate::types::Pipeline).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PipelineBuilder {
    pub(crate) pipeline_name: ::std::option::Option<::std::string::String>,
    pub(crate) pipeline_arn: ::std::option::Option<::std::string::String>,
    pub(crate) min_units: ::std::option::Option<i32>,
    pub(crate) max_units: ::std::option::Option<i32>,
    pub(crate) status: ::std::option::Option<crate::types::PipelineStatus>,
    pub(crate) status_reason: ::std::option::Option<crate::types::PipelineStatusReason>,
    pub(crate) pipeline_configuration_body: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) ingest_endpoint_urls: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) log_publishing_options: ::std::option::Option<crate::types::LogPublishingOptions>,
    pub(crate) vpc_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::VpcEndpoint>>,
    pub(crate) buffer_options: ::std::option::Option<crate::types::BufferOptions>,
    pub(crate) encryption_at_rest_options: ::std::option::Option<crate::types::EncryptionAtRestOptions>,
    pub(crate) vpc_endpoint_service: ::std::option::Option<::std::string::String>,
    pub(crate) service_vpc_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::ServiceVpcEndpoint>>,
    pub(crate) destinations: ::std::option::Option<::std::vec::Vec<crate::types::PipelineDestination>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl PipelineBuilder {
    /// <p>The name of the pipeline.</p>
    pub fn pipeline_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the pipeline.</p>
    pub fn set_pipeline_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_name = input;
        self
    }
    /// <p>The name of the pipeline.</p>
    pub fn get_pipeline_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_name
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn pipeline_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn set_pipeline_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the pipeline.</p>
    pub fn get_pipeline_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_arn
    }
    /// <p>The minimum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn min_units(mut self, input: i32) -> Self {
        self.min_units = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn set_min_units(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_units = input;
        self
    }
    /// <p>The minimum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn get_min_units(&self) -> &::std::option::Option<i32> {
        &self.min_units
    }
    /// <p>The maximum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn max_units(mut self, input: i32) -> Self {
        self.max_units = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn set_max_units(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_units = input;
        self
    }
    /// <p>The maximum pipeline capacity, in Ingestion Compute Units (ICUs).</p>
    pub fn get_max_units(&self) -> &::std::option::Option<i32> {
        &self.max_units
    }
    /// <p>The current status of the pipeline.</p>
    pub fn status(mut self, input: crate::types::PipelineStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the pipeline.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::PipelineStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the pipeline.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::PipelineStatus> {
        &self.status
    }
    /// <p>The reason for the current status of the pipeline.</p>
    pub fn status_reason(mut self, input: crate::types::PipelineStatusReason) -> Self {
        self.status_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason for the current status of the pipeline.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<crate::types::PipelineStatusReason>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>The reason for the current status of the pipeline.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<crate::types::PipelineStatusReason> {
        &self.status_reason
    }
    /// <p>The Data Prepper pipeline configuration in YAML format.</p>
    pub fn pipeline_configuration_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_configuration_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Data Prepper pipeline configuration in YAML format.</p>
    pub fn set_pipeline_configuration_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_configuration_body = input;
        self
    }
    /// <p>The Data Prepper pipeline configuration in YAML format.</p>
    pub fn get_pipeline_configuration_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_configuration_body
    }
    /// <p>The date and time when the pipeline was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the pipeline was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time when the pipeline was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time when the pipeline was last updated.</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the pipeline was last updated.</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>The date and time when the pipeline was last updated.</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Appends an item to `ingest_endpoint_urls`.
    ///
    /// To override the contents of this collection use [`set_ingest_endpoint_urls`](Self::set_ingest_endpoint_urls).
    ///
    /// <p>The ingestion endpoints for the pipeline, which you can send data to.</p>
    pub fn ingest_endpoint_urls(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.ingest_endpoint_urls.unwrap_or_default();
        v.push(input.into());
        self.ingest_endpoint_urls = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ingestion endpoints for the pipeline, which you can send data to.</p>
    pub fn set_ingest_endpoint_urls(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.ingest_endpoint_urls = input;
        self
    }
    /// <p>The ingestion endpoints for the pipeline, which you can send data to.</p>
    pub fn get_ingest_endpoint_urls(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.ingest_endpoint_urls
    }
    /// <p>Key-value pairs that represent log publishing settings.</p>
    pub fn log_publishing_options(mut self, input: crate::types::LogPublishingOptions) -> Self {
        self.log_publishing_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Key-value pairs that represent log publishing settings.</p>
    pub fn set_log_publishing_options(mut self, input: ::std::option::Option<crate::types::LogPublishingOptions>) -> Self {
        self.log_publishing_options = input;
        self
    }
    /// <p>Key-value pairs that represent log publishing settings.</p>
    pub fn get_log_publishing_options(&self) -> &::std::option::Option<crate::types::LogPublishingOptions> {
        &self.log_publishing_options
    }
    /// Appends an item to `vpc_endpoints`.
    ///
    /// To override the contents of this collection use [`set_vpc_endpoints`](Self::set_vpc_endpoints).
    ///
    /// <p>The VPC interface endpoints that have access to the pipeline.</p>
    pub fn vpc_endpoints(mut self, input: crate::types::VpcEndpoint) -> Self {
        let mut v = self.vpc_endpoints.unwrap_or_default();
        v.push(input);
        self.vpc_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>The VPC interface endpoints that have access to the pipeline.</p>
    pub fn set_vpc_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcEndpoint>>) -> Self {
        self.vpc_endpoints = input;
        self
    }
    /// <p>The VPC interface endpoints that have access to the pipeline.</p>
    pub fn get_vpc_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcEndpoint>> {
        &self.vpc_endpoints
    }
    /// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
    pub fn buffer_options(mut self, input: crate::types::BufferOptions) -> Self {
        self.buffer_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
    pub fn set_buffer_options(mut self, input: ::std::option::Option<crate::types::BufferOptions>) -> Self {
        self.buffer_options = input;
        self
    }
    /// <p>Options that specify the configuration of a persistent buffer. To configure how OpenSearch Ingestion encrypts this data, set the <code>EncryptionAtRestOptions</code>. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/osis-features-overview.html#persistent-buffering">Persistent buffering</a>.</p>
    pub fn get_buffer_options(&self) -> &::std::option::Option<crate::types::BufferOptions> {
        &self.buffer_options
    }
    /// <p>Options to control how OpenSearch encrypts buffer data.</p>
    pub fn encryption_at_rest_options(mut self, input: crate::types::EncryptionAtRestOptions) -> Self {
        self.encryption_at_rest_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options to control how OpenSearch encrypts buffer data.</p>
    pub fn set_encryption_at_rest_options(mut self, input: ::std::option::Option<crate::types::EncryptionAtRestOptions>) -> Self {
        self.encryption_at_rest_options = input;
        self
    }
    /// <p>Options to control how OpenSearch encrypts buffer data.</p>
    pub fn get_encryption_at_rest_options(&self) -> &::std::option::Option<crate::types::EncryptionAtRestOptions> {
        &self.encryption_at_rest_options
    }
    /// <p>The VPC endpoint service name for the pipeline.</p>
    pub fn vpc_endpoint_service(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_endpoint_service = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC endpoint service name for the pipeline.</p>
    pub fn set_vpc_endpoint_service(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_endpoint_service = input;
        self
    }
    /// <p>The VPC endpoint service name for the pipeline.</p>
    pub fn get_vpc_endpoint_service(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_endpoint_service
    }
    /// Appends an item to `service_vpc_endpoints`.
    ///
    /// To override the contents of this collection use [`set_service_vpc_endpoints`](Self::set_service_vpc_endpoints).
    ///
    /// <p>A list of VPC endpoints that OpenSearch Ingestion has created to other Amazon Web Services services.</p>
    pub fn service_vpc_endpoints(mut self, input: crate::types::ServiceVpcEndpoint) -> Self {
        let mut v = self.service_vpc_endpoints.unwrap_or_default();
        v.push(input);
        self.service_vpc_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of VPC endpoints that OpenSearch Ingestion has created to other Amazon Web Services services.</p>
    pub fn set_service_vpc_endpoints(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ServiceVpcEndpoint>>) -> Self {
        self.service_vpc_endpoints = input;
        self
    }
    /// <p>A list of VPC endpoints that OpenSearch Ingestion has created to other Amazon Web Services services.</p>
    pub fn get_service_vpc_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ServiceVpcEndpoint>> {
        &self.service_vpc_endpoints
    }
    /// Appends an item to `destinations`.
    ///
    /// To override the contents of this collection use [`set_destinations`](Self::set_destinations).
    ///
    /// <p>Destinations to which the pipeline writes data.</p>
    pub fn destinations(mut self, input: crate::types::PipelineDestination) -> Self {
        let mut v = self.destinations.unwrap_or_default();
        v.push(input);
        self.destinations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Destinations to which the pipeline writes data.</p>
    pub fn set_destinations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PipelineDestination>>) -> Self {
        self.destinations = input;
        self
    }
    /// <p>Destinations to which the pipeline writes data.</p>
    pub fn get_destinations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PipelineDestination>> {
        &self.destinations
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags associated with the given pipeline.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags associated with the given pipeline.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags associated with the given pipeline.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`Pipeline`](crate::types::Pipeline).
    pub fn build(self) -> crate::types::Pipeline {
        crate::types::Pipeline {
            pipeline_name: self.pipeline_name,
            pipeline_arn: self.pipeline_arn,
            min_units: self.min_units.unwrap_or_default(),
            max_units: self.max_units.unwrap_or_default(),
            status: self.status,
            status_reason: self.status_reason,
            pipeline_configuration_body: self.pipeline_configuration_body,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            ingest_endpoint_urls: self.ingest_endpoint_urls,
            log_publishing_options: self.log_publishing_options,
            vpc_endpoints: self.vpc_endpoints,
            buffer_options: self.buffer_options,
            encryption_at_rest_options: self.encryption_at_rest_options,
            vpc_endpoint_service: self.vpc_endpoint_service,
            service_vpc_endpoints: self.service_vpc_endpoints,
            destinations: self.destinations,
            tags: self.tags,
        }
    }
}
