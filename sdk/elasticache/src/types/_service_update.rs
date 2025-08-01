// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An update that you can apply to your Valkey or Redis OSS clusters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceUpdate {
    /// <p>The unique ID of the service update</p>
    pub service_update_name: ::std::option::Option<::std::string::String>,
    /// <p>The date when the service update is initially available</p>
    pub service_update_release_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date after which the service update is no longer available</p>
    pub service_update_end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The severity of the service update</p>
    pub service_update_severity: ::std::option::Option<crate::types::ServiceUpdateSeverity>,
    /// <p>The recommendend date to apply the service update in order to ensure compliance. For information on compliance, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/elasticache-compliance.html#elasticache-compliance-self-service">Self-Service Security Updates for Compliance</a>.</p>
    pub service_update_recommended_apply_by_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the service update</p>
    pub service_update_status: ::std::option::Option<crate::types::ServiceUpdateStatus>,
    /// <p>Provides details of the service update</p>
    pub service_update_description: ::std::option::Option<::std::string::String>,
    /// <p>Reflects the nature of the service update</p>
    pub service_update_type: ::std::option::Option<crate::types::ServiceUpdateType>,
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub engine: ::std::option::Option<::std::string::String>,
    /// <p>The Elasticache engine version to which the update applies. Either Valkey, Redis OSS or Memcached engine version.</p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether the service update will be automatically applied once the recommended apply-by date has expired.</p>
    pub auto_update_after_recommended_apply_by_date: ::std::option::Option<bool>,
    /// <p>The estimated length of time the service update will take</p>
    pub estimated_update_time: ::std::option::Option<::std::string::String>,
}
impl ServiceUpdate {
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(&self) -> ::std::option::Option<&str> {
        self.service_update_name.as_deref()
    }
    /// <p>The date when the service update is initially available</p>
    pub fn service_update_release_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.service_update_release_date.as_ref()
    }
    /// <p>The date after which the service update is no longer available</p>
    pub fn service_update_end_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.service_update_end_date.as_ref()
    }
    /// <p>The severity of the service update</p>
    pub fn service_update_severity(&self) -> ::std::option::Option<&crate::types::ServiceUpdateSeverity> {
        self.service_update_severity.as_ref()
    }
    /// <p>The recommendend date to apply the service update in order to ensure compliance. For information on compliance, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/elasticache-compliance.html#elasticache-compliance-self-service">Self-Service Security Updates for Compliance</a>.</p>
    pub fn service_update_recommended_apply_by_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.service_update_recommended_apply_by_date.as_ref()
    }
    /// <p>The status of the service update</p>
    pub fn service_update_status(&self) -> ::std::option::Option<&crate::types::ServiceUpdateStatus> {
        self.service_update_status.as_ref()
    }
    /// <p>Provides details of the service update</p>
    pub fn service_update_description(&self) -> ::std::option::Option<&str> {
        self.service_update_description.as_deref()
    }
    /// <p>Reflects the nature of the service update</p>
    pub fn service_update_type(&self) -> ::std::option::Option<&crate::types::ServiceUpdateType> {
        self.service_update_type.as_ref()
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn engine(&self) -> ::std::option::Option<&str> {
        self.engine.as_deref()
    }
    /// <p>The Elasticache engine version to which the update applies. Either Valkey, Redis OSS or Memcached engine version.</p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>Indicates whether the service update will be automatically applied once the recommended apply-by date has expired.</p>
    pub fn auto_update_after_recommended_apply_by_date(&self) -> ::std::option::Option<bool> {
        self.auto_update_after_recommended_apply_by_date
    }
    /// <p>The estimated length of time the service update will take</p>
    pub fn estimated_update_time(&self) -> ::std::option::Option<&str> {
        self.estimated_update_time.as_deref()
    }
}
impl ServiceUpdate {
    /// Creates a new builder-style object to manufacture [`ServiceUpdate`](crate::types::ServiceUpdate).
    pub fn builder() -> crate::types::builders::ServiceUpdateBuilder {
        crate::types::builders::ServiceUpdateBuilder::default()
    }
}

/// A builder for [`ServiceUpdate`](crate::types::ServiceUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceUpdateBuilder {
    pub(crate) service_update_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_update_release_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) service_update_end_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) service_update_severity: ::std::option::Option<crate::types::ServiceUpdateSeverity>,
    pub(crate) service_update_recommended_apply_by_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) service_update_status: ::std::option::Option<crate::types::ServiceUpdateStatus>,
    pub(crate) service_update_description: ::std::option::Option<::std::string::String>,
    pub(crate) service_update_type: ::std::option::Option<crate::types::ServiceUpdateType>,
    pub(crate) engine: ::std::option::Option<::std::string::String>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) auto_update_after_recommended_apply_by_date: ::std::option::Option<bool>,
    pub(crate) estimated_update_time: ::std::option::Option<::std::string::String>,
}
impl ServiceUpdateBuilder {
    /// <p>The unique ID of the service update</p>
    pub fn service_update_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_update_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn set_service_update_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_update_name = input;
        self
    }
    /// <p>The unique ID of the service update</p>
    pub fn get_service_update_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_update_name
    }
    /// <p>The date when the service update is initially available</p>
    pub fn service_update_release_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.service_update_release_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the service update is initially available</p>
    pub fn set_service_update_release_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.service_update_release_date = input;
        self
    }
    /// <p>The date when the service update is initially available</p>
    pub fn get_service_update_release_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.service_update_release_date
    }
    /// <p>The date after which the service update is no longer available</p>
    pub fn service_update_end_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.service_update_end_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date after which the service update is no longer available</p>
    pub fn set_service_update_end_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.service_update_end_date = input;
        self
    }
    /// <p>The date after which the service update is no longer available</p>
    pub fn get_service_update_end_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.service_update_end_date
    }
    /// <p>The severity of the service update</p>
    pub fn service_update_severity(mut self, input: crate::types::ServiceUpdateSeverity) -> Self {
        self.service_update_severity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The severity of the service update</p>
    pub fn set_service_update_severity(mut self, input: ::std::option::Option<crate::types::ServiceUpdateSeverity>) -> Self {
        self.service_update_severity = input;
        self
    }
    /// <p>The severity of the service update</p>
    pub fn get_service_update_severity(&self) -> &::std::option::Option<crate::types::ServiceUpdateSeverity> {
        &self.service_update_severity
    }
    /// <p>The recommendend date to apply the service update in order to ensure compliance. For information on compliance, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/elasticache-compliance.html#elasticache-compliance-self-service">Self-Service Security Updates for Compliance</a>.</p>
    pub fn service_update_recommended_apply_by_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.service_update_recommended_apply_by_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommendend date to apply the service update in order to ensure compliance. For information on compliance, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/elasticache-compliance.html#elasticache-compliance-self-service">Self-Service Security Updates for Compliance</a>.</p>
    pub fn set_service_update_recommended_apply_by_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.service_update_recommended_apply_by_date = input;
        self
    }
    /// <p>The recommendend date to apply the service update in order to ensure compliance. For information on compliance, see <a href="https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/elasticache-compliance.html#elasticache-compliance-self-service">Self-Service Security Updates for Compliance</a>.</p>
    pub fn get_service_update_recommended_apply_by_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.service_update_recommended_apply_by_date
    }
    /// <p>The status of the service update</p>
    pub fn service_update_status(mut self, input: crate::types::ServiceUpdateStatus) -> Self {
        self.service_update_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the service update</p>
    pub fn set_service_update_status(mut self, input: ::std::option::Option<crate::types::ServiceUpdateStatus>) -> Self {
        self.service_update_status = input;
        self
    }
    /// <p>The status of the service update</p>
    pub fn get_service_update_status(&self) -> &::std::option::Option<crate::types::ServiceUpdateStatus> {
        &self.service_update_status
    }
    /// <p>Provides details of the service update</p>
    pub fn service_update_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_update_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provides details of the service update</p>
    pub fn set_service_update_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_update_description = input;
        self
    }
    /// <p>Provides details of the service update</p>
    pub fn get_service_update_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_update_description
    }
    /// <p>Reflects the nature of the service update</p>
    pub fn service_update_type(mut self, input: crate::types::ServiceUpdateType) -> Self {
        self.service_update_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reflects the nature of the service update</p>
    pub fn set_service_update_type(mut self, input: ::std::option::Option<crate::types::ServiceUpdateType>) -> Self {
        self.service_update_type = input;
        self
    }
    /// <p>Reflects the nature of the service update</p>
    pub fn get_service_update_type(&self) -> &::std::option::Option<crate::types::ServiceUpdateType> {
        &self.service_update_type
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn engine(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn set_engine(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine = input;
        self
    }
    /// <p>The Elasticache engine to which the update applies. Either Valkey, Redis OSS or Memcached.</p>
    pub fn get_engine(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine
    }
    /// <p>The Elasticache engine version to which the update applies. Either Valkey, Redis OSS or Memcached engine version.</p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Elasticache engine version to which the update applies. Either Valkey, Redis OSS or Memcached engine version.</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The Elasticache engine version to which the update applies. Either Valkey, Redis OSS or Memcached engine version.</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>Indicates whether the service update will be automatically applied once the recommended apply-by date has expired.</p>
    pub fn auto_update_after_recommended_apply_by_date(mut self, input: bool) -> Self {
        self.auto_update_after_recommended_apply_by_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the service update will be automatically applied once the recommended apply-by date has expired.</p>
    pub fn set_auto_update_after_recommended_apply_by_date(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_update_after_recommended_apply_by_date = input;
        self
    }
    /// <p>Indicates whether the service update will be automatically applied once the recommended apply-by date has expired.</p>
    pub fn get_auto_update_after_recommended_apply_by_date(&self) -> &::std::option::Option<bool> {
        &self.auto_update_after_recommended_apply_by_date
    }
    /// <p>The estimated length of time the service update will take</p>
    pub fn estimated_update_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.estimated_update_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The estimated length of time the service update will take</p>
    pub fn set_estimated_update_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.estimated_update_time = input;
        self
    }
    /// <p>The estimated length of time the service update will take</p>
    pub fn get_estimated_update_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.estimated_update_time
    }
    /// Consumes the builder and constructs a [`ServiceUpdate`](crate::types::ServiceUpdate).
    pub fn build(self) -> crate::types::ServiceUpdate {
        crate::types::ServiceUpdate {
            service_update_name: self.service_update_name,
            service_update_release_date: self.service_update_release_date,
            service_update_end_date: self.service_update_end_date,
            service_update_severity: self.service_update_severity,
            service_update_recommended_apply_by_date: self.service_update_recommended_apply_by_date,
            service_update_status: self.service_update_status,
            service_update_description: self.service_update_description,
            service_update_type: self.service_update_type,
            engine: self.engine,
            engine_version: self.engine_version,
            auto_update_after_recommended_apply_by_date: self.auto_update_after_recommended_apply_by_date,
            estimated_update_time: self.estimated_update_time,
        }
    }
}
