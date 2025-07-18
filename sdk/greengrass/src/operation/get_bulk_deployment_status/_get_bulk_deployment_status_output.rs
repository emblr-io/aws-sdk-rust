// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBulkDeploymentStatusOutput {
    /// Relevant metrics on input records processed during bulk deployment.
    pub bulk_deployment_metrics: ::std::option::Option<crate::types::BulkDeploymentMetrics>,
    /// The status of the bulk deployment.
    pub bulk_deployment_status: ::std::option::Option<crate::types::BulkDeploymentStatus>,
    /// The time, in ISO format, when the deployment was created.
    pub created_at: ::std::option::Option<::std::string::String>,
    /// Error details
    pub error_details: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>,
    /// Error message
    pub error_message: ::std::option::Option<::std::string::String>,
    /// Tag(s) attached to the resource arn.
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetBulkDeploymentStatusOutput {
    /// Relevant metrics on input records processed during bulk deployment.
    pub fn bulk_deployment_metrics(&self) -> ::std::option::Option<&crate::types::BulkDeploymentMetrics> {
        self.bulk_deployment_metrics.as_ref()
    }
    /// The status of the bulk deployment.
    pub fn bulk_deployment_status(&self) -> ::std::option::Option<&crate::types::BulkDeploymentStatus> {
        self.bulk_deployment_status.as_ref()
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// Error details
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.error_details.is_none()`.
    pub fn error_details(&self) -> &[crate::types::ErrorDetail] {
        self.error_details.as_deref().unwrap_or_default()
    }
    /// Error message
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// Tag(s) attached to the resource arn.
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetBulkDeploymentStatusOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBulkDeploymentStatusOutput {
    /// Creates a new builder-style object to manufacture [`GetBulkDeploymentStatusOutput`](crate::operation::get_bulk_deployment_status::GetBulkDeploymentStatusOutput).
    pub fn builder() -> crate::operation::get_bulk_deployment_status::builders::GetBulkDeploymentStatusOutputBuilder {
        crate::operation::get_bulk_deployment_status::builders::GetBulkDeploymentStatusOutputBuilder::default()
    }
}

/// A builder for [`GetBulkDeploymentStatusOutput`](crate::operation::get_bulk_deployment_status::GetBulkDeploymentStatusOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBulkDeploymentStatusOutputBuilder {
    pub(crate) bulk_deployment_metrics: ::std::option::Option<crate::types::BulkDeploymentMetrics>,
    pub(crate) bulk_deployment_status: ::std::option::Option<crate::types::BulkDeploymentStatus>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) error_details: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl GetBulkDeploymentStatusOutputBuilder {
    /// Relevant metrics on input records processed during bulk deployment.
    pub fn bulk_deployment_metrics(mut self, input: crate::types::BulkDeploymentMetrics) -> Self {
        self.bulk_deployment_metrics = ::std::option::Option::Some(input);
        self
    }
    /// Relevant metrics on input records processed during bulk deployment.
    pub fn set_bulk_deployment_metrics(mut self, input: ::std::option::Option<crate::types::BulkDeploymentMetrics>) -> Self {
        self.bulk_deployment_metrics = input;
        self
    }
    /// Relevant metrics on input records processed during bulk deployment.
    pub fn get_bulk_deployment_metrics(&self) -> &::std::option::Option<crate::types::BulkDeploymentMetrics> {
        &self.bulk_deployment_metrics
    }
    /// The status of the bulk deployment.
    pub fn bulk_deployment_status(mut self, input: crate::types::BulkDeploymentStatus) -> Self {
        self.bulk_deployment_status = ::std::option::Option::Some(input);
        self
    }
    /// The status of the bulk deployment.
    pub fn set_bulk_deployment_status(mut self, input: ::std::option::Option<crate::types::BulkDeploymentStatus>) -> Self {
        self.bulk_deployment_status = input;
        self
    }
    /// The status of the bulk deployment.
    pub fn get_bulk_deployment_status(&self) -> &::std::option::Option<crate::types::BulkDeploymentStatus> {
        &self.bulk_deployment_status
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
    }
    /// Appends an item to `error_details`.
    ///
    /// To override the contents of this collection use [`set_error_details`](Self::set_error_details).
    ///
    /// Error details
    pub fn error_details(mut self, input: crate::types::ErrorDetail) -> Self {
        let mut v = self.error_details.unwrap_or_default();
        v.push(input);
        self.error_details = ::std::option::Option::Some(v);
        self
    }
    /// Error details
    pub fn set_error_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>) -> Self {
        self.error_details = input;
        self
    }
    /// Error details
    pub fn get_error_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>> {
        &self.error_details
    }
    /// Error message
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// Error message
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// Error message
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// Tag(s) attached to the resource arn.
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// Tag(s) attached to the resource arn.
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// Tag(s) attached to the resource arn.
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBulkDeploymentStatusOutput`](crate::operation::get_bulk_deployment_status::GetBulkDeploymentStatusOutput).
    pub fn build(self) -> crate::operation::get_bulk_deployment_status::GetBulkDeploymentStatusOutput {
        crate::operation::get_bulk_deployment_status::GetBulkDeploymentStatusOutput {
            bulk_deployment_metrics: self.bulk_deployment_metrics,
            bulk_deployment_status: self.bulk_deployment_status,
            created_at: self.created_at,
            error_details: self.error_details,
            error_message: self.error_message,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
