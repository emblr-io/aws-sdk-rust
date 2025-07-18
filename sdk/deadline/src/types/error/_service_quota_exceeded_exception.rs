// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>You exceeded your service quota. Service quotas, also referred to as limits, are the maximum number of service resources or operations for your Amazon Web Services account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServiceQuotaExceededException {
    #[allow(missing_docs)] // documentation missing in model
    pub message: ::std::string::String,
    /// <p>A string that describes the reason the quota was exceeded.</p>
    pub reason: crate::types::ServiceQuotaExceededExceptionReason,
    /// <p>The type of the affected resource</p>
    pub resource_type: ::std::string::String,
    /// <p>Identifies the service that exceeded the quota.</p>
    pub service_code: ::std::string::String,
    /// <p>Identifies the quota that has been exceeded.</p>
    pub quota_code: ::std::string::String,
    /// <p>The identifier of the affected resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>Information about the resources in use when the exception was thrown.</p>
    pub context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) meta: ::aws_smithy_types::error::ErrorMetadata,
}
impl ServiceQuotaExceededException {
    /// <p>A string that describes the reason the quota was exceeded.</p>
    pub fn reason(&self) -> &crate::types::ServiceQuotaExceededExceptionReason {
        &self.reason
    }
    /// <p>The type of the affected resource</p>
    pub fn resource_type(&self) -> &str {
        use std::ops::Deref;
        self.resource_type.deref()
    }
    /// <p>Identifies the service that exceeded the quota.</p>
    pub fn service_code(&self) -> &str {
        use std::ops::Deref;
        self.service_code.deref()
    }
    /// <p>Identifies the quota that has been exceeded.</p>
    pub fn quota_code(&self) -> &str {
        use std::ops::Deref;
        self.quota_code.deref()
    }
    /// <p>The identifier of the affected resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>Information about the resources in use when the exception was thrown.</p>
    pub fn context(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.context.as_ref()
    }
}
impl ServiceQuotaExceededException {
    /// Returns the error message.
    pub fn message(&self) -> &str {
        &self.message
    }
}
impl ::std::fmt::Display for ServiceQuotaExceededException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        ::std::write!(f, "ServiceQuotaExceededException")?;
        {
            ::std::write!(f, ": {}", &self.message)?;
        }
        Ok(())
    }
}
impl ::std::error::Error for ServiceQuotaExceededException {}
impl ::aws_types::request_id::RequestId for crate::types::error::ServiceQuotaExceededException {
    fn request_id(&self) -> Option<&str> {
        use ::aws_smithy_types::error::metadata::ProvideErrorMetadata;
        self.meta().request_id()
    }
}
impl ::aws_smithy_types::error::metadata::ProvideErrorMetadata for ServiceQuotaExceededException {
    fn meta(&self) -> &::aws_smithy_types::error::ErrorMetadata {
        &self.meta
    }
}
impl ServiceQuotaExceededException {
    /// Creates a new builder-style object to manufacture [`ServiceQuotaExceededException`](crate::types::error::ServiceQuotaExceededException).
    pub fn builder() -> crate::types::error::builders::ServiceQuotaExceededExceptionBuilder {
        crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::default()
    }
}

/// A builder for [`ServiceQuotaExceededException`](crate::types::error::ServiceQuotaExceededException).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServiceQuotaExceededExceptionBuilder {
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::ServiceQuotaExceededExceptionReason>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) service_code: ::std::option::Option<::std::string::String>,
    pub(crate) quota_code: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) context: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>,
}
impl ServiceQuotaExceededExceptionBuilder {
    #[allow(missing_docs)] // documentation missing in model
    /// This field is required.
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    #[allow(missing_docs)] // documentation missing in model
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// <p>A string that describes the reason the quota was exceeded.</p>
    /// This field is required.
    pub fn reason(mut self, input: crate::types::ServiceQuotaExceededExceptionReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>A string that describes the reason the quota was exceeded.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::ServiceQuotaExceededExceptionReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>A string that describes the reason the quota was exceeded.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::ServiceQuotaExceededExceptionReason> {
        &self.reason
    }
    /// <p>The type of the affected resource</p>
    /// This field is required.
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of the affected resource</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of the affected resource</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>Identifies the service that exceeded the quota.</p>
    /// This field is required.
    pub fn service_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the service that exceeded the quota.</p>
    pub fn set_service_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_code = input;
        self
    }
    /// <p>Identifies the service that exceeded the quota.</p>
    pub fn get_service_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_code
    }
    /// <p>Identifies the quota that has been exceeded.</p>
    /// This field is required.
    pub fn quota_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.quota_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifies the quota that has been exceeded.</p>
    pub fn set_quota_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.quota_code = input;
        self
    }
    /// <p>Identifies the quota that has been exceeded.</p>
    pub fn get_quota_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.quota_code
    }
    /// <p>The identifier of the affected resource.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the affected resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The identifier of the affected resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Adds a key-value pair to `context`.
    ///
    /// To override the contents of this collection use [`set_context`](Self::set_context).
    ///
    /// <p>Information about the resources in use when the exception was thrown.</p>
    pub fn context(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.context.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.context = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Information about the resources in use when the exception was thrown.</p>
    pub fn set_context(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.context = input;
        self
    }
    /// <p>Information about the resources in use when the exception was thrown.</p>
    pub fn get_context(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.context
    }
    /// Sets error metadata
    pub fn meta(mut self, meta: ::aws_smithy_types::error::ErrorMetadata) -> Self {
        self.meta = Some(meta);
        self
    }

    /// Sets error metadata
    pub fn set_meta(&mut self, meta: std::option::Option<::aws_smithy_types::error::ErrorMetadata>) -> &mut Self {
        self.meta = meta;
        self
    }
    /// Consumes the builder and constructs a [`ServiceQuotaExceededException`](crate::types::error::ServiceQuotaExceededException).
    /// This method will fail if any of the following fields are not set:
    /// - [`message`](crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::message)
    /// - [`reason`](crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::reason)
    /// - [`resource_type`](crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::resource_type)
    /// - [`service_code`](crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::service_code)
    /// - [`quota_code`](crate::types::error::builders::ServiceQuotaExceededExceptionBuilder::quota_code)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::error::ServiceQuotaExceededException, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::error::ServiceQuotaExceededException {
            message: self.message.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "message",
                    "message was not specified but it is required when building ServiceQuotaExceededException",
                )
            })?,
            reason: self.reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reason",
                    "reason was not specified but it is required when building ServiceQuotaExceededException",
                )
            })?,
            resource_type: self.resource_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "resource_type",
                    "resource_type was not specified but it is required when building ServiceQuotaExceededException",
                )
            })?,
            service_code: self.service_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "service_code",
                    "service_code was not specified but it is required when building ServiceQuotaExceededException",
                )
            })?,
            quota_code: self.quota_code.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "quota_code",
                    "quota_code was not specified but it is required when building ServiceQuotaExceededException",
                )
            })?,
            resource_id: self.resource_id,
            context: self.context,
            meta: self.meta.unwrap_or_default(),
        })
    }
}
