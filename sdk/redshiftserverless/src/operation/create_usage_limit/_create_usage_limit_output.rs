// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateUsageLimitOutput {
    /// <p>The returned usage limit object.</p>
    pub usage_limit: ::std::option::Option<crate::types::UsageLimit>,
    _request_id: Option<String>,
}
impl CreateUsageLimitOutput {
    /// <p>The returned usage limit object.</p>
    pub fn usage_limit(&self) -> ::std::option::Option<&crate::types::UsageLimit> {
        self.usage_limit.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateUsageLimitOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateUsageLimitOutput {
    /// Creates a new builder-style object to manufacture [`CreateUsageLimitOutput`](crate::operation::create_usage_limit::CreateUsageLimitOutput).
    pub fn builder() -> crate::operation::create_usage_limit::builders::CreateUsageLimitOutputBuilder {
        crate::operation::create_usage_limit::builders::CreateUsageLimitOutputBuilder::default()
    }
}

/// A builder for [`CreateUsageLimitOutput`](crate::operation::create_usage_limit::CreateUsageLimitOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateUsageLimitOutputBuilder {
    pub(crate) usage_limit: ::std::option::Option<crate::types::UsageLimit>,
    _request_id: Option<String>,
}
impl CreateUsageLimitOutputBuilder {
    /// <p>The returned usage limit object.</p>
    pub fn usage_limit(mut self, input: crate::types::UsageLimit) -> Self {
        self.usage_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The returned usage limit object.</p>
    pub fn set_usage_limit(mut self, input: ::std::option::Option<crate::types::UsageLimit>) -> Self {
        self.usage_limit = input;
        self
    }
    /// <p>The returned usage limit object.</p>
    pub fn get_usage_limit(&self) -> &::std::option::Option<crate::types::UsageLimit> {
        &self.usage_limit
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateUsageLimitOutput`](crate::operation::create_usage_limit::CreateUsageLimitOutput).
    pub fn build(self) -> crate::operation::create_usage_limit::CreateUsageLimitOutput {
        crate::operation::create_usage_limit::CreateUsageLimitOutput {
            usage_limit: self.usage_limit,
            _request_id: self._request_id,
        }
    }
}
