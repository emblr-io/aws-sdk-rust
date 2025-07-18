// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDomainOutput {
    /// <p>The Amazon Resource Name (ARN) of the domain.</p>
    pub domain_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDomainOutput {
    /// <p>The Amazon Resource Name (ARN) of the domain.</p>
    pub fn domain_arn(&self) -> ::std::option::Option<&str> {
        self.domain_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDomainOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDomainOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDomainOutput`](crate::operation::update_domain::UpdateDomainOutput).
    pub fn builder() -> crate::operation::update_domain::builders::UpdateDomainOutputBuilder {
        crate::operation::update_domain::builders::UpdateDomainOutputBuilder::default()
    }
}

/// A builder for [`UpdateDomainOutput`](crate::operation::update_domain::UpdateDomainOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDomainOutputBuilder {
    pub(crate) domain_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDomainOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the domain.</p>
    pub fn domain_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the domain.</p>
    pub fn set_domain_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the domain.</p>
    pub fn get_domain_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDomainOutput`](crate::operation::update_domain::UpdateDomainOutput).
    pub fn build(self) -> crate::operation::update_domain::UpdateDomainOutput {
        crate::operation::update_domain::UpdateDomainOutput {
            domain_arn: self.domain_arn,
            _request_id: self._request_id,
        }
    }
}
