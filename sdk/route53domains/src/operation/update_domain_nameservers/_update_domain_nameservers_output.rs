// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The UpdateDomainNameservers response includes the following element.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDomainNameserversOutput {
    /// <p>Identifier for tracking the progress of the request. To query the operation status, use <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetOperationDetail.html">GetOperationDetail</a>.</p>
    pub operation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDomainNameserversOutput {
    /// <p>Identifier for tracking the progress of the request. To query the operation status, use <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetOperationDetail.html">GetOperationDetail</a>.</p>
    pub fn operation_id(&self) -> ::std::option::Option<&str> {
        self.operation_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateDomainNameserversOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDomainNameserversOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDomainNameserversOutput`](crate::operation::update_domain_nameservers::UpdateDomainNameserversOutput).
    pub fn builder() -> crate::operation::update_domain_nameservers::builders::UpdateDomainNameserversOutputBuilder {
        crate::operation::update_domain_nameservers::builders::UpdateDomainNameserversOutputBuilder::default()
    }
}

/// A builder for [`UpdateDomainNameserversOutput`](crate::operation::update_domain_nameservers::UpdateDomainNameserversOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDomainNameserversOutputBuilder {
    pub(crate) operation_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl UpdateDomainNameserversOutputBuilder {
    /// <p>Identifier for tracking the progress of the request. To query the operation status, use <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetOperationDetail.html">GetOperationDetail</a>.</p>
    pub fn operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier for tracking the progress of the request. To query the operation status, use <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetOperationDetail.html">GetOperationDetail</a>.</p>
    pub fn set_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation_id = input;
        self
    }
    /// <p>Identifier for tracking the progress of the request. To query the operation status, use <a href="https://docs.aws.amazon.com/Route53/latest/APIReference/API_domains_GetOperationDetail.html">GetOperationDetail</a>.</p>
    pub fn get_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDomainNameserversOutput`](crate::operation::update_domain_nameservers::UpdateDomainNameserversOutput).
    pub fn build(self) -> crate::operation::update_domain_nameservers::UpdateDomainNameserversOutput {
        crate::operation::update_domain_nameservers::UpdateDomainNameserversOutput {
            operation_id: self.operation_id,
            _request_id: self._request_id,
        }
    }
}
