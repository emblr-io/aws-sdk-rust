// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDomainEntryOutput {
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub operation: ::std::option::Option<crate::types::Operation>,
    _request_id: Option<String>,
}
impl CreateDomainEntryOutput {
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn operation(&self) -> ::std::option::Option<&crate::types::Operation> {
        self.operation.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateDomainEntryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDomainEntryOutput {
    /// Creates a new builder-style object to manufacture [`CreateDomainEntryOutput`](crate::operation::create_domain_entry::CreateDomainEntryOutput).
    pub fn builder() -> crate::operation::create_domain_entry::builders::CreateDomainEntryOutputBuilder {
        crate::operation::create_domain_entry::builders::CreateDomainEntryOutputBuilder::default()
    }
}

/// A builder for [`CreateDomainEntryOutput`](crate::operation::create_domain_entry::CreateDomainEntryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDomainEntryOutputBuilder {
    pub(crate) operation: ::std::option::Option<crate::types::Operation>,
    _request_id: Option<String>,
}
impl CreateDomainEntryOutputBuilder {
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn operation(mut self, input: crate::types::Operation) -> Self {
        self.operation = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<crate::types::Operation>) -> Self {
        self.operation = input;
        self
    }
    /// <p>An array of objects that describe the result of the action, such as the status of the request, the timestamp of the request, and the resources affected by the request.</p>
    pub fn get_operation(&self) -> &::std::option::Option<crate::types::Operation> {
        &self.operation
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDomainEntryOutput`](crate::operation::create_domain_entry::CreateDomainEntryOutput).
    pub fn build(self) -> crate::operation::create_domain_entry::CreateDomainEntryOutput {
        crate::operation::create_domain_entry::CreateDomainEntryOutput {
            operation: self.operation,
            _request_id: self._request_id,
        }
    }
}
