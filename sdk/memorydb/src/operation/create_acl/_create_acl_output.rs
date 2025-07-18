// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAclOutput {
    /// <p>The newly-created Access Control List.</p>
    pub acl: ::std::option::Option<crate::types::Acl>,
    _request_id: Option<String>,
}
impl CreateAclOutput {
    /// <p>The newly-created Access Control List.</p>
    pub fn acl(&self) -> ::std::option::Option<&crate::types::Acl> {
        self.acl.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAclOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAclOutput {
    /// Creates a new builder-style object to manufacture [`CreateAclOutput`](crate::operation::create_acl::CreateAclOutput).
    pub fn builder() -> crate::operation::create_acl::builders::CreateAclOutputBuilder {
        crate::operation::create_acl::builders::CreateAclOutputBuilder::default()
    }
}

/// A builder for [`CreateAclOutput`](crate::operation::create_acl::CreateAclOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAclOutputBuilder {
    pub(crate) acl: ::std::option::Option<crate::types::Acl>,
    _request_id: Option<String>,
}
impl CreateAclOutputBuilder {
    /// <p>The newly-created Access Control List.</p>
    pub fn acl(mut self, input: crate::types::Acl) -> Self {
        self.acl = ::std::option::Option::Some(input);
        self
    }
    /// <p>The newly-created Access Control List.</p>
    pub fn set_acl(mut self, input: ::std::option::Option<crate::types::Acl>) -> Self {
        self.acl = input;
        self
    }
    /// <p>The newly-created Access Control List.</p>
    pub fn get_acl(&self) -> &::std::option::Option<crate::types::Acl> {
        &self.acl
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAclOutput`](crate::operation::create_acl::CreateAclOutput).
    pub fn build(self) -> crate::operation::create_acl::CreateAclOutput {
        crate::operation::create_acl::CreateAclOutput {
            acl: self.acl,
            _request_id: self._request_id,
        }
    }
}
