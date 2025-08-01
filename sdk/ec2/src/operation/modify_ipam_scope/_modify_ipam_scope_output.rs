// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyIpamScopeOutput {
    /// <p>The results of the modification.</p>
    pub ipam_scope: ::std::option::Option<crate::types::IpamScope>,
    _request_id: Option<String>,
}
impl ModifyIpamScopeOutput {
    /// <p>The results of the modification.</p>
    pub fn ipam_scope(&self) -> ::std::option::Option<&crate::types::IpamScope> {
        self.ipam_scope.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ModifyIpamScopeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyIpamScopeOutput {
    /// Creates a new builder-style object to manufacture [`ModifyIpamScopeOutput`](crate::operation::modify_ipam_scope::ModifyIpamScopeOutput).
    pub fn builder() -> crate::operation::modify_ipam_scope::builders::ModifyIpamScopeOutputBuilder {
        crate::operation::modify_ipam_scope::builders::ModifyIpamScopeOutputBuilder::default()
    }
}

/// A builder for [`ModifyIpamScopeOutput`](crate::operation::modify_ipam_scope::ModifyIpamScopeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyIpamScopeOutputBuilder {
    pub(crate) ipam_scope: ::std::option::Option<crate::types::IpamScope>,
    _request_id: Option<String>,
}
impl ModifyIpamScopeOutputBuilder {
    /// <p>The results of the modification.</p>
    pub fn ipam_scope(mut self, input: crate::types::IpamScope) -> Self {
        self.ipam_scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>The results of the modification.</p>
    pub fn set_ipam_scope(mut self, input: ::std::option::Option<crate::types::IpamScope>) -> Self {
        self.ipam_scope = input;
        self
    }
    /// <p>The results of the modification.</p>
    pub fn get_ipam_scope(&self) -> &::std::option::Option<crate::types::IpamScope> {
        &self.ipam_scope
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyIpamScopeOutput`](crate::operation::modify_ipam_scope::ModifyIpamScopeOutput).
    pub fn build(self) -> crate::operation::modify_ipam_scope::ModifyIpamScopeOutput {
        crate::operation::modify_ipam_scope::ModifyIpamScopeOutput {
            ipam_scope: self.ipam_scope,
            _request_id: self._request_id,
        }
    }
}
