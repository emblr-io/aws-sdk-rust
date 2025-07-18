// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEntitlementOutput {
    /// <p>The entitlement.</p>
    pub entitlement: ::std::option::Option<crate::types::Entitlement>,
    _request_id: Option<String>,
}
impl UpdateEntitlementOutput {
    /// <p>The entitlement.</p>
    pub fn entitlement(&self) -> ::std::option::Option<&crate::types::Entitlement> {
        self.entitlement.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateEntitlementOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateEntitlementOutput {
    /// Creates a new builder-style object to manufacture [`UpdateEntitlementOutput`](crate::operation::update_entitlement::UpdateEntitlementOutput).
    pub fn builder() -> crate::operation::update_entitlement::builders::UpdateEntitlementOutputBuilder {
        crate::operation::update_entitlement::builders::UpdateEntitlementOutputBuilder::default()
    }
}

/// A builder for [`UpdateEntitlementOutput`](crate::operation::update_entitlement::UpdateEntitlementOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEntitlementOutputBuilder {
    pub(crate) entitlement: ::std::option::Option<crate::types::Entitlement>,
    _request_id: Option<String>,
}
impl UpdateEntitlementOutputBuilder {
    /// <p>The entitlement.</p>
    pub fn entitlement(mut self, input: crate::types::Entitlement) -> Self {
        self.entitlement = ::std::option::Option::Some(input);
        self
    }
    /// <p>The entitlement.</p>
    pub fn set_entitlement(mut self, input: ::std::option::Option<crate::types::Entitlement>) -> Self {
        self.entitlement = input;
        self
    }
    /// <p>The entitlement.</p>
    pub fn get_entitlement(&self) -> &::std::option::Option<crate::types::Entitlement> {
        &self.entitlement
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateEntitlementOutput`](crate::operation::update_entitlement::UpdateEntitlementOutput).
    pub fn build(self) -> crate::operation::update_entitlement::UpdateEntitlementOutput {
        crate::operation::update_entitlement::UpdateEntitlementOutput {
            entitlement: self.entitlement,
            _request_id: self._request_id,
        }
    }
}
