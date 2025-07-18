// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEntitlementOutput {
    /// <p>The entitlement.</p>
    pub entitlement: ::std::option::Option<crate::types::Entitlement>,
    _request_id: Option<String>,
}
impl CreateEntitlementOutput {
    /// <p>The entitlement.</p>
    pub fn entitlement(&self) -> ::std::option::Option<&crate::types::Entitlement> {
        self.entitlement.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateEntitlementOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateEntitlementOutput {
    /// Creates a new builder-style object to manufacture [`CreateEntitlementOutput`](crate::operation::create_entitlement::CreateEntitlementOutput).
    pub fn builder() -> crate::operation::create_entitlement::builders::CreateEntitlementOutputBuilder {
        crate::operation::create_entitlement::builders::CreateEntitlementOutputBuilder::default()
    }
}

/// A builder for [`CreateEntitlementOutput`](crate::operation::create_entitlement::CreateEntitlementOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEntitlementOutputBuilder {
    pub(crate) entitlement: ::std::option::Option<crate::types::Entitlement>,
    _request_id: Option<String>,
}
impl CreateEntitlementOutputBuilder {
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
    /// Consumes the builder and constructs a [`CreateEntitlementOutput`](crate::operation::create_entitlement::CreateEntitlementOutput).
    pub fn build(self) -> crate::operation::create_entitlement::CreateEntitlementOutput {
        crate::operation::create_entitlement::CreateEntitlementOutput {
            entitlement: self.entitlement,
            _request_id: self._request_id,
        }
    }
}
