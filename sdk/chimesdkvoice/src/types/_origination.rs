// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Origination settings enable your SIP hosts to receive inbound calls using your Amazon Chime SDK Voice Connector.</p><note>
/// <p>The parameters listed below are not required, but you must use at least one.</p>
/// </note>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Origination {
    /// <p>The call distribution properties defined for your SIP hosts. Valid range: Minimum value of 1. Maximum value of 20. This parameter is not required, but you must specify this parameter or <code>Disabled</code>.</p>
    pub routes: ::std::option::Option<::std::vec::Vec<crate::types::OriginationRoute>>,
    /// <p>When origination settings are disabled, inbound calls are not enabled for your Amazon Chime SDK Voice Connector. This parameter is not required, but you must specify this parameter or <code>Routes</code>.</p>
    pub disabled: ::std::option::Option<bool>,
}
impl Origination {
    /// <p>The call distribution properties defined for your SIP hosts. Valid range: Minimum value of 1. Maximum value of 20. This parameter is not required, but you must specify this parameter or <code>Disabled</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.routes.is_none()`.
    pub fn routes(&self) -> &[crate::types::OriginationRoute] {
        self.routes.as_deref().unwrap_or_default()
    }
    /// <p>When origination settings are disabled, inbound calls are not enabled for your Amazon Chime SDK Voice Connector. This parameter is not required, but you must specify this parameter or <code>Routes</code>.</p>
    pub fn disabled(&self) -> ::std::option::Option<bool> {
        self.disabled
    }
}
impl Origination {
    /// Creates a new builder-style object to manufacture [`Origination`](crate::types::Origination).
    pub fn builder() -> crate::types::builders::OriginationBuilder {
        crate::types::builders::OriginationBuilder::default()
    }
}

/// A builder for [`Origination`](crate::types::Origination).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OriginationBuilder {
    pub(crate) routes: ::std::option::Option<::std::vec::Vec<crate::types::OriginationRoute>>,
    pub(crate) disabled: ::std::option::Option<bool>,
}
impl OriginationBuilder {
    /// Appends an item to `routes`.
    ///
    /// To override the contents of this collection use [`set_routes`](Self::set_routes).
    ///
    /// <p>The call distribution properties defined for your SIP hosts. Valid range: Minimum value of 1. Maximum value of 20. This parameter is not required, but you must specify this parameter or <code>Disabled</code>.</p>
    pub fn routes(mut self, input: crate::types::OriginationRoute) -> Self {
        let mut v = self.routes.unwrap_or_default();
        v.push(input);
        self.routes = ::std::option::Option::Some(v);
        self
    }
    /// <p>The call distribution properties defined for your SIP hosts. Valid range: Minimum value of 1. Maximum value of 20. This parameter is not required, but you must specify this parameter or <code>Disabled</code>.</p>
    pub fn set_routes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::OriginationRoute>>) -> Self {
        self.routes = input;
        self
    }
    /// <p>The call distribution properties defined for your SIP hosts. Valid range: Minimum value of 1. Maximum value of 20. This parameter is not required, but you must specify this parameter or <code>Disabled</code>.</p>
    pub fn get_routes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OriginationRoute>> {
        &self.routes
    }
    /// <p>When origination settings are disabled, inbound calls are not enabled for your Amazon Chime SDK Voice Connector. This parameter is not required, but you must specify this parameter or <code>Routes</code>.</p>
    pub fn disabled(mut self, input: bool) -> Self {
        self.disabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>When origination settings are disabled, inbound calls are not enabled for your Amazon Chime SDK Voice Connector. This parameter is not required, but you must specify this parameter or <code>Routes</code>.</p>
    pub fn set_disabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.disabled = input;
        self
    }
    /// <p>When origination settings are disabled, inbound calls are not enabled for your Amazon Chime SDK Voice Connector. This parameter is not required, but you must specify this parameter or <code>Routes</code>.</p>
    pub fn get_disabled(&self) -> &::std::option::Option<bool> {
        &self.disabled
    }
    /// Consumes the builder and constructs a [`Origination`](crate::types::Origination).
    pub fn build(self) -> crate::types::Origination {
        crate::types::Origination {
            routes: self.routes,
            disabled: self.disabled,
        }
    }
}
