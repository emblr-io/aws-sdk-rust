// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the connection attribute, thing attribute, and the user property key.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PropagatingAttribute {
    /// <p>The key of the user property key-value pair.</p>
    pub user_property_key: ::std::option::Option<::std::string::String>,
    /// <p>The user-defined thing attribute that is propagating for MQTT 5 message enrichment.</p>
    pub thing_attribute: ::std::option::Option<::std::string::String>,
    /// <p>The attribute associated with the connection between a device and Amazon Web Services IoT Core.</p>
    pub connection_attribute: ::std::option::Option<::std::string::String>,
}
impl PropagatingAttribute {
    /// <p>The key of the user property key-value pair.</p>
    pub fn user_property_key(&self) -> ::std::option::Option<&str> {
        self.user_property_key.as_deref()
    }
    /// <p>The user-defined thing attribute that is propagating for MQTT 5 message enrichment.</p>
    pub fn thing_attribute(&self) -> ::std::option::Option<&str> {
        self.thing_attribute.as_deref()
    }
    /// <p>The attribute associated with the connection between a device and Amazon Web Services IoT Core.</p>
    pub fn connection_attribute(&self) -> ::std::option::Option<&str> {
        self.connection_attribute.as_deref()
    }
}
impl PropagatingAttribute {
    /// Creates a new builder-style object to manufacture [`PropagatingAttribute`](crate::types::PropagatingAttribute).
    pub fn builder() -> crate::types::builders::PropagatingAttributeBuilder {
        crate::types::builders::PropagatingAttributeBuilder::default()
    }
}

/// A builder for [`PropagatingAttribute`](crate::types::PropagatingAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PropagatingAttributeBuilder {
    pub(crate) user_property_key: ::std::option::Option<::std::string::String>,
    pub(crate) thing_attribute: ::std::option::Option<::std::string::String>,
    pub(crate) connection_attribute: ::std::option::Option<::std::string::String>,
}
impl PropagatingAttributeBuilder {
    /// <p>The key of the user property key-value pair.</p>
    pub fn user_property_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_property_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key of the user property key-value pair.</p>
    pub fn set_user_property_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_property_key = input;
        self
    }
    /// <p>The key of the user property key-value pair.</p>
    pub fn get_user_property_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_property_key
    }
    /// <p>The user-defined thing attribute that is propagating for MQTT 5 message enrichment.</p>
    pub fn thing_attribute(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.thing_attribute = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-defined thing attribute that is propagating for MQTT 5 message enrichment.</p>
    pub fn set_thing_attribute(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.thing_attribute = input;
        self
    }
    /// <p>The user-defined thing attribute that is propagating for MQTT 5 message enrichment.</p>
    pub fn get_thing_attribute(&self) -> &::std::option::Option<::std::string::String> {
        &self.thing_attribute
    }
    /// <p>The attribute associated with the connection between a device and Amazon Web Services IoT Core.</p>
    pub fn connection_attribute(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_attribute = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The attribute associated with the connection between a device and Amazon Web Services IoT Core.</p>
    pub fn set_connection_attribute(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_attribute = input;
        self
    }
    /// <p>The attribute associated with the connection between a device and Amazon Web Services IoT Core.</p>
    pub fn get_connection_attribute(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_attribute
    }
    /// Consumes the builder and constructs a [`PropagatingAttribute`](crate::types::PropagatingAttribute).
    pub fn build(self) -> crate::types::PropagatingAttribute {
        crate::types::PropagatingAttribute {
            user_property_key: self.user_property_key,
            thing_attribute: self.thing_attribute,
            connection_attribute: self.connection_attribute,
        }
    }
}
