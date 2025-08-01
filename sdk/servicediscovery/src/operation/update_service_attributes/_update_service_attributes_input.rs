// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServiceAttributesInput {
    /// <p>The ID of the service that you want to update.</p>
    pub service_id: ::std::option::Option<::std::string::String>,
    /// <p>A string map that contains attribute key-value pairs.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateServiceAttributesInput {
    /// <p>The ID of the service that you want to update.</p>
    pub fn service_id(&self) -> ::std::option::Option<&str> {
        self.service_id.as_deref()
    }
    /// <p>A string map that contains attribute key-value pairs.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.attributes.as_ref()
    }
}
impl UpdateServiceAttributesInput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceAttributesInput`](crate::operation::update_service_attributes::UpdateServiceAttributesInput).
    pub fn builder() -> crate::operation::update_service_attributes::builders::UpdateServiceAttributesInputBuilder {
        crate::operation::update_service_attributes::builders::UpdateServiceAttributesInputBuilder::default()
    }
}

/// A builder for [`UpdateServiceAttributesInput`](crate::operation::update_service_attributes::UpdateServiceAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServiceAttributesInputBuilder {
    pub(crate) service_id: ::std::option::Option<::std::string::String>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl UpdateServiceAttributesInputBuilder {
    /// <p>The ID of the service that you want to update.</p>
    /// This field is required.
    pub fn service_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the service that you want to update.</p>
    pub fn set_service_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_id = input;
        self
    }
    /// <p>The ID of the service that you want to update.</p>
    pub fn get_service_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_id
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>A string map that contains attribute key-value pairs.</p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A string map that contains attribute key-value pairs.</p>
    pub fn set_attributes(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.attributes = input;
        self
    }
    /// <p>A string map that contains attribute key-value pairs.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.attributes
    }
    /// Consumes the builder and constructs a [`UpdateServiceAttributesInput`](crate::operation::update_service_attributes::UpdateServiceAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_service_attributes::UpdateServiceAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_service_attributes::UpdateServiceAttributesInput {
            service_id: self.service_id,
            attributes: self.attributes,
        })
    }
}
