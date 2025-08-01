// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDiscovererInput {
    /// <p>The ID of the discoverer.</p>
    pub discoverer_id: ::std::option::Option<::std::string::String>,
}
impl DeleteDiscovererInput {
    /// <p>The ID of the discoverer.</p>
    pub fn discoverer_id(&self) -> ::std::option::Option<&str> {
        self.discoverer_id.as_deref()
    }
}
impl DeleteDiscovererInput {
    /// Creates a new builder-style object to manufacture [`DeleteDiscovererInput`](crate::operation::delete_discoverer::DeleteDiscovererInput).
    pub fn builder() -> crate::operation::delete_discoverer::builders::DeleteDiscovererInputBuilder {
        crate::operation::delete_discoverer::builders::DeleteDiscovererInputBuilder::default()
    }
}

/// A builder for [`DeleteDiscovererInput`](crate::operation::delete_discoverer::DeleteDiscovererInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDiscovererInputBuilder {
    pub(crate) discoverer_id: ::std::option::Option<::std::string::String>,
}
impl DeleteDiscovererInputBuilder {
    /// <p>The ID of the discoverer.</p>
    /// This field is required.
    pub fn discoverer_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.discoverer_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the discoverer.</p>
    pub fn set_discoverer_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.discoverer_id = input;
        self
    }
    /// <p>The ID of the discoverer.</p>
    pub fn get_discoverer_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.discoverer_id
    }
    /// Consumes the builder and constructs a [`DeleteDiscovererInput`](crate::operation::delete_discoverer::DeleteDiscovererInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_discoverer::DeleteDiscovererInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_discoverer::DeleteDiscovererInput {
            discoverer_id: self.discoverer_id,
        })
    }
}
