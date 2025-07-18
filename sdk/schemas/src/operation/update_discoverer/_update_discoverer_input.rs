// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDiscovererInput {
    /// <p>The description of the discoverer to update.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the discoverer.</p>
    pub discoverer_id: ::std::option::Option<::std::string::String>,
    /// <p>Support discovery of schemas in events sent to the bus from another account. (default: true)</p>
    pub cross_account: ::std::option::Option<bool>,
}
impl UpdateDiscovererInput {
    /// <p>The description of the discoverer to update.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ID of the discoverer.</p>
    pub fn discoverer_id(&self) -> ::std::option::Option<&str> {
        self.discoverer_id.as_deref()
    }
    /// <p>Support discovery of schemas in events sent to the bus from another account. (default: true)</p>
    pub fn cross_account(&self) -> ::std::option::Option<bool> {
        self.cross_account
    }
}
impl UpdateDiscovererInput {
    /// Creates a new builder-style object to manufacture [`UpdateDiscovererInput`](crate::operation::update_discoverer::UpdateDiscovererInput).
    pub fn builder() -> crate::operation::update_discoverer::builders::UpdateDiscovererInputBuilder {
        crate::operation::update_discoverer::builders::UpdateDiscovererInputBuilder::default()
    }
}

/// A builder for [`UpdateDiscovererInput`](crate::operation::update_discoverer::UpdateDiscovererInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDiscovererInputBuilder {
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) discoverer_id: ::std::option::Option<::std::string::String>,
    pub(crate) cross_account: ::std::option::Option<bool>,
}
impl UpdateDiscovererInputBuilder {
    /// <p>The description of the discoverer to update.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the discoverer to update.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the discoverer to update.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
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
    /// <p>Support discovery of schemas in events sent to the bus from another account. (default: true)</p>
    pub fn cross_account(mut self, input: bool) -> Self {
        self.cross_account = ::std::option::Option::Some(input);
        self
    }
    /// <p>Support discovery of schemas in events sent to the bus from another account. (default: true)</p>
    pub fn set_cross_account(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cross_account = input;
        self
    }
    /// <p>Support discovery of schemas in events sent to the bus from another account. (default: true)</p>
    pub fn get_cross_account(&self) -> &::std::option::Option<bool> {
        &self.cross_account
    }
    /// Consumes the builder and constructs a [`UpdateDiscovererInput`](crate::operation::update_discoverer::UpdateDiscovererInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_discoverer::UpdateDiscovererInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_discoverer::UpdateDiscovererInput {
            description: self.description,
            discoverer_id: self.discoverer_id,
            cross_account: self.cross_account,
        })
    }
}
