// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAccountInput {
    /// <p>The Amazon Chime account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The new name for the specified Amazon Chime account.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The default license applied when you add users to an Amazon Chime account.</p>
    pub default_license: ::std::option::Option<crate::types::License>,
}
impl UpdateAccountInput {
    /// <p>The Amazon Chime account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The new name for the specified Amazon Chime account.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The default license applied when you add users to an Amazon Chime account.</p>
    pub fn default_license(&self) -> ::std::option::Option<&crate::types::License> {
        self.default_license.as_ref()
    }
}
impl UpdateAccountInput {
    /// Creates a new builder-style object to manufacture [`UpdateAccountInput`](crate::operation::update_account::UpdateAccountInput).
    pub fn builder() -> crate::operation::update_account::builders::UpdateAccountInputBuilder {
        crate::operation::update_account::builders::UpdateAccountInputBuilder::default()
    }
}

/// A builder for [`UpdateAccountInput`](crate::operation::update_account::UpdateAccountInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAccountInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) default_license: ::std::option::Option<crate::types::License>,
}
impl UpdateAccountInputBuilder {
    /// <p>The Amazon Chime account ID.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Chime account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The new name for the specified Amazon Chime account.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new name for the specified Amazon Chime account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The new name for the specified Amazon Chime account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The default license applied when you add users to an Amazon Chime account.</p>
    pub fn default_license(mut self, input: crate::types::License) -> Self {
        self.default_license = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default license applied when you add users to an Amazon Chime account.</p>
    pub fn set_default_license(mut self, input: ::std::option::Option<crate::types::License>) -> Self {
        self.default_license = input;
        self
    }
    /// <p>The default license applied when you add users to an Amazon Chime account.</p>
    pub fn get_default_license(&self) -> &::std::option::Option<crate::types::License> {
        &self.default_license
    }
    /// Consumes the builder and constructs a [`UpdateAccountInput`](crate::operation::update_account::UpdateAccountInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_account::UpdateAccountInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_account::UpdateAccountInput {
            account_id: self.account_id,
            name: self.name,
            default_license: self.default_license,
        })
    }
}
